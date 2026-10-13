"""Isolated client callbacks for comparison with portable decoding."""

import collections
import hashlib
import json
import os
from pathlib import Path
import threading


def load_profile():
    return json.loads(Path(__file__).with_name("client-profile.json").read_text())


class NativeDecoder:
    def __init__(self, client, unlicense_agent, profile, archive_keys=None):
        import frida

        self.frida = frida
        self.pid = None
        self.script = None
        self.last_metadata = None
        self.metadata_counts = collections.Counter()
        self.ready = threading.Event()
        self.oep_error = None
        self.profile = profile
        os.environ["__COMPAT_LAYER"] = "RUNASINVOKER"
        agent = unlicense_agent.read_text(encoding="utf-8")
        if hashlib.sha256(agent.encode()).hexdigest() != profile["unlicense_agent_sha256"]:
            raise ValueError("Unlicense agent hash mismatch")
        agent += "\n" + Path(__file__).with_name("native-decoder.js").read_text(encoding="utf-8")
        try:
            self.pid = frida.spawn(str(client), cwd=str(client.parent))
            session = frida.attach(self.pid)
            self.script = session.create_script(agent)
            self.script.on("message", self.on_message)
            self.script.load()
            self.script.exports_sync.setup_oep_tracing(client.name, profile["oep_ranges"])
            frida.resume(self.pid)
            if not self.ready.wait(20):
                raise TimeoutError("Client did not reach its original entry point")
            if self.oep_error:
                raise ValueError(self.oep_error)
            keys = [{"id": key_id, "bytes": list(value)}
                    for key_id, value in (archive_keys or {}).items()]
            initialization = self.script.exports_sync.initialize_decoder(keys)
            print("Decoder ready:", json.dumps(initialization), flush=True)
        except BaseException:
            self.close()
            raise

    def on_message(self, message, _data):
        if message.get("type") == "error":
            print("Agent error:", message, flush=True)
        payload = message.get("payload", {})
        if payload.get("event") == "oep_reached":
            relative = int(payload["OEP"], 16) - int(payload["BASE"], 16)
            expected = int(self.profile["oep"], 16) - self.profile["image_base"]
            if relative != expected:
                self.oep_error = "Unexpected original entry point"
            self.ready.set()
        elif payload.get("event") == "entry":
            self.last_metadata = payload
            self.metadata_counts[(payload["headerType"], payload["cipherId"], payload["compression"])] += 1

    def decode(self, name, real, payload):
        self.last_metadata = None
        return self.script.exports_sync.decode_entry(list(name), real, payload)

    def close(self):
        if self.pid is not None:
            try:
                self.frida.kill(self.pid)
            except self.frida.ProcessNotFoundError:
                pass
            self.pid = None
