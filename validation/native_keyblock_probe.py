"""Bounded Windows archive-key-loader oracle for the pinned native profile.

Uses the existing Windows Python/Frida bridge and GumJS interface. It is not a
portable decoder or a dependency of the archive CLI. Run only on scratch copies.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import struct
import sys
import threading
import time


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--client', type=Path, required=True)
    parser.add_argument('--agent', type=Path, required=True)
    parser.add_argument('--key-block', type=Path, action='append', required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--trace-derivations', action='store_true')
    parser.add_argument('--controls', action='store_true', help='Also flip one body bit and one checksum bit')
    args = parser.parse_args()
    if sys.platform != 'win32' or struct.calcsize('P') != 4:
        parser.error('Use 32-bit Windows Python with the native guide prerequisites')
    import frida

    root = Path(__file__).resolve().parents[1]
    sys.path.insert(0, str(root / 'src'))
    from grfkit.protected import _cham_keys

    native = root / 'src/grf_extractor/native'
    profile = json.loads((native / 'client-profile.json').read_text())
    client = args.client.resolve(strict=True)
    if (client.name != profile['executable'] or client.stat().st_size != profile['size']
            or hashlib.sha256(client.read_bytes()).hexdigest() != profile['sha256']):
        parser.error('Client differs from the exact native profile')
    agent = args.agent.read_text(encoding='utf-8')
    if hashlib.sha256(agent.encode()).hexdigest() != profile['unlicense_agent_sha256']:
        parser.error('Startup agent differs from the native profile')
    if frida.__version__ != profile['frida_version']:
        parser.error('Frida version differs from the native profile')
    if args.output.exists():
        parser.error('Output must be new')
    inputs = []
    for path in args.key_block:
        if not 84 <= path.stat().st_size <= 20 + 65535 * 64:
            parser.error('Key-block input exceeds supported bounds')
        raw = path.read_bytes()
        inputs.append((path, raw))
    ready = threading.Event()
    oep = []

    def message(item, _):
        if item.get('type') == 'send' and item.get('payload', {}).get('event') == 'oep_reached':
            oep.append(item['payload'])
            ready.set()

    pid = None

    def kill():
        if pid is not None:
            try:
                frida.kill(pid)
            except frida.ProcessNotFoundError:
                pass

    rows = []
    os.environ['__COMPAT_LAYER'] = 'RUNASINVOKER'
    watchdog = threading.Timer(60, kill)
    try:
        pid = frida.spawn(str(client), cwd=str(client.parent))
        watchdog.start()
        session = frida.attach(pid)
        source = agent + '\n' + (native / 'native-decoder.js').read_text(encoding='utf-8')
        source += '\n' + Path(__file__).with_suffix('.js').read_text(encoding='utf-8')
        script = session.create_script(source)
        script.on('message', message)
        script.load()
        script.exports_sync.setup_oep_tracing(client.name, profile['oep_ranges'])
        frida.resume(pid)
        if not ready.wait(20):
            raise TimeoutError('Native client did not reach OEP')
        if int(oep[-1]['OEP'], 16) - int(oep[-1]['BASE'], 16) != int(profile['oep'], 16) - profile['image_base']:
            raise ValueError('Native client reached an unexpected OEP')
        script.exports_sync.initialize_decoder([])
        script.exports_sync.setup_key_probe(args.trace_derivations)
        for path, original in inputs:
            cases = [('original', original)]
            if args.controls:
                for name, offset in (('body-bit', 20), ('checksum-bit', 16)):
                    damaged = bytearray(original)
                    damaged[offset] ^= 1
                    cases.append((name, bytes(damaged)))
            for name, raw in cases:
                script.exports_sync.start_key_probe(list(raw))
                deadline = time.monotonic() + 15
                while True:
                    job = script.exports_sync.poll_key_probe()
                    if job['done']:
                        break
                    if time.monotonic() >= deadline:
                        raise TimeoutError('Native key-loader call did not complete')
                    time.sleep(0.05)
                if 'error' in job:
                    raise RuntimeError(job['error'])
                value = job['value']
                derivations = []
                for sample in value.pop('parameter_samples'):
                    digest = bytes.fromhex(sample['digest'])
                    # Ignore uninitialized/cleanup frame bytes. Classify a sample
                    # only when the observed native schedule matches its key.
                    if not any(digest) or struct.pack('<8I', *_cham_keys(digest[:16])).hex() != sample['keySchedule']:
                        continue
                    seed = sample['seed']
                    if seed is not None and hashlib.sha256(seed.encode()).digest() != digest:
                        seed = None
                    derivation = dict(digest=sample['digest'], seed=seed)
                    if derivation not in derivations:
                        derivations.append(derivation)
                value['derivations'] = derivations
                rows.append(dict(input=path.name, case=name, size=len(raw),
                                 sha256=hashlib.sha256(raw).hexdigest(), **value))
    finally:
        kill()
        watchdog.cancel()
    # Query the owned PID after termination; do not report cleanup by assumption.
    device = frida.get_local_device()
    deadline = time.monotonic() + 2
    while any(process.pid == pid for process in device.enumerate_processes()):
        if time.monotonic() >= deadline:
            raise RuntimeError('Owned native process still appears in the process list')
        time.sleep(0.05)
    report = dict(client_sha256=profile['sha256'], frida=frida.__version__,
                  startup_agent_sha256=profile['unlicense_agent_sha256'],
                  main_thread_held_at_oep=True, process_terminated=True, results=rows)
    with args.output.open('x', encoding='utf-8') as handle:
        json.dump(report, handle, indent=2)
        handle.write('\n')
    print(json.dumps(report))


if __name__ == '__main__':
    main()
