"""Small synthetic archive checks; no game files or portable cipher dependencies."""

import json
import os
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest
import zlib

from grf_extractor.archive import read_entries



def archive(path, names, *, version=0x300, signature=b"Master of Magic\0", count=None):
    payload = zlib.compress(b"hello")
    layout = "<IIIBQ" if version == 0x300 else "<IIIBI"
    table = b"".join(name + b"\0" + struct.pack(layout, len(payload), len(payload), 5, 1, 0)
                     for name in names)
    packed = zlib.compress(table)
    reserved = 0 if version == 0x300 else 9
    if count is None:
        count = len(names) + (0 if version == 0x300 else reserved + 7)
    prefix = struct.pack("<II", len(packed), len(table))
    if version == 0x300:
        prefix = bytes(4) + prefix
    path.write_bytes(signature + bytes(14) + struct.pack("<IIII", len(payload), reserved, count, version)
                     + payload + prefix + packed)


class ExtractionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.source = self.root / "test.grf"
        self.output = self.root / "out"

    def run_tool(self, *args, code=None):
        command = [sys.executable, "-m", "grf_extractor"] if code is None else [sys.executable, "-c", code]
        return subprocess.run(command + ["--portable", "--archive", str(self.source),
                                         "--output", str(self.output), *args],
                              env=dict(os.environ, PYTHONDONTWRITEBYTECODE="1"),
                              capture_output=True, text=True, timeout=20)

    def manifest(self):
        return json.loads(self.output.with_suffix(".manifest.json").read_text())

    def test_header_identity_and_version_specific_record_counts(self):
        for version in (0x200, 0x300):
            with self.subTest(version=version):
                archive(self.source, [b"a.txt"], version=version)
                self.assertEqual(len(read_entries(self.source)), 1)
                archive(self.source, [b"a.txt"], version=version, count=999)
                with self.assertRaisesRegex(ValueError, "count"):
                    read_entries(self.source)
        archive(self.source, [b"a.txt"], signature=b"Event Horizon\0RL")
        self.assertEqual(len(read_entries(self.source)), 1)
        archive(self.source, [b"a.txt"], signature=b"NOT A GRF FILE!\0")
        with self.assertRaisesRegex(ValueError, "signature"):
            read_entries(self.source)

    def test_collisions_fail_before_writing_even_on_resume(self):
        for names in ([b"data\\a.txt", b"data/a.txt"], [b"data", b"data/a.txt"]):
            archive(self.source, names)
            for args in ((), ("--resume",)):
                result = self.run_tool(*args)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("extraction path", result.stderr)
                self.assertFalse(self.output.exists())

    def test_hard_exit_recovers_checkpoint_and_unrecorded_output(self):
        archive(self.source, [b"a.txt", b"b.txt", b"c.txt"])
        for stop_after in (1, 2):
            self.output = self.root / f"out{stop_after}"
            code = f"""
import sys, os
from grf_extractor import cli as extract
extract.CHECKPOINT_ENTRIES = 1
original = extract.write_atomic
writes = 0
def interrupt(target, data, **kwargs):
    global writes
    original(target, data, **kwargs)
    if not kwargs.get('replace'):
        writes += 1
        if writes == {stop_after}:
            os._exit(99)
extract.write_atomic = interrupt
extract.main()
"""
            self.assertEqual(self.run_tool(code=code).returncode, 99)
            checkpoint = self.manifest()
            self.assertFalse(checkpoint["complete"])
            self.assertEqual(checkpoint["extracted"], stop_after - 1)
            orphan = self.output / ("a.txt" if stop_after == 1 else "b.txt")
            stamp = orphan.stat().st_mtime_ns
            result = self.run_tool("--resume")
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(orphan.stat().st_mtime_ns, stamp)
            self.assertTrue(self.manifest()["lossless_complete"])
            orphan.write_bytes(b"changed")
            self.assertNotEqual(self.run_tool("--resume").returncode, 0)


if __name__ == "__main__":
    unittest.main()
