"""Resumable extraction must retain raw identities needed by the writer."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from grfkit.archive import Archive, Writer


class RoundtripTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.source = self.root / 'source.grf'
        self.output = self.root / 'out'

    def command(self, *arguments):
        return subprocess.run([sys.executable, '-m', 'grf_extractor', '--portable',
                               '--archive', str(self.source), '--output', str(self.output), *arguments],
                              capture_output=True, text=True, timeout=20)

    def test_collision_safe_resume_and_raw_name_pack_roundtrip(self):
        records = [(b'data\\A.txt', b'one'), (b'data/a.txt', b'two'),
                   (b'data\\A.txt', b'three'), (b'data\\CON', b'four'),
                   (b'data\\\xff.txt', b'five')]
        with Writer(self.source) as writer:
            for name, value in records:
                writer.add(name, value)
        result = self.command()
        self.assertEqual(result.returncode, 0, result.stderr)
        manifest = [json.loads(line) for line in (self.output / '.grf-manifest.jsonl').read_text().splitlines()]
        self.assertEqual([bytes.fromhex(row['raw_name']) for row in manifest[1:]], [r[0] for r in records])
        paths = [row['path'] for row in manifest[1:]]
        self.assertEqual(len({p.casefold() for p in paths}), len(records))
        self.assertEqual([(self.output / p).read_bytes() for p in paths], [r[1] for r in records])
        result = self.command('--resume')
        self.assertEqual(result.returncode, 0, result.stderr)
        packed = self.root / 'packed.grf'
        result = subprocess.run([sys.executable, '-m', 'grfkit', 'pack', str(self.output), str(packed)],
                                capture_output=True, text=True, timeout=20)
        self.assertEqual(result.returncode, 0, result.stderr)
        with Archive(packed) as archive:
            self.assertEqual([(e.raw_name, archive.read(e)) for e in archive.entries], records)
        (self.output / paths[0]).write_bytes(b'changed')
        result = self.command('--resume')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('modified', result.stderr)

    def test_incomplete_checkpoint_cannot_be_packed_and_rejects_source_change(self):
        with Writer(self.source) as writer:
            writer.add(b'a.txt', b'one')
            writer.add(b'b.txt', b'two')
        code = '''
import os
from grf_extractor import cli
original = cli.write_atomic
def interrupt(target, data, **kwargs):
    original(target, data, **kwargs)
    if not kwargs.get('replace'):
        os._exit(99)
cli.write_atomic = interrupt
cli.main()
'''
        result = subprocess.run([sys.executable, '-c', code, '--portable', '--archive', str(self.source),
                                 '--output', str(self.output)], capture_output=True, text=True, timeout=20)
        self.assertEqual(result.returncode, 99)
        packed = self.root / 'partial.grf'
        result = subprocess.run([sys.executable, '-m', 'grfkit', 'pack', str(self.output), str(packed)],
                                capture_output=True, text=True, timeout=20)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(packed.exists())
        # Preserve size and mtime: resume identity must still detect changed source bytes.
        stamp = self.source.stat()
        data = bytearray(self.source.read_bytes())
        data[46] ^= 1
        self.source.write_bytes(data)
        os.utime(self.source, ns=(stamp.st_atime_ns, stamp.st_mtime_ns))
        result = self.command('--resume')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('archive_sha256', result.stderr)

    def test_unversioned_checkpoint_is_rejected_without_touching_outputs(self):
        with Writer(self.source) as writer:
            writer.add(b'a.txt', b'one')
        result = self.command()
        self.assertEqual(result.returncode, 0, result.stderr)
        checkpoint = self.output.with_suffix('.manifest.json')
        data = json.loads(checkpoint.read_text())
        data.pop('schema', None)
        checkpoint.write_text(json.dumps(data))
        before = (self.output / 'a.txt').stat().st_mtime_ns
        result = self.command('--resume')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('schema', result.stderr)
        self.assertEqual((self.output / 'a.txt').stat().st_mtime_ns, before)


class BoundedExtractionTests(unittest.TestCase):
    def test_filtered_archive_cli_does_not_hash_full_source(self):
        from unittest.mock import patch
        from grfkit.cli import main
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / 'source.grf'
            with Writer(source) as writer:
                writer.add(b'one.txt', b'one')
                writer.add(b'two.bin', b'two')
            with patch('grf_extractor.cli.sha256', side_effect=AssertionError('unexpected full-source hash')):
                self.assertEqual(main(['extract', str(source), str(root / 'out'), '--match', '*.txt']), 0)
            self.assertEqual((root / 'out/one.txt').read_bytes(), b'one')
            self.assertFalse((root / 'out/two.bin').exists())
            self.assertFalse((root / 'out.manifest.json').exists())

    def test_protected_alignment_and_probe_use_declared_payload(self):
        from grfkit.protected import encode_entry
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / 'source.grf'
            name, data = b'data\\protected', b'protected test' * 100
            payload = encode_entry(data, name)
            with Writer(source) as writer:
                writer.add_raw(name, payload + bytes(16), len(data), 128, compressed_size=len(payload))
            result = subprocess.run([sys.executable, '-m', 'grf_extractor', '--archive', str(source),
                '--output', str(root / 'out'), '--probe'], capture_output=True, text=True, timeout=20)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual((root / 'out/data/protected').read_bytes(), data)

    def test_decoder_runtime_failure_records_error_and_continues(self):
        from unittest.mock import patch
        from grf_extractor.cli import main
        from grf_extractor.codecs.decoder import PortableDecoder
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / 'source.grf'
            with Writer(source) as writer:
                writer.add(b'bad', b'bad content', protect=True)
                writer.add(b'good', b'good content', protect=True)
            decode = PortableDecoder.decode
            def failing_decoder(decoder, name, real, payload):
                if name == b'bad':
                    raise RuntimeError('native-style decoder failure')
                return decode(decoder, name, real, payload)
            with patch.object(PortableDecoder, 'decode', failing_decoder):
                self.assertEqual(main(['--archive', str(source), '--output', str(root / 'out')]), 1)
            self.assertEqual((root / 'out/good').read_bytes(), b'good content')
            checkpoint = json.loads((root / 'out.manifest.json').read_text())
            self.assertEqual(checkpoint['extracted'], 1)
            self.assertEqual(len(checkpoint['failures']), 1)
            self.assertIn('native-style decoder failure', checkpoint['failures'][0]['error'])
