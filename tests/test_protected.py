"""Exercise the portable package against the existing independent decoder vectors."""

from pathlib import Path
import struct
import unittest

from grf_extractor.codecs.decoder import PortableDecoder
from grf_extractor.codecs.footer import decode_footer


def fixtures():
    data = (Path(__file__).parent / "fixtures/protected-grf.bin").read_bytes()
    offset = 0

    def number():
        nonlocal offset
        value, = struct.unpack_from("<I", data, offset)
        offset += 4
        return value

    for _ in range(number()):
        fields = []
        for _ in range(5):
            size = number()
            fields.append(data[offset:offset + size])
            offset += size
        yield (*fields, number())
    assert offset == len(data), "Trailing fixture data"


class ProtectedDecodingTests(unittest.TestCase):
    def test_independent_valid_and_invalid_vectors(self):
        valid = {"raw-name", "zlib-rc6-footer", "lz4-aes-checksum", "threeway-partial", "body1-lz4"}
        for tag, name, footer, payload, expected, size in fixtures():
            tag = tag.decode()

            def decode():
                keys = decode_footer(footer) if footer else {}
                return PortableDecoder(keys).decode(name, size, payload)

            with self.subTest(tag=tag):
                if tag in valid or tag.startswith("boundary-"):
                    self.assertEqual(decode(), expected)
                else:
                    with self.assertRaises(ValueError):
                        decode()
