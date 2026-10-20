import importlib.util
import os
from pathlib import Path

import pytest

from grfkit.legacy import decode_full, encode_header, transform_block


def independent_encoder():
    root = Path(os.environ.get(
        "GRF_REFERENCE_ROOT",
        Path(__file__).resolve().parents[3] / "roBrowserLegacy-RemoteClient-Rust",
    ))
    path = root / "scripts/grf_des.py"
    if not path.exists():
        pytest.skip("reference checkout needed for differential DES test")
    spec = importlib.util.spec_from_file_location("encoder", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.mark.parametrize("length", [0, 7, 8, 160, 161, 1234, 12345, 100000])
def test_legacy_payload_against_independent_encoder(length):
    encoder = independent_encoder()
    data = bytes((i * 31 + 17) % 256 for i in range(length))
    encrypted = encoder.encode_full(data, len(data), length)
    assert decode_full(encrypted, len(encrypted), length) == data
    assert encode_header(encoder.encode_header(data, length), length) == data


def test_block_is_involution():
    data = bytes.fromhex("0123456789abcdef")
    assert bytes(transform_block(transform_block(data))) == data
