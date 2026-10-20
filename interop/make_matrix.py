"""Generate synthetic Python-writer archives for independent C# verification.

Usage: python interop/make_matrix.py OUTPUT_DIR
The destination must be new, so an earlier verification fixture is preserved.
"""

import hashlib
import itertools
from pathlib import Path
import sys

from grfkit.archive import Writer
from grfkit.protected import encode_entry


def main():
    destination = Path(sys.argv[1])
    destination.mkdir(parents=True, exist_ok=False)
    expected = destination / "expected"
    expected.mkdir()
    keys = {7: bytes((i * 31 + 7) % 256 for i in range(60)),
            42: bytes((i * 13 + 11) % 256 for i in range(60))}
    count = 0
    archive = destination / "matrix.grf"
    with Writer(archive, keys=keys) as writer:
        def add(label, data, cipher, compression, header, flags, key_id):
            nonlocal count
            name = f"data\\한글\\{label}.bin"
            raw_name = name.encode("cp949")
            payload = encode_entry(data, raw_name, cipher=cipher,
                compression=compression, header_type=header, flags=flags,
                keys=keys, key_id=key_id,
                material=None if key_id else keys[7])
            writer.add_raw(raw_name, payload, len(data), 0x80)
            local = expected.joinpath(*name.split("\\"))
            local.parent.mkdir(parents=True, exist_ok=True)
            local.write_bytes(data)
            count += 1

        for cipher, header, compression, flags, key_id in itertools.product(
                (1, 5, 7, 128, 133), (1, 2, 15, 0x71), (0, 1, 2),
                (0, 1), (0, 7, 42)):
            label = f"c{cipher}-h{header}-z{compression}-f{flags}-k{key_id}"
            data = hashlib.shake_256(label.encode()).digest(1351)
            add(label, data, cipher, compression, header, flags, key_id)
        for cipher, size in itertools.product((1, 5, 7, 128, 133),
                (0, 1, 127, 128, 129, 143, 144, 1151, 1152, 1153, 3199, 3200, 3201)):
            label = f"boundary-c{cipher}-n{size}"
            data = hashlib.shake_256(label.encode()).digest(size)
            add(label, data, cipher, 0, 2, size % 2, 0)
    print(f"Generated {archive}: {count} protected files; expected contents in {expected}")


if __name__ == "__main__":
    main()
