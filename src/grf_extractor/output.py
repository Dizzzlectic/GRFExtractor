"""Safe extraction destinations, atomic writes and file hashes."""

import hashlib
import os
from pathlib import Path
import tempfile


def sha256(path):
    with path.open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def write_atomic(target, data, *, replace=False):
    """Publish a complete file and remove only the temporary file we created."""
    if not replace and (target.exists() or target.is_symlink()):
        raise ValueError("Duplicate extraction path")
    descriptor, temporary_name = tempfile.mkstemp(prefix=".grf-", suffix=".tmp", dir=target.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as output:
            output.write(data)
            if replace:
                output.flush()
                os.fsync(output.fileno())
        if not replace and (target.exists() or target.is_symlink()):
            raise ValueError("Duplicate extraction path")
        os.replace(temporary, target)
    finally:
        temporary.unlink(missing_ok=True)
