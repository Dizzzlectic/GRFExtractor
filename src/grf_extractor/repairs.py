"""Compatibility names for the shared explicit, non-lossless WAV repair."""

from grfkit.archive import (
    WAV_NAME,
    WAV_OUTPUT_SHA256,
    WAV_PAYLOAD_SHA256 as WAV_INPUT_SHA256,
    repair_known_wav,
)

__all__ = ["WAV_NAME", "WAV_INPUT_SHA256", "WAV_OUTPUT_SHA256", "repair_known_wav"]
