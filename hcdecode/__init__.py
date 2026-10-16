"""HTTP Custom offline decoder for the observed legacy profile."""
__version__ = "0.1.0"

from .decoder import decode_bytes, decode_file
from .errors import DecodeError

__all__ = ["decode_bytes", "decode_file", "DecodeError", "__version__"]
