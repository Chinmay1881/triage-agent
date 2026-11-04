"""Decode PowerShell -EncodedCommand payloads so the agent sees what actually runs.

Decoding happens on the full command line, before the 300-character cap: cutting base64
first would break it. The decoded text is still log content (s12 hides its prompt injection
there), so it goes back inside untrusted_log_data like everything else.
"""

import base64
import binascii
import re

# PowerShell accepts any unambiguous prefix; these are the forms seen in practice.
ENCODED_ARG = re.compile(r"(?:^|\s)-e(?:c|nc|ncodedcommand)?\s+([A-Za-z0-9+/=]{8,})", re.I)
UNDECODABLE = "[could not decode -EncodedCommand payload]"


def decode_encoded_command(cmdline: str) -> str | None:
    """The decoded script(s), UNDECODABLE if an -enc argument is malformed, else None."""
    blobs = ENCODED_ARG.findall(cmdline)
    if not blobs:
        return None
    decoded = []
    for blob in blobs:
        try:
            decoded.append(base64.b64decode(blob, validate=True).decode("utf-16-le"))
        except (binascii.Error, UnicodeDecodeError):
            return UNDECODABLE
    return " ; ".join(decoded)
