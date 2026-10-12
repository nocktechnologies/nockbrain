"""Channel-frame grammar shared by ingest and derived-artifact purge."""
from __future__ import annotations

import re


# Channel-relay plugins emit 12-character lowercase hexadecimal frame IDs.
# This pattern is deliberately unanchored so callers can locate complete frames
# embedded in a larger artifact; ingest validates a whole message with fullmatch().
CHANNEL_FRAME_RE = re.compile(
    r"(?P<opening_tag><channel\s[^>]*>)\s*"
    r"\[BEGIN UNTRUSTED CHANNEL CONTENT #(?P<frame_id>[0-9a-f]{12})[^\]]*\]\s*"
    r"(?P<body>(?:(?!\[END UNTRUSTED CHANNEL CONTENT #(?P=frame_id)\]).)*)\s*"
    r"\[END UNTRUSTED CHANNEL CONTENT #(?P=frame_id)\]\s*</channel>",
    re.DOTALL,
)
