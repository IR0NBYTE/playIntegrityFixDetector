#!/usr/bin/env python3
"""Refresh the bundled copy of Google's key attestation revocation list.

Writes app/src/main/assets/revocation_snapshot.bin (gzip payload; the .bin
extension matters because aapt2 silently decompresses and renames .gz assets). Refuses to write anything
unless every guard below passes, because a bad snapshot is worse than a stale
one: a short or empty list still answers "not listed" for every serial.

Guards:
  HTTP 200, JSON content type, body under 2 MiB
  a top-level "entries" object with at least MIN_ENTRIES members
  every key lowercases to ^[0-9a-f]{8,64}$
  the new entry count is not more than SHRINK_TOLERANCE below the committed one

Output is byte reproducible: serials are sorted, gzip mtime is pinned to 0.
"""

import argparse
import gzip
import json
import os
import re
import sys
import urllib.request

STATUS_URL = "https://android.googleapis.com/attestation/status"
ASSET_REL = os.path.join("app", "src", "main", "assets", "revocation_snapshot.bin")
SERIAL_RE = re.compile(r"^[0-9a-f]{8,64}$")
MAX_BODY = 2 * 1024 * 1024
MIN_ENTRIES = 1000
SHRINK_TOLERANCE = 0.20
KEPT_STATUSES = ("REVOKED", "SUSPENDED")
HEADER_VERSION = "# pifd-revocation-snapshot v1"


def fail(message):
    print("refresh_snapshot: " + message, file=sys.stderr)
    sys.exit(1)


def fetch(url):
    request = urllib.request.Request(url, headers={"Accept": "application/json"})
    with urllib.request.urlopen(request, timeout=60) as response:
        if response.status != 200:
            fail("expected HTTP 200, got %s" % response.status)
        content_type = (response.headers.get("Content-Type") or "").lower()
        if "json" not in content_type:
            fail("expected a JSON content type, got %r" % content_type)
        body = response.read(MAX_BODY + 1)
        if len(body) > MAX_BODY:
            fail("body larger than %d bytes, refusing" % MAX_BODY)
        return body, response.headers.get("Last-Modified") or "unknown"


def parse(body):
    try:
        document = json.loads(body.decode("utf-8"))
    except (ValueError, UnicodeDecodeError) as error:
        fail("body is not valid JSON: %s" % error)
    entries = document.get("entries")
    if not isinstance(entries, dict) or not entries:
        fail("no usable top-level 'entries' object")
    if len(entries) < MIN_ENTRIES:
        fail("only %d entries, expected at least %d" % (len(entries), MIN_ENTRIES))
    serials = set()
    for key, value in entries.items():
        lowered = str(key).lower()
        if not SERIAL_RE.match(lowered):
            fail("entry key is not a serial: %r" % key)
        status = ""
        if isinstance(value, dict):
            status = str(value.get("status", "")).upper()
        if status in KEPT_STATUSES:
            serials.add(lowered)
    if len(serials) < MIN_ENTRIES:
        fail(
            "only %d usable REVOKED/SUSPENDED entries after filtering, expected at "
            "least %d. A short list is worse than a stale one: it still answers "
            "'not listed' for every serial." % (len(serials), MIN_ENTRIES)
        )
    return serials


def read_committed(path):
    """Returns None when there is no committed asset, which is the only case
    where skipping the shrink guard is legitimate. An asset that exists but
    cannot be read is an error, not an empty baseline."""
    if not os.path.exists(path):
        return None
    try:
        with gzip.open(path, "rt", encoding="utf-8") as handle:
            return {
                line.strip()
                for line in handle
                if line.strip() and not line.startswith("#")
            }
    except OSError as error:
        fail("existing snapshot at %s could not be read: %s" % (path, error))


def render(serials, fetched, last_modified):
    lines = [
        HEADER_VERSION,
        "# source: " + STATUS_URL,
        "# fetched: " + fetched,
        "# last-modified: " + last_modified,
        "# entries: %d" % len(serials),
    ]
    lines.extend(sorted(serials))
    return ("\n".join(lines) + "\n").encode("utf-8")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", default=os.getcwd())
    parser.add_argument("--fetched", required=True, help="snapshot date, YYYY-MM-DD")
    args = parser.parse_args()

    if not re.match(r"^\d{4}-\d{2}-\d{2}$", args.fetched):
        fail("--fetched must be YYYY-MM-DD")

    asset_path = os.path.join(args.repo_root, ASSET_REL)
    previous = read_committed(asset_path)

    body, last_modified = fetch(STATUS_URL)
    serials = parse(body)

    if previous is not None and len(serials) < len(previous) * (1 - SHRINK_TOLERANCE):
        fail(
            "entry count fell from %d to %d, more than %d percent. A shrinking "
            "revocation list is anomalous and needs a human."
            % (len(previous), len(serials), int(SHRINK_TOLERANCE * 100))
        )

    payload = render(serials, args.fetched, last_modified)
    os.makedirs(os.path.dirname(asset_path), exist_ok=True)
    with open(asset_path, "wb") as raw:
        with gzip.GzipFile(fileobj=raw, mode="wb", compresslevel=9, mtime=0) as gz:
            gz.write(payload)

    baseline = previous or set()
    added = sorted(serials - baseline)
    removed = sorted(baseline - serials)
    print("entries: %d (was %d)" % (len(serials), len(baseline)))
    print("added: %d" % len(added))
    print("removed: %d" % len(removed))
    for serial in added[:40]:
        print("  + " + serial)
    for serial in removed[:40]:
        print("  - " + serial)
    print("wrote " + asset_path)


if __name__ == "__main__":
    main()
