#!/usr/bin/env python3
"""Post the registration vectors to a Transparency Service and print what it answers.

  python3 run_against.py https://your-test-instance.example [--only R01,R03]

USE A TEST INSTANCE. A log is append-only: every statement a service accepts stays in it, and these are test
statements signed with a key whose seed is published in make_vectors.py. Standard library only.

This script records the initial HTTP response only. A 202 is pending, not a completed registration. It does not
verify a receipt or compare the registered statement bytes; those checks must be performed separately using the
service's returned Location and documented retrieval interface. Exit status 0 does not mean that every statement was
registered or that the service passed a conformance test."""
import http.client
import json
import pathlib
import sys
import urllib.parse

HERE = pathlib.Path(__file__).resolve().parent


def main(argv):
    if len(argv) < 2:
        print(__doc__)
        return 2
    url = urllib.parse.urlsplit(argv[1])
    only = set(argv[argv.index("--only") + 1].split(",")) if "--only" in argv else None
    meta = json.loads((HERE / "vectors" / "vectors.json").read_text(encoding="utf-8"))
    print("| Vector | Status | Location | Answer (first bytes, hex) |")
    print("|---|---|---|---|")
    for item in meta["vectors"]:
        if only and item["id"] not in only:
            continue
        raw = (HERE / "vectors" / item["file"]).read_bytes()
        cls = http.client.HTTPSConnection if url.scheme == "https" else http.client.HTTPConnection
        conn = cls(url.netloc, timeout=30)
        conn.request("POST", (url.path.rstrip("/") or "") + "/entries", body=raw,
                     headers={"Content-Type": "application/cose", "Accept": "application/cose, application/concise-problem-details+cbor",
                              "Content-Length": str(len(raw)), "User-Agent": "registration-vectors/1"})
        resp = conn.getresponse()
        body = resp.read()
        print(f"| {item['id']} | {resp.status} | {resp.getheader('Location') or ''} | {body[:48].hex()} |")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
