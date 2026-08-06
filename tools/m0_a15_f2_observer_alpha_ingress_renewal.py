#!/usr/bin/env python3
from __future__ import annotations

import base64
import hashlib
import json
import os
import pathlib
import re
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


def canonical_bytes(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")


def write_json(path: pathlib.Path, value):
    path.write_bytes(canonical_bytes(value) + b"\n")


def main() -> int:
    root = pathlib.Path("artifacts")
    raw = (root / "received/authenticated-history.json").read_bytes()
    parsed = json.loads(raw.decode("utf-8"))
    canonical = canonical_bytes(parsed)
    raw_digest = hashlib.sha256(raw).hexdigest()
    canonical_digest = hashlib.sha256(canonical).hexdigest()
    expected_digest = os.environ["EXPECTED_HISTORY_DIGEST"]
    expected_length = int(os.environ["EXPECTED_CONTENT_LENGTH"])
    if raw != canonical:
        raise SystemExit("history-not-byte-exact-canonical")
    if len(raw) != expected_length:
        raise SystemExit("history-content-length-mismatch")
    if raw_digest != expected_digest or canonical_digest != expected_digest:
        raise SystemExit("history-digest-mismatch")

    metadata = (root / "curl-metadata.txt").read_text(encoding="utf-8").splitlines()
    if len(metadata) != 4:
        raise SystemExit("curl-metadata-shape-invalid")
    http_status, effective_url, content_type, downloaded_size = metadata
    requested_url = os.environ["CARRIER_URL"]
    if http_status != "200":
        raise SystemExit("carrier-http-status-invalid")
    if effective_url != requested_url:
        raise SystemExit("carrier-effective-url-mismatch")
    if int(downloaded_size) != expected_length:
        raise SystemExit("carrier-downloaded-size-mismatch")
    if not re.search(r"/[0-9a-f]{40}/", requested_url):
        raise SystemExit("carrier-url-not-commit-bound")

    observed_at = (root / "retrieval-completed-at.txt").read_text(encoding="utf-8").strip()
    started_at = (root / "retrieval-started-at.txt").read_text(encoding="utf-8").strip()

    private_key = Ed25519PrivateKey.generate()
    public_raw = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    key_id = f"observer-alpha-ingress-ed25519-{os.environ['GITHUB_RUN_ID']}-{os.environ['GITHUB_RUN_ATTEMPT']}"
    profile = {
        "principalId": "m0-a15-f2-observer-alpha-ingress-20260805",
        "role": "observer",
        "controlDomainId": "github-actions-observer-alpha-ingress-control",
        "identityRoot": "github-actions:Nico59000/EIGIIB-M0-A15-F2-external-evidence-20260805:observer-alpha",
        "providerOperator": "github-actions-hosted-runner-observer-alpha",
        "networkPath": "github-actions-ubuntu-24.04-public-egress-alpha",
        "implementation": "eigiib-m0-a15-f2-observer-alpha-python-renewal-1",
        "keyId": key_id,
        "algorithm": "ed25519",
        "publicKey": base64.b64encode(public_raw).decode("ascii"),
    }
    payload = {
        "recordType": "external-history-readback",
        "observerId": profile["principalId"],
        "controlDomainId": profile["controlDomainId"],
        "historyDigest": expected_digest,
        "ingressReceiptDigest": os.environ["INGRESS_RECEIPT_DIGEST"],
        "carrierId": os.environ["CARRIER_ID"],
        "carrierLocator": requested_url,
        "observedAt": observed_at,
    }
    signature = private_key.sign(canonical_bytes(payload))
    envelope = {
        "payload": payload,
        "signature": {
            "algorithm": "ed25519",
            "keyId": key_id,
            "value": base64.b64encode(signature).decode("ascii"),
        },
    }
    private_key.public_key().verify(signature, canonical_bytes(payload))
    record = {
        "standard": "EIGIIB-M0-A15-F2-OBSERVER-READBACK-1.0",
        "mode": "ingress",
        "observerProfile": profile,
        "pipeline": {
            "GITHUB_ACTIONS": os.environ.get("GITHUB_ACTIONS"),
            "GITHUB_REPOSITORY": os.environ.get("GITHUB_REPOSITORY"),
            "GITHUB_SHA": os.environ.get("GITHUB_SHA"),
            "GITHUB_REF": os.environ.get("GITHUB_REF"),
            "GITHUB_RUN_ID": os.environ.get("GITHUB_RUN_ID"),
            "GITHUB_RUN_NUMBER": os.environ.get("GITHUB_RUN_NUMBER"),
            "GITHUB_RUN_ATTEMPT": os.environ.get("GITHUB_RUN_ATTEMPT"),
            "RUNNER_NAME": os.environ.get("RUNNER_NAME"),
            "RUNNER_OS": os.environ.get("RUNNER_OS"),
            "RUNNER_ARCH": os.environ.get("RUNNER_ARCH"),
        },
        "source": {
            "requestedUrl": requested_url,
            "effectiveUrl": effective_url,
            "httpStatus": int(http_status),
            "contentType": content_type or None,
            "retrievalStartedAt": started_at,
            "retrievalCompletedAt": observed_at,
        },
        "download": {
            "rawLength": len(raw),
            "rawSha256": raw_digest,
            "canonicalLength": len(canonical),
            "canonicalSha256": canonical_digest,
            "byteExactCanonical": raw == canonical,
        },
        "signedPayloadDigest": hashlib.sha256(canonical_bytes(payload)).hexdigest(),
        "signedEnvelopeDigest": hashlib.sha256(canonical_bytes(envelope)).hexdigest(),
        "privateKeyDisposition": "ephemeral-runner-key-never-persisted",
        "scopeBoundary": "renewed ingress-readback-only; activation is not inferred",
    }
    write_json(root / "observer-alpha-profile.json", profile)
    write_json(root / "ingress-readback-envelope.json", envelope)
    write_json(root / "ingress-readback-record.json", record)
    print(json.dumps({
        "observedAt": observed_at,
        "payloadDigest": record["signedPayloadDigest"],
        "envelopeDigest": record["signedEnvelopeDigest"],
        "keyId": key_id,
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
