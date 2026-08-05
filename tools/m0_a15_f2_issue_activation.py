#!/usr/bin/env python3
"""Issue a bounded, sequence-one M0-A15-F2 point-in-time activation."""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import secrets
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

F1_HEAD = "b66ba8d5b11ce4e9d30d5fdb70fb982db3e26095"
F1_TREE = "9c2ded5aedbf5c22d311461ad7ee42d8315f8763"
HISTORY_DIGEST = "5cc59426485811978f8d404681abbd309aa56121854daf963a0f6c5dba0d6965"
F1_REPORT_DIGEST = "e2cc5a3b3e4c68285b44b046e41ec2f694bea38bc9d76166918cd40beb4bcfb2"
INGRESS_RECEIPT_DIGEST = "87ee516f5712c092af37609dd05b086a723acb61021f2adb669b8fdf7b854c6e"
INGRESS_READBACK_SET_DIGEST = "ef1cc383dfd46eeb7a5b70cdbe54cf1a7f17420b91ec2eeebf594b1220439e96"


def canonical_bytes(value: Any) -> bytes:
    def guard(item: Any, path: str = "$") -> None:
        if item is None or isinstance(item, (bool, int, str)):
            return
        if isinstance(item, float):
            raise ValueError(f"floating-point-forbidden:{path}")
        if isinstance(item, list):
            for index, child in enumerate(item):
                guard(child, f"{path}[{index}]")
            return
        if isinstance(item, dict):
            for key, child in item.items():
                if not isinstance(key, str):
                    raise ValueError(f"non-string-key:{path}")
                guard(child, f"{path}.{key}")
            return
        raise ValueError(f"unsupported-type:{path}:{type(item).__name__}")
    guard(value)
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    ).encode("utf-8")


def digest_hex(value: Any) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def time_text(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(canonical_bytes(value) + b"\n")


def nonempty(value: str, name: str) -> str:
    if not value or "REPLACE_" in value:
        raise ValueError(f"authority-metadata-invalid:{name}")
    return value


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--principal-id", required=True)
    parser.add_argument("--control-domain-id", required=True)
    parser.add_argument("--identity-root", required=True)
    parser.add_argument("--provider-operator", required=True)
    parser.add_argument("--network-path", required=True)
    parser.add_argument("--implementation", default="eigiib-m0-a15-f2-activation-authority-v1")
    parser.add_argument("--key-id", required=True)
    parser.add_argument("--window-seconds", type=int, default=3300)
    parser.add_argument("--backdate-seconds", type=int, default=30)
    args = parser.parse_args()

    if not 60 <= args.window_seconds <= 3600:
        raise ValueError("activation-window-seconds-invalid")
    if not 0 <= args.backdate_seconds <= 120:
        raise ValueError("activation-backdate-seconds-invalid")
    for name in (
        "principal_id", "control_domain_id", "identity_root", "provider_operator",
        "network_path", "implementation", "key_id",
    ):
        nonempty(getattr(args, name), name)

    now = datetime.now(timezone.utc).replace(microsecond=0)
    activated_at = now - timedelta(seconds=args.backdate_seconds)
    valid_until = activated_at + timedelta(seconds=args.window_seconds)
    private_key = Ed25519PrivateKey.generate()
    public_raw = private_key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    authority_profile = {
        "principalId": args.principal_id,
        "role": "activation-authority",
        "controlDomainId": args.control_domain_id,
        "identityRoot": args.identity_root,
        "providerOperator": args.provider_operator,
        "networkPath": args.network_path,
        "implementation": args.implementation,
        "keyId": args.key_id,
        "algorithm": "ed25519",
        "publicKey": base64.b64encode(public_raw).decode("ascii"),
    }
    payload = {
        "recordType": "point-in-time-activation",
        "sourceF1Head": F1_HEAD,
        "sourceF1Tree": F1_TREE,
        "historyDigest": HISTORY_DIGEST,
        "f1ReportDigest": F1_REPORT_DIGEST,
        "ingressReceiptDigest": INGRESS_RECEIPT_DIGEST,
        "ingressReadbackSetDigest": INGRESS_READBACK_SET_DIGEST,
        "activationSequence": 1,
        "previousActivationDigest": None,
        "activationNonce": secrets.token_hex(32),
        "activatedAt": time_text(activated_at),
        "validUntil": time_text(valid_until),
        "decision": "m0-a15-f2-t-closure",
    }
    activation_envelope = {
        "payload": payload,
        "signature": {
            "algorithm": "ed25519",
            "keyId": args.key_id,
            "value": base64.b64encode(private_key.sign(canonical_bytes(payload))).decode("ascii"),
        },
    }
    record = {
        "standard": "EIGIIB-M0-A15-F2-ACTIVATION-ISSUANCE-RECORD-1.0",
        "authorityProfileDigest": digest_hex(authority_profile),
        "activationDigest": digest_hex(payload),
        "activationEnvelopeDigest": digest_hex(activation_envelope),
        "activatedAt": payload["activatedAt"],
        "validUntil": payload["validUntil"],
        "windowSeconds": args.window_seconds,
        "backdateSeconds": args.backdate_seconds,
        "privateKeyDisposition": "generated-in-memory-and-not-persisted",
        "claimBoundary": "sequence-one point-in-time activation issuance only; witness quorum and readbacks not inferred",
    }

    out = Path(args.output_dir)
    write_json(out / "activation-authority-profile.json", authority_profile)
    write_json(out / "activation-envelope.json", activation_envelope)
    write_json(out / "activation-issuance-record.json", record)
    lines = [
        f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.name}"
        for path in sorted(out.glob("*.json"))
    ]
    (out / "SHA256SUMS").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(json.dumps({
        "activationDigest": record["activationDigest"],
        "activatedAt": record["activatedAt"],
        "validUntil": record["validUntil"],
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
