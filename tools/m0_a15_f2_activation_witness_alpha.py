#!/usr/bin/env python3
"""Issue one ephemeral GitHub Actions activation-witness endorsement for M0-A15-F2."""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

F1_HEAD = "b66ba8d5b11ce4e9d30d5fdb70fb982db3e26095"
F1_TREE = "9c2ded5aedbf5c22d311461ad7ee42d8315f8763"
HISTORY_DIGEST = "5cc59426485811978f8d404681abbd309aa56121854daf963a0f6c5dba0d6965"
F1_REPORT_DIGEST = "e2cc5a3b3e4c68285b44b046e41ec2f694bea38bc9d76166918cd40beb4bcfb2"
INGRESS_RECEIPT_DIGEST = "87ee516f5712c092af37609dd05b086a723acb61021f2adb669b8fdf7b854c6e"
INGRESS_READBACK_SET_DIGEST = "ef1cc383dfd46eeb7a5b70cdbe54cf1a7f17420b91ec2eeebf594b1220439e96"
ACTIVATION_KEYS = {
    "recordType", "sourceF1Head", "sourceF1Tree", "historyDigest", "f1ReportDigest",
    "ingressReceiptDigest", "ingressReadbackSetDigest", "activationSequence",
    "previousActivationDigest", "activationNonce", "activatedAt", "validUntil", "decision",
}
PROFILE_KEYS = {
    "principalId", "role", "controlDomainId", "identityRoot", "providerOperator",
    "networkPath", "implementation", "keyId", "algorithm", "publicKey",
}


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


def parse_time(value: Any) -> datetime:
    if not isinstance(value, str):
        raise ValueError("time-not-string")
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("time-not-zoned")
    return parsed.astimezone(timezone.utc)


def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(canonical_bytes(value) + b"\n")


def verify_authority(profile: Any, envelope: Any) -> tuple[dict[str, Any], str, datetime, datetime]:
    if not isinstance(profile, dict) or set(profile) != PROFILE_KEYS:
        raise ValueError("activation-authority-profile-shape-invalid")
    if profile.get("role") != "activation-authority" or profile.get("algorithm") != "ed25519":
        raise ValueError("activation-authority-profile-role-or-algorithm-invalid")
    if not isinstance(envelope, dict) or set(envelope) != {"payload", "signature"}:
        raise ValueError("activation-envelope-shape-invalid")
    payload = envelope.get("payload")
    signature = envelope.get("signature")
    if not isinstance(payload, dict) or set(payload) != ACTIVATION_KEYS:
        raise ValueError("activation-payload-shape-invalid")
    if not isinstance(signature, dict) or set(signature) != {"algorithm", "keyId", "value"}:
        raise ValueError("activation-signature-shape-invalid")
    expected = {
        "recordType": "point-in-time-activation",
        "sourceF1Head": F1_HEAD,
        "sourceF1Tree": F1_TREE,
        "historyDigest": HISTORY_DIGEST,
        "f1ReportDigest": F1_REPORT_DIGEST,
        "ingressReceiptDigest": INGRESS_RECEIPT_DIGEST,
        "ingressReadbackSetDigest": INGRESS_READBACK_SET_DIGEST,
        "activationSequence": 1,
        "previousActivationDigest": None,
        "activationNonce": payload.get("activationNonce"),
        "activatedAt": payload.get("activatedAt"),
        "validUntil": payload.get("validUntil"),
        "decision": "m0-a15-f2-t-closure",
    }
    if payload != expected:
        raise ValueError("activation-payload-not-derived")
    nonce = payload.get("activationNonce")
    if not isinstance(nonce, str) or len(nonce) != 64 or any(c not in "0123456789abcdef" for c in nonce):
        raise ValueError("activation-nonce-invalid")
    if signature.get("algorithm") != "ed25519" or signature.get("keyId") != profile.get("keyId"):
        raise ValueError("activation-signature-binding-invalid")
    public_raw = base64.b64decode(profile["publicKey"], validate=True)
    signature_raw = base64.b64decode(signature["value"], validate=True)
    if len(public_raw) != 32 or len(signature_raw) != 64:
        raise ValueError("activation-key-or-signature-length-invalid")
    Ed25519PublicKey.from_public_bytes(public_raw).verify(signature_raw, canonical_bytes(payload))
    activated_at = parse_time(payload["activatedAt"])
    valid_until = parse_time(payload["validUntil"])
    if not activated_at < valid_until:
        raise ValueError("activation-window-order-invalid")
    if (valid_until - activated_at).total_seconds() > 3600:
        raise ValueError("activation-window-exceeded")
    return payload, digest_hex(payload), activated_at, valid_until


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--authority-profile", required=True)
    parser.add_argument("--activation-envelope", required=True)
    parser.add_argument("--output-dir", required=True)
    args = parser.parse_args()

    profile_path = Path(args.authority_profile)
    envelope_path = Path(args.activation_envelope)
    output_dir = Path(args.output_dir)
    authority_profile = load_json(profile_path)
    activation_envelope = load_json(envelope_path)
    activation_payload, activation_digest, activated_at, valid_until = verify_authority(
        authority_profile, activation_envelope
    )

    signed_at = datetime.now(timezone.utc)
    if not activated_at <= signed_at <= valid_until:
        raise ValueError("witness-signing-time-outside-activation-window")
    signed_at_text = signed_at.isoformat(timespec="seconds").replace("+00:00", "Z")

    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    run_id = os.environ.get("GITHUB_RUN_ID", "unknown")
    run_attempt = os.environ.get("GITHUB_RUN_ATTEMPT", "unknown")
    key_id = f"activation-witness-alpha-ed25519-{run_id}-{run_attempt}"
    witness_profile = {
        "principalId": "m0-a15-f2-activation-witness-alpha-github",
        "role": "activation-witness",
        "controlDomainId": "github-actions-witness-alpha-control",
        "identityRoot": "github:Nico59000/EIGIIB-M0-A15-F2-external-evidence-20260805:actions:witness-alpha",
        "providerOperator": "github-actions-hosted-runner",
        "networkPath": "github-actions-ubuntu-public-egress",
        "implementation": "eigiib-m0-a15-f2-witness-alpha-v1",
        "keyId": key_id,
        "algorithm": "ed25519",
        "publicKey": base64.b64encode(public_key).decode("ascii"),
    }
    endorsement_payload = {
        "recordType": "point-in-time-activation-endorsement",
        "witnessId": witness_profile["principalId"],
        "controlDomainId": witness_profile["controlDomainId"],
        "activationDigest": activation_digest,
        "signedAt": signed_at_text,
    }
    endorsement_envelope = {
        "payload": endorsement_payload,
        "signature": {
            "algorithm": "ed25519",
            "keyId": key_id,
            "value": base64.b64encode(private_key.sign(canonical_bytes(endorsement_payload))).decode("ascii"),
        },
    }
    record = {
        "standard": "EIGIIB-M0-A15-F2-ACTIVATION-WITNESS-RECORD-1.0",
        "profileDigest": digest_hex(witness_profile),
        "activationAuthorityProfileDigest": digest_hex(authority_profile),
        "activationEnvelopeDigest": digest_hex(activation_envelope),
        "activationDigest": activation_digest,
        "endorsementPayloadDigest": digest_hex(endorsement_payload),
        "endorsementEnvelopeDigest": digest_hex(endorsement_envelope),
        "signedAt": signed_at_text,
        "workflow": {
            "repository": os.environ.get("GITHUB_REPOSITORY"),
            "workflow": os.environ.get("GITHUB_WORKFLOW"),
            "runId": run_id,
            "runAttempt": run_attempt,
            "job": os.environ.get("GITHUB_JOB"),
            "sha": os.environ.get("GITHUB_SHA"),
            "runnerName": os.environ.get("RUNNER_NAME"),
            "runnerOs": os.environ.get("RUNNER_OS"),
            "runnerArch": os.environ.get("RUNNER_ARCH"),
        },
        "privateKeyDisposition": "generated-in-memory-and-not-persisted",
    }

    write_json(output_dir / "activation-witness-alpha-profile.json", witness_profile)
    write_json(output_dir / "activation-endorsement-envelope.json", endorsement_envelope)
    write_json(output_dir / "activation-witness-alpha-record.json", record)
    write_json(output_dir / "activation-envelope-observed.json", activation_envelope)
    write_json(output_dir / "activation-authority-profile-observed.json", authority_profile)

    sums = []
    for path in sorted(output_dir.glob("*.json")):
        sums.append(f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.name}")
    (output_dir / "SHA256SUMS").write_text("\n".join(sums) + "\n", encoding="utf-8")
    print(json.dumps({"activationDigest": activation_digest, "signedAt": signed_at_text}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
