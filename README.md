# EIGIIB M0-A15-F2 external evidence carrier — 2026-08-05

This public repository is the external carrier for the contemporaneous M0-A15-F2 campaign.

## Published immutable history

- Commit: `977581dee414851bfcfc1abd74eb44032f49933a`
- Tree: `5026fae04b96189f7c3427a563a155e448fafa43`
- Blob: `7b931c846c8e42b0bfa3d5ab6805d7bc49e205b6`
- Canonical length: `48010` bytes
- Canonical SHA-256: `5cc59426485811978f8d404681abbd309aa56121854daf963a0f6c5dba0d6965`
- Media type: `application/vnd.eigiib.m0-a15-f1-history+json`

Immutable locator:

```text
https://raw.githubusercontent.com/Nico59000/EIGIIB-M0-A15-F2-external-evidence-20260805/977581dee414851bfcfc1abd74eb44032f49933a/external-evidence/m0-a15-f2/authenticated-history.json
```

## Signed ingress publication

The publisher profile, carrier record, signed ingress receipt, authoritative publication record and exact observer inputs are under:

```text
external-evidence/m0-a15-f2/publication/
```

The F2 `INGRESS_RECEIPT_DIGEST` is the SHA-256 digest of the canonical receipt **payload**:

```text
87ee516f5712c092af37609dd05b086a723acb61021f2adb669b8fdf7b854c6e
```

The complete signed envelope digest is recorded separately and must not be substituted for the payload digest.

## Current claim boundary

Established:

- canonical F1 history bytes published at an immutable external GitHub locator;
- exact length and digest checked by GitHub Actions;
- publisher ingress receipt signed with Ed25519;
- exact Observer A/B ingress variables published.

Not yet established:

- two independent signed ingress readbacks;
- exact live F1 replay resulting in `T`;
- activation authority issuance and 3-of-4 witness quorum;
- two independent activation readbacks;
- operational M0-A15-F2 point-in-time `T` closure.

The normative F2 verifier remains bound to `Nico59000/EIGIIB-norm` head `91cc92a4928382b09868a65a4c57e657e4bdf4ef`.
