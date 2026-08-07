# M0-A15-F2 — optimized next sequence-one activation runbook

This runbook is operational material for the next external activation attempt. It does not alter the frozen F2 normative verifier.

## Fixed bindings

- F1 head: `b66ba8d5b11ce4e9d30d5fdb70fb982db3e26095`
- F1 tree: `9c2ded5aedbf5c22d311461ad7ee42d8315f8763`
- history SHA-256: `5cc59426485811978f8d404681abbd309aa56121854daf963a0f6c5dba0d6965`
- F1 report digest: `e2cc5a3b3e4c68285b44b046e41ec2f694bea38bc9d76166918cd40beb4bcfb2`
- ingress receipt digest: `f9a0d4548634dd3c3d95013ba8eb0f08c02b7ce6bf04f420c9a0d50cc8666289`
- ingress readback-set digest: `3ca43a46ddd67f14380189ca73e2258b2b4f2c9945e53d0816a275eb47e6175e`
- ingress retrieved at: `2026-08-06T23:45:21Z`
- latest permitted activation instant under the 86,400 s ingress bound: `2026-08-07T23:45:21Z`

## GO gate before opening a window

Do not issue an activation unless all five surfaces report GO:

1. Witness Alpha workflow syntax/path and attempt-bound verifier ready.
2. Witness Beta GitLab `validate` green, File-type private-key variable exposed, `WITNESS_MODE=endorse` launch card ready.
3. Witness Gamma local profile/key/config tested and endorsement command ready.
4. Observer Beta GitLab validation/preflight green and `OBSERVER_MODE=activation` launch card ready.
5. Observer Gamma local key/config tested and activation-readback command ready.

No script, config file, URL or digest is to be manually rewritten after activation issuance.

## The eight execution stages

### 1 — Close and verify the predecessor attempt

Preserve all prior attempts append-only. Verify the last activation remains NT because activation-readback quorum was not met. Preserve its valid historical 3-of-4 witness quorum independently from the failed readback phase.

GO: prior evidence frozen, no branch rewrite, ingress still within its 86,400 s activation bound.

### 2 — Preflight all four external operator surfaces plus Alpha

Run all non-activation checks before issuing a fresh envelope. Beta secrets must be present without being printed. Gamma local keys must remain outside output directories. Every expected output directory must be writable and every runner must have its pinned Python/Ed25519 provider.

GO requires all five preflight entries in the manifest.

### 3 — Prepare one immutable launch card

Choose `ATTEMPT_ID` before issuance. Leave only `ACTIVATION_COMMIT` and `EXPECTED_ACTIVATION_DIGEST` unset. All witness/observer commands derive both immutable raw URLs from these three fresh values. Do not edit the commands after issuance.

### 4 — Issue the fresh activation and open the window

Generate a fresh Ed25519 authority key in memory, fresh nonce, `activationSequence=1`, `previousActivationDigest=null`, and a 3,300-second validity window. Verify the authority signature locally before publication. Publish byte-exactly under the attempt-specific append-only path and record the resulting commit.

The window starts only here.

### 5 — Obtain witness quorum in parallel

Alpha starts automatically from the issuance path. Start Beta and Gamma immediately in parallel using the immutable commit-bound URLs and the same expected activation digest.

Accept only endorsements with valid Ed25519 signatures and `activatedAt <= signedAt <= validUntil`.

GO to stage 6 as soon as any 3 of the 4 declared witnesses are accepted. Do not wait for Delta.

### 6 — Launch both activation readbacks immediately

As soon as 3-of-4 is cryptographically established, launch Observer Beta and Observer Gamma in parallel. No configuration edits are allowed at this stage.

Accept only signed readbacks bound to the exact activation digest, history digest and F1 report digest, with `activatedAt <= observedAt <= validUntil`.

### 7 — Assemble and replay the byte-exact F2 package

Assemble the exact external package from the fixed ingress material, activation authority/envelope, four declared witness profiles, at least three accepted witness endorsements, and at least two accepted activation readbacks. Preserve every source artifact and its SHA-256.

Choose and record an explicit `evaluation_at` inside the same activation window, then run the exact frozen F2 verifier with `--require-t`.

### 8 — Declare T or preserve NT without interpretation

Declare operational M0-A15-F2 `T` only if the exact replay returns T without errors. Freeze the package digest, evaluation instant, external artifact digests, activation digest and exact F2 head together.

Otherwise preserve the entire attempt append-only as NT with the exact failed predicate. Never extend the window, change timestamps, reuse the activation digest for a later attempt, or infer M0-A16 succession.
