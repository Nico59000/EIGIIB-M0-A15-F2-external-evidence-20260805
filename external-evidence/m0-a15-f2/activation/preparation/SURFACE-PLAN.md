# M0-A15-F2 — Point-in-time activation surface plan

## Current state

The external authenticated history, the independent Alpha/Beta ingress quorum and the exact F1 replay are accepted. The activation is deliberately **not issued yet**.

The validity window is bounded to at most 3,600 seconds. Issuance before all external signing surfaces are configured would create an avoidable expiration race.

## Authority and 3-of-4 witness topology

| Role | Surface | Key lifecycle | Planned use |
|---|---|---|---|
| Activation authority | isolated session runtime distinct from GitHub and GitLab | generated in memory and destroyed after issuance | sequence-one activation signature |
| Witness Alpha | GitHub Actions hosted runner | ephemeral in-memory key | endorsement 1 |
| Witness Beta | separate GitLab CI repository | protected File variable | endorsement 2 |
| Witness Gamma | isolated local workstation | local key outside repository | endorsement 3 |
| Witness Delta | distinct Cloud Build project | Secret Manager key | registered reserve; optional endorsement 4 |

The final activation package requires four real witness profiles with pairwise-distinct `controlDomainId`, `identityRoot` and `providerOperator`, plus at least three valid endorsements.

## Activation readback topology

The ingress Observer Alpha key was intentionally ephemeral and destroyed. It cannot sign an activation readback.

The prepared closure therefore uses:

1. the existing Observer Beta GitLab with its persistent observer key and `OBSERVER_MODE=activation`;
2. a new local Activation Observer Gamma with a key separate from Witness Gamma.

The final observer inventory may contain ingress Alpha, ingress/activation Beta and activation Gamma. Their five observer-independence coordinates must remain pairwise distinct.

## Required surfaces before issuance

1. Import the Witness Beta GitLab bundle into a separate repository, recommended path `eigiib/eigiib-m0-a15-f2-witness-beta`.
2. Create `ACTIVATION_WITNESS_BETA_PRIVATE_KEY_PEM` as a protected GitLab File variable and validate `WITNESS_MODE=profile`.
3. Configure Witness Gamma with truthful local metadata, a separate Ed25519 key and a successful profile-mode smoke test.
4. Configure Witness Delta in a genuinely separate provider project and obtain its real public profile. Delta may remain non-signing if Alpha, Beta and Gamma succeed.
5. Configure Activation Observer Gamma locally with a key distinct from the local witness key.
6. Confirm that the existing GitLab Observer Beta activation mode and private key remain available.

## Live execution order

1. Generate an activation-authority key in memory.
2. Issue sequence `1` with `previousActivationDigest=null`, a fresh 64-hex nonce, a 30-second backdate and a 3,300-second window.
3. Publish the authority profile and activation envelope in one immutable carrier commit.
4. Let Witness Alpha run automatically.
5. Launch Witness Beta and Witness Gamma immediately; use Delta only if one active witness fails.
6. Collect four profiles and at least three endorsements.
7. During the same window, run Observer Beta GitLab in activation mode and local Activation Observer Gamma.
8. Assemble the exact package and evaluate with a caller-supplied instant inside `[activatedAt, validUntil]`.

## Abort conditions

Abort this activation instance and issue a fresh one if any signature, digest or independence coordinate fails; if a mobile branch URL was used; if fewer than three endorsements are available; if either activation readback is missing; or if `validUntil` has passed.

An expired activation must never be edited or extended. A fresh nonce, key, envelope and immutable publication are required.
