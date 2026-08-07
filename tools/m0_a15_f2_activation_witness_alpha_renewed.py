#!/usr/bin/env python3
"""Campaign-bound launcher for Witness Alpha on the renewed ingress quorum."""
from __future__ import annotations

import importlib.util
from pathlib import Path

BASE = Path(__file__).with_name("m0_a15_f2_activation_witness_alpha.py")
spec = importlib.util.spec_from_file_location("m0_a15_f2_activation_witness_alpha_base", BASE)
if spec is None or spec.loader is None:
    raise RuntimeError("witness-alpha-base-load-failed")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)

module.INGRESS_RECEIPT_DIGEST = "f9a0d4548634dd3c3d95013ba8eb0f08c02b7ce6bf04f420c9a0d50cc8666289"
module.INGRESS_READBACK_SET_DIGEST = "3ca43a46ddd67f14380189ca73e2258b2b4f2c9945e53d0816a275eb47e6175e"

raise SystemExit(module.main())
