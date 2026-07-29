# Lucebox formal-contract portfolio

Status: design baseline for the `dusterbloom/lucebox-hub` pilot, 2026-07-29.

This document records the intended formal-verification coverage for Lucebox.
It is a portfolio, not a claim that every target below is implemented today.
The protected Luce registry remains the authoritative source for promoted
contracts and their exact bounds.

The companion
[`drift-sentinel design`](drift-sentinel-design.md) defines how this portfolio,
the protected registry, the verifier toolchain, and a fast-moving upstream
Lucebox revision remain synchronized without overstating path-level coverage.

## The promise

For a pull request that changes a reviewed critical core, CI should select the
smallest applicable base-approved contract and require deterministic evidence
about the exact head code. A successful result means every state inside the
declared bound satisfies that contract. It does not mean that all Lucebox
behavior, GPU arithmetic, or external I/O has been formally verified.

Existing build, unit, integration, and GPU tests remain in place. The formal
lane adds evidence about bounded state combinations that ordinary tests may
not enumerate.

AI is downstream from this decision:

1. The deterministic verifier produces `verified`, `counterexample`,
   `inconclusive`, `coverage_gap`, or `not_applicable`.
2. A counterexample or coverage-gap bundle may be sent to a credential-bearing
   AI proposer.
3. A separate networkless and secretless validator applies the proposal and
   reruns the original deterministic evidence.
4. AI output never defines or passes its own merge gate.

Disabling AI therefore does not weaken formal verification. It removes only
automatic diagnosis and candidate repair or contract proposals.

## Selection rules

A required contract should meet all of these conditions:

- failure can silently corrupt output, ownership, persistence, resource
  accounting, or process boundaries;
- the important decision can be represented by a compact deterministic core;
- a bounded proof adds something stronger than a handful of examples;
- the proof can execute against production code rather than a duplicate model;
- a base-native regression can guard the production call site when the formal
  core alone cannot prove integration.

Do not model an entire HTTP server, filesystem, JSON formatter, GGML graph, or
CUDA kernel merely because it is important. Extract and prove the host-side
transition, ownership, indexing, and bounds decisions. Retain native and GPU
tests for numerical parity, serialization, external I/O, and device behavior.

## Current promoted coverage

### `prefix-cache-inline`

Current status: implemented.

Production boundary:
`server/src/server/prefix_cache_state.h::InlinePrefixCacheState`.

The bounded contract checks fresh `prepare`, `confirm`, exact lookup, slot
ranges, entry capacity, committed token length, and structural uniqueness.

### `prefix-cache-abort-hole`

Current status: implemented.

Production boundary:
`server/src/server/prefix_cache_state.h::select_inline_free_slot`.

ESBMC checks every bounded cursor and occupancy pattern. The authoritative
plan also compiles the immutable base regression against the exact head and
runs the production `prepare -> confirm -> prepare -> abort -> prepare`
sequence. This distinction is deliberate: the selector is model-checked; the
call-site integration is regression-tested.

The checked-in mutation changes only the `prepare()` call site while leaving
the selector correct. A healthy pipeline must keep the selector target
verified and report a counterexample from the base-native regression.

## Required targeted PR contracts

These contracts should be required when their registered production or
contract paths change. They should not run on unrelated pull requests.

### 1. `prefix-cache-inline-lifecycle`

This is the sequence-complete expansion of the current inline capsules.

Properties:

- entry count never exceeds capacity;
- every committed entry owns one unique in-range slot and hash;
- `prepare` never selects a slot owned by an entry that is meant to survive;
- a full cache selects a valid prefix-aware eviction victim;
- pending eviction refers to an existing entry and is resolved only by the
  matching confirm, abort, or cancel transition;
- abort removes every entry whose backend slot was cleared;
- cancel preserves an existing restore source and removes only the pending
  reservation;
- stale lookup metadata is removed instead of restoring the wrong position;
- clear resets entries, cursor, and pending state;
- public size mirrors agree with production state after each mutation.

Primary paths:

- `server/src/server/prefix_cache_state.h`
- `server/src/server/prefix_cache.cpp`
- `server/test/test_prefix_cache_state.cpp`

### 2. `prefix-cache-full-lifecycle`

The full-compress cache currently keeps a second reservation and eviction
state machine inside `PrefixCache`; it deserves a verification-friendly
production core analogous to `InlinePrefixCacheState`.

Properties:

- full-cache slots stay in `[full_slot_base, full_slot_base + full_cap)`;
- no full-cache reservation can claim the disk staging slot
  `ModelBackend::kMaxSlots - 1`;
- keys and slot ownership are unique;
- a pending LRU victim remains valid until confirm or abort;
- confirm removes the intended pending victim and any stale entry reusing the
  destination slot before adding the new entry;
- abort removes every key whose backend slot was cleared, including sparse
  round-robin reuse;
- lookup changes LRU order without changing ownership;
- `cur_ids_len` is positive and does not exceed the prompt represented by the
  entry;
- the atomic in-use mirror equals the abstract entry count.

Primary paths:

- `server/src/server/prefix_cache.h`
- `server/src/server/prefix_cache.cpp`

### 3. `request-snapshot-transaction`

Extract the snapshot orchestration in `http_server.cpp` into a small
production decision core. The contract reasons over abstract backend results;
it does not model HTTP or GPU execution.

Properties:

- every successful prepare ends exactly once in confirm, abort, or cancel;
- a snapshot used as the current restore source is never cleared before
  restoration;
- if destination and restore-source slots collide, the new reservation is
  cancelled and the committed source is preserved;
- failed generation, client disconnect, no visible output, absent backend
  snapshot, or an invalid saved position cannot produce a committed cache hit;
- saved positions are positive and no greater than the requested snapshot
  boundary;
- invalid memory hits clear both the backend slot and all ownership metadata;
- the disk staging slot is released on every terminal path exactly once;
- inline and full reservation outcomes remain independent and do not confirm
  the wrong tier.

Primary path:
`server/src/server/http_server.cpp`.

### 4. `spec-commit-exactness`

This is the highest-priority new core. Closely related acceptance, bonus,
generation-budget, rollback, and emission logic is currently repeated across
multiple model-family loops. Extract a shared production
`SpecCommitDecision` and require every loop to call it.

Properties:

- accepted draft tokens are exactly the longest target-matching prefix;
- every emitted token is a target-verified draft token or the single permitted
  target bonus token;
- `1 <= accept_n <= verify_width`;
- `0 < commit_n <= remaining_generation_budget`;
- clamping the budget never leaves an uninitialized or disallowed bonus token;
- fast rollback and restore-plus-replay reach the same abstract committed
  position, token prefix, and next-token seed;
- failed fast rollback restores the pre-verify snapshot before replay;
- cancellation advances committed and generated counters by emitted tokens
  only;
- EOS cannot cause tokens after the first emitted EOS to become committed
  output;
- hint tokens remain speculative and require the same target acceptance as
  every other draft token.

Primary paths:

- `server/src/common/dflash_spec_decode.cpp`
- `server/src/qwen35/qwen35_backend.cpp`
- `server/src/qwen35moe/qwen35moe_backend.cpp`
- `server/src/laguna/laguna_backend.cpp`
- `server/src/gemma4/gemma4_backend.cpp`

### 5. `ddtree-attention-visibility`

Properties:

- every non-root node has an earlier valid parent;
- parent links are acyclic and depth increases by one along an edge;
- the visibility matrix includes the root, self, and ancestors only;
- tree construction never exceeds its node budget or requested maximum depth;
- following the posterior produces one connected root path;
- every accepted child matches the posterior token at its parent;
- causal masks expose no future keys;
- tree masks expose no unrelated branch;
- sliding-window exclusion and padding remain negative infinity;
- padded query rows and non-resident KV slots are never marked visible.

Primary paths:

- `server/src/common/ddtree.cpp`
- `server/src/common/attn_masks.h`

### 6. `kvflash-residency-map`

Model the pager with small chunks and a storage-free backend. GPU byte movement
remains covered by native/GPU parity tests.

Properties:

- resident logical chunks and physical blocks form a partial bijection;
- free and resident block counts sum to the configured pool;
- `slot_for` and `slot_of` agree for every resident logical position;
- sink chunks and the protected tail window are not selected as victims;
- failed allocation restores the previous append-head cursor;
- page-out frees exactly one block and preserves an abstract host-backed copy;
- page-in consumes one free block and restores residency;
- reset removes all mappings, advances the epoch, and restores the full free
  set;
- the epoch changes on every residency change;
- `identity_prefix_covers(n)` is true exactly when the required prefix is
  materialized in identity blocks;
- slot-position and slot-validity masks agree with the residency map.

Primary path:
`server/src/common/kvflash_pager.h`.

### 7. `ipc-payload-sequence-safety`

Properties:

- byte addition and multiplication reject every overflow;
- header plus payload fits the shared mapping;
- a list of payload segments fits iff its checked total fits capacity;
- request dimensions imply exactly the expected byte count;
- parent and daemon agree on hidden size, token count, expert count, and
  payload layout;
- a response sequence must equal the request sequence before its payload can
  be consumed;
- stale, truncated, oversized, or mismatched payloads fail before a read,
  write, reshape, or device copy;
- transport selection cannot claim shared memory without a valid shared map.

Apply the same core to draft IPC, target-shard IPC, PFlash IPC, and MoE expert
compute IPC.

Primary paths:

- `server/src/common/backend_ipc.h`
- `server/src/common/backend_ipc.cpp`
- `server/src/common/dflash_draft_ipc.cpp`
- `server/src/common/target_shard_ipc.cpp`
- `server/src/common/moe_expert_compute_ipc.cpp`

### 8. `gguf-loader-bounds`

Properties:

- a tensor is accepted iff
  `[data_offset + tensor_offset, + tensor_size)` lies entirely in the file;
- no acceptance calculation can wrap `size_t`;
- tensor dimension and byte-count products use checked arithmetic;
- invalid type, dimensions, offsets, or sizes fail before mmap access or
  device copy;
- every GGUF loader call site invokes the shared guard before copying;
- a diagnostic-only calculation cannot introduce an overflow absent from the
  decision path.

Primary path:
`server/src/common/gguf_bounds.h`, plus every model and draft GGUF loader.

### 9. `feature-placement-compatibility`

The existing compatibility gate is already mostly pure. A compact symbolic
projection should enumerate architectures, placement classes, and feature
booleans without asking ESBMC to model error strings.

Properties:

- unknown architectures are rejected;
- requested target backend equals the compiled backend;
- IPC-only auxiliary options require the corresponding IPC binary;
- PFlash requires a configured drafter;
- mixed target/draft backends require remote draft IPC, and unnecessary remote
  draft IPC is rejected;
- layer-split vectors are structurally coherent;
- mixed target splits contain exactly one local-to-remote backend boundary;
- architectures without a layer-split adapter cannot accept a layer split;
- DS4 approximate prefill and fused decode reach only their supported
  monolithic HIP placement;
- no configuration rejected by the pure compatibility core reaches backend
  construction through a production call-site bypass.

Primary paths:

- `server/src/common/feature_gate.cpp`
- `server/src/common/model_capabilities.h`
- `server/src/placement/placement_config.h`

### 10. `context-admission-arithmetic`

Properties:

- token and context inputs are validated as non-negative;
- additions are performed in a representation that cannot signed-overflow;
- a verbatim request is accepted iff prompt plus requested output fits;
- compression may defer the initial gate but cannot bypass the post-compress
  gate;
- a full-cache hit uses the served compressed size, including the valid
  zero-length-hit sentinel;
- the no-hit sentinel selects the effective prompt size;
- exactly-at-limit is accepted and one-over-limit is rejected.

Primary path:
`server/src/server/admission.h`.

## Required nightly and targeted-on-change contracts

These contracts should run when touched and in the wider nightly portfolio.
Their larger state spaces or integration dependencies make them poor
unconditional PR checks.

### 11. `disk-cache-persistence-integrity`

Properties:

- wrong magic, version, model/layout identity, token hash, dimensions, or
  truncated payload is rejected before `snapshot_adopt`;
- an invalid entry cannot be reported as a hit;
- a failed read removes or quarantines the bad index entry without affecting
  unrelated entries;
- header and tensor-table lengths fit the file using checked arithmetic;
- a live-model layout mismatch clears the unverified disk-derived index before
  switching layouts;
- indexed file sizes sum to `total_bytes`;
- budget enforcement terminates within budget and obeys explicit protection
  rules;
- continued-checkpoint boundaries are monotonic, in range, and do not save the
  same interval repeatedly.

Primary paths:

- `server/src/server/disk_prefix_cache.h`
- `server/src/server/disk_prefix_cache.cpp`

### 12. `streaming-tool-protocol-state`

Extract an enum-and-counter transition core from the SSE emitter. Keep JSON
rendering and complete parser strings in native tests.

Properties:

- start and terminal events occur at most once and in order;
- termination and disconnect are absorbing;
- content-block starts and stops are balanced for every API format;
- block indices advance monotonically;
- reasoning, content, and tool-buffer accounting agrees with mode transitions;
- a valid emitted tool call produces the matching terminal reason;
- malformed or undeclared tool syntax cannot become an executable call;
- buffered tool syntax is either parsed as a permitted call, safely returned
  as content under the explicit fallback rule, or suppressed;
- stop-sequence holdback emits neither the stop sequence nor duplicated text;
- arbitrary token chunking does not change the final abstract event sequence.

Primary paths:

- `server/src/server/sse_emitter.cpp`
- `server/src/server/tool_parser.cpp`
- `server/src/server/tool_hint.cpp`

The `HintStateMachine` sub-contract should also require monotonic segment
progress, no hints during a gap, exact slices during forced segments, and an
absorbing `DONE` state.

### 13. `moe-placement-swap-integrity`

Properties:

- hot expert IDs are unique and within layer/expert bounds;
- per-layer hot counts equal their concrete ID lists;
- total hot count equals the sum of per-layer counts;
- expert and byte budgets cannot overflow and are never exceeded;
- required per-layer floors are either satisfied or rejected explicitly;
- every swap promotes a currently cold expert and evicts a currently hot one;
- promoted traffic exceeds evicted traffic by the configured minimum gain;
- action count never exceeds policy;
- applying a swap changes only the named layer and preserves all placement
  invariants.

Primary paths:

- `server/src/common/moe_hybrid_placement.cpp`
- `server/src/common/moe_hybrid_swap_manager.cpp`

## Implementation pattern for every capsule

Each promoted target should contain all of the following:

1. **Production decision core.** A dependency-light function or state class
   used by real Lucebox code.
2. **Protected contract template.** Stored in the base-approved registry with
   reviewed symbols, bounds, defines, and ESBMC arguments.
3. **Bounded ESBMC harness.** Exercises all symbolic states in the declared
   envelope and calls production code directly.
4. **Immutable base-native regression.** Compiled against the exact head when
   call-site or multi-component integration is part of the promise.
5. **Checked-in mutation.** Reproduces the historical or representative defect
   and is required to produce a counterexample for the intended reason.
6. **Explicit properties document.** Separates model-checked properties,
   regression-tested integration, assumptions, bounds, and exclusions.
7. **Path-based selection.** Required only when production, contract, or
   integration paths registered for the target change.
8. **Fail-closed evidence.** Timeout, compiler failure, plan tampering,
   unavailable native execution, or unsupported frontend behavior is
   `inconclusive` or `invalid_contract`, never `verified`.

## Rollout order

The recommended order after the two current prefix-cache targets is:

1. `spec-commit-exactness`
2. `kvflash-residency-map`
3. `prefix-cache-full-lifecycle`
4. `request-snapshot-transaction`
5. `ipc-payload-sequence-safety`
6. `gguf-loader-bounds`
7. `feature-placement-compatibility`
8. `context-admission-arithmetic`
9. `ddtree-attention-visibility`
10. the disk, streaming/tool, and MoE nightly targets

The first three additions maximize value: they cover emitted-token
correctness, logical-to-physical KV ownership, and the second snapshot
reservation state machine.

## CI operating envelope

Pull-request mode:

- select only targets affected by changed registered paths;
- use the smallest reviewed state and sequence bounds;
- keep a per-target hard timeout, initially 120 seconds;
- run independent selected targets in parallel;
- aim for a normal selected formal lane below five minutes;
- retain exact evidence and replay bundles for failures.

Nightly mode:

- run every promoted target;
- widen capacities, sequence lengths, feature combinations, and tree/pager
  state spaces;
- run every checked-in mutation sensitivity test;
- compare the generated-plan lane with the legacy shadow until migration is
  complete;
- retain evidence longer than PR artifacts.

## Non-goals

This portfolio does not promise:

- whole-program verification of Lucebox;
- numerical correctness of CUDA, HIP, or GGML kernels;
- model quality or semantic correctness of generated language;
- tokenizer, SHA-1 collision-resistance, filesystem, network, or operating
  system correctness;
- correctness outside each contract's declared bounds;
- that an AI-proposed repair is acceptable merely because it compiles.

Those exclusions should appear in leadership and contributor documentation so
that a green formal result remains precise and credible.
