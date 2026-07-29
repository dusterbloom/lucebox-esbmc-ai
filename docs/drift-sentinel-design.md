# Lucebox drift-sentinel design

Status: proposed implementation design for the `dusterbloom/lucebox-hub`
pilot, 2026-07-29.

Implementation status: the minimum PR-level slice is implemented on the
companion `agent/per-pr-contract-plans` branch. It includes the shared bounded
classifier, normalized Git change inventory, include adjacency, submodule
coordinates, policy-shrink detection, planner embedding, verifier
recomputation, structural blocking, and adversarial tests. Build/link
adjacency, a standalone nightly audit, workflow-wide image-lock comparison,
and synthetic upstream-merge automation remain follow-up work. CI adoption
requires publishing the companion `0.3.0` images and accepting their immutable
digests in Lucebox policy.

This document defines how the formal-verification integration should remain
honest and useful while Lucebox and its upstream dependencies change quickly.
It incorporates an adversarial review performed with
`zai-coding-plan/glm-5.2` through OpenCode and a subsequent code-level
reconciliation of that review.

## Decision

The drift sentinel is not another proof engine. It is a deterministic
classifier that answers:

1. What exact revisions and protected artifacts are being evaluated?
2. Which registered boundaries, triggers, dependencies, policies, and
   toolchain inputs changed?
3. Which approved contracts were invoked because of those changes?
4. Which changes have no applicable approved contract?
5. Did the protected coverage definition or verifier identity shrink or drift?

Only the verifier may return `verified`. A path is never described as
"verified" or "covered" merely because it selected a contract. Selection means
only that the contract was invoked against the exact head revision.

The PR planner should use one shared drift-classification library and embed the
result in its authenticated plan. A later standalone audit command may expose
the same engine for nightly and upstream-sync runs. It must not implement a
second diff or matching algorithm.

## Authority model

The synchronization coordinate has three authorities:

| Input | Authority | Required identity |
|---|---|---|
| Production code | exact PR, merge-queue, push, or synthetic integration head | repository and `head_sha` |
| Contract policy | protected Lucebox target or pilot base | `base_sha`, registry hash, template hashes, immutable contract snapshots |
| Planner and verifier | companion release accepted by Lucebox policy | image digests, registry schema, ESBMC version and checksum |

Contracts, templates, property documents, native regressions, mutations, and
their registry remain in Lucebox beside production code. The companion
repository owns the policy parser, planner, verifier, drift classifier, and
advisory AI machinery. It must not own a parallel model of Lucebox production
behavior.

## What exists today

The current implementation already:

- reads policy, templates, and immutable contract content from the exact
  protected `base_sha`;
- checks out and authenticates the exact `head_sha`;
- records hashes for generated harnesses and selected contract snapshots;
- runs old base-approved targets when a PR changes the registry, because the
  registry path is a trigger for every promoted target;
- supports GitHub merge-queue heads;
- compares workflow image digests with the protected registry;
- treats counterexamples, inconclusive execution, tool errors, invalid plans,
  and invalid contracts as deterministic failures;
- reports unmatched registered critical paths as `coverage_gap`;
- keeps coverage gaps advisory in schema v1;
- runs required contracts on push to `main` and in the nightly lane.

The important gaps are:

- the production registry's critical areas are exact-file lists, so a new
  sibling with an unrelated name can be classified `not_applicable`;
- changed paths are name-only, so rename, copy, deletion, and submodule
  diagnostics are imprecise;
- the plan records no base/head submodule pointer inventory;
- registry, legacy manifest, and all workflow image-digest copies are not
  checked together;
- there is no root CODEOWNERS policy protecting formal policy and workflow
  changes;
- there is no automated comparison between the pilot and current upstream
  Lucebox;
- the portfolio is intentionally a roadmap and can become stale if it is
  treated as implementation status rather than a view of the registry.

## Honest signal model

A changed path can have several independent relationships:

| Relation | Meaning | Nature |
|---|---|---|
| `declared_boundary` | The protected registry explicitly names the path as part of a critical area or target. | Deterministic enforcement of a human decision |
| `target_trigger` | The path matched a target trigger and caused that target to be selected. | Deterministic process fact |
| `include_adjacent` | The path is reachable through a resolved project-local include edge from a declared boundary. | Deterministic structural evidence, primarily for headers |
| `build_adjacent` | The path belongs to a translation or link unit associated with a declared boundary. | Deterministic only when a trustworthy build graph exists |
| `watch_match` | The path matches an approved risk-routing pattern. | Heuristic routing signal |
| `unmodeled` | No registered or structural relation was found. | Explicit unknown |
| `verified(target)` | ESBMC and any declared immutable native regression passed the target's declared bound. | Formal result about that target, not a path or diff line |

This terminology prevents two overclaims:

- invoking a contract does not prove every change in the file that triggered
  it;
- an include graph is not semantic discovery and does not cover separately
  compiled C++ translation units.

## Change inventory

The shared classifier should replace the name-only diff with a bounded,
NUL-delimited change inventory equivalent to:

```text
git diff --name-status -z --find-renames --find-copies BASE...HEAD
```

It should normalize:

- added, modified, and deleted paths;
- old and new sides of renames and copies;
- Git mode changes, including mode `160000` submodule pointers;
- policy, template, property, mutation, native-regression, workflow, and
  toolchain-lock changes.

Target selection should receive both sides of a rename. Existing triple-dot
semantics remain appropriate for ordinary pull requests: policy is taken from
the target tip while the diff describes the proposal since its merge base.
The plan must also record the computed `merge_base_sha` and revision topology.
For a merge-queue event, failure to establish the expected relationship
between the protected base and synthetic head must fail closed.

## Registry evolution

The minimum compatible extension keeps existing `critical_paths.paths` as
explicit, human-approved boundaries and adds optional routing metadata:

```toml
[[critical_paths]]
id = "prefix-cache"
description = "Inline and full prefix-cache lifecycle"
paths = [
  "server/src/server/prefix_cache_state.h",
  "server/src/server/prefix_cache.h",
  "server/src/server/prefix_cache.cpp",
]
watch_paths = [
  "server/src/server/prefix_cache*",
  "server/src/server/*eviction*",
]
include_roots = ["server/src"]
policy = "advisory"
```

The distinctions are important:

- `paths` are asserted boundaries;
- `watch_paths` are intentionally noisy routing hints and never proofs;
- `include_roots` bound deterministic project-local include traversal;
- `policy` controls whether an unmatched structural finding is advisory or
  blocking after a proving period.

Patterns need explicit repository-relative semantics. The implementation
should not expose Python `fnmatch` behavior as an accidental public contract.
A schema revision should define exact and glob patterns separately or adopt
one documented Git-style path matcher.

Build adjacency is a later extension. `compile_commands.json` identifies
translation commands but not necessarily final link membership, so reliable
`.cpp` adjacency also needs a CMake file-api codemodel, Ninja graph, or another
authenticated link-unit inventory. If a critical area declares build
adjacency as required, absence of that graph must be an explicit failure,
never silent fallback to header-only analysis.

## Plan schema

The authenticated `plan.json` should gain a bounded `drift` object:

```json
{
  "schema_version": 1,
  "coordinate": {
    "repository": "owner/repository",
    "event": "pull_request",
    "base_sha": "40 hex",
    "head_sha": "40 hex",
    "merge_base_sha": "40 hex",
    "base_policy_sha256": "64 hex",
    "registry_schema_version": 1,
    "verifier_image": "repository@sha256:digest",
    "repair_image": "repository@sha256:digest",
    "esbmc_version": "8.4",
    "esbmc_linux_sha256": "64 hex",
    "submodules": [
      {
        "path": "server/deps/Block-Sparse-Attention",
        "base_sha": "40 hex",
        "head_sha": "40 hex"
      }
    ]
  },
  "changes": [
    {
      "status": "added|modified|deleted|renamed|copied|submodule",
      "old_path": null,
      "new_path": "server/src/server/example.h",
      "relations": ["include_adjacent", "watch_match"],
      "areas": ["prefix-cache"],
      "selected_targets": []
    }
  ],
  "findings": [
    {
      "id": "stable-machine-id",
      "kind": "no_contract_invoked",
      "severity": "info|warning|blocking",
      "paths": ["server/src/server/example.h"],
      "areas": ["prefix-cache"],
      "reason": "bounded diagnostic"
    }
  ],
  "policy_delta": {
    "removed_areas": [],
    "removed_boundaries": [],
    "weakened_targets": []
  }
}
```

All arrays, strings, file sizes, graph depth, and graph node counts need the
same style of hard bounds as the current plan and evidence bundles. The
verifier must authenticate this object and reproduce security-relevant
classification inputs rather than trusting arbitrary generated JSON.

## Classification

For each normalized change:

1. Record whether the old or new path is an exact protected boundary.
2. Match both sides against base-approved target triggers.
3. Select targets using only base-approved policy.
4. Traverse bounded, project-local include relationships in both base and head
   trees.
5. Consult an authenticated build graph when one is available and declared.
6. Apply base-approved watch patterns as advisory routing.
7. Record submodule pointer changes independently.
8. Emit `unmodeled` rather than treating absence of a signal as safety.

Useful finding kinds include:

- `boundary_deleted`;
- `boundary_renamed`;
- `policy_shrunk`;
- `target_weakened`;
- `toolchain_mismatch`;
- `dependency_changed`;
- `no_contract_invoked`;
- `build_graph_missing`;
- `unmodeled_change`.

The deterministic planner still emits its existing target items,
`coverage_gap`, and `not_applicable` results. Drift findings add explanation
and structural integrity; they do not replace contract results.

## Enforcement

The initial pilot policy should be:

| Finding | PR and merge queue | Push and nightly |
|---|---:|---:|
| Counterexample, inconclusive result, tool error, invalid contract | blocking | blocking |
| Invalid or unauthenticated drift data | blocking | blocking |
| Required target source or immutable contract missing | blocking | blocking |
| Protected policy removes an area, required target, or required boundary | blocking pending an explicit maintainer transition | blocking |
| Registry, legacy manifest, and workflow image identities disagree | blocking | blocking |
| Coverage gap or structurally adjacent change with no selected contract | advisory in schema v1 | visible nightly debt |
| Watch-pattern or AI-triage finding | advisory | advisory |
| Submodule change outside a declared required dependency | advisory | advisory |

A legitimate breaking refactor of a required boundary should be staged:

1. introduce its successor and proposed contract while the old boundary still
   exists;
2. review and promote the successor through protected base policy;
3. move production behavior under the now-approved contract;
4. retire the old boundary after mutation sensitivity and a proving period.

This avoids allowing a PR to redefine the policy that judges itself. Until a
full lifecycle exists, an exceptional shrink should require an explicit
maintainer override and remain visible in artifacts.

Coverage gaps should become blocking per critical area, not globally, only
after that area's triggers have shown acceptable precision and latency.
Waivers must identify an area and path, name an owner and reason, and have a
short expiry. An expired waiver is a structural failure.

## Pull request and merge queue

For a pull request:

1. use the protected target tip as policy base;
2. inventory `BASE...HEAD`;
3. embed drift classification in the generated plan;
4. verify selected targets against the exact head;
5. publish the coordinate, findings, contract results, and evidence;
6. send only authenticated gaps or counterexamples to the advisory AI lane.

The merge queue must rerun the same process against its synthetic integration
head. Repository settings must require the exact formal check for merge-group
heads; workflow support alone cannot prove that branch protection enforces it.

## Nightly audit

Nightly should run every promoted target and additionally:

- validate every boundary, source, template, contract snapshot, native
  regression, mutation, and declared production symbol;
- compare registry, legacy manifest, formal workflows, and companion image
  identities;
- inventory submodule pointers;
- run every mutation-sensitivity test;
- detect expired waivers and protected-policy shrinkage;
- render implemented status directly from the registry rather than treating
  the portfolio roadmap as current state;
- retain the drift coordinate and report longer than PR artifacts.

## Upstream synchronization

Upstream does not yet contain the pilot's `formal/` directory, so checking
upstream by itself is meaningless. The candidate must be the result of merging
current upstream Lucebox into the pilot, judged by pilot-owned protected
policy.

A scheduled, initially report-only workflow should:

1. resolve and record exact pilot and upstream SHAs;
2. fetch `Luce-Org/lucebox-hub` without credentials;
3. construct an ephemeral merge of upstream into the pilot without pushing or
   changing a protected ref;
4. stop and report a structured conflict if no merge candidate exists;
5. materialize the synthetic merge as an ephemeral commit so the existing
   planner can authenticate it as `head_sha`;
6. set `base_sha` to the pilot commit that owns the registry;
7. run drift inventory for `PILOT...SYNTHETIC_HEAD`;
8. run every promoted target in `all` mode, not only path-selected targets;
9. record upstream, pilot, synthetic-head, merge-base, toolchain, and
   submodule identities;
10. publish a durable report and update the last-audited upstream SHA.

No synthetic commit is pushed. A later phase may have a bot open or update a
normal upstream-sync PR after a clean audit, but it must not auto-merge during
the proving period.

## AI's role

AI may:

- group and explain advisory drift findings;
- identify likely ownership and affected invariants;
- propose watch-pattern, registry, contract, or native-regression changes;
- draft a contract candidate from an authenticated coverage-gap bundle.

AI may not:

- classify its own guess as formal coverage;
- change finding severity;
- waive a structural failure;
- promote a target or contract;
- make its proposal satisfy the deterministic merge gate.

Every AI proposal follows the existing separate, credential-bearing proposer
and networkless validator architecture.

## Minimum implementation increment

Companion repository:

1. add a bounded `lucebox_formal/drift.py` containing normalized Git changes,
   matching, include adjacency, classification, and policy-delta logic;
2. make `plan.py` call that library and embed its result in `plan.json`;
3. make `verifier.py` authenticate the new structure and expose findings in
   JSON, JUnit, and Markdown;
4. record merge-base and submodule coordinates;
5. add focused unit tests before changing enforcement.

Lucebox repository:

1. add actual maintainer ownership for formal policy and workflows through
   `.github/CODEOWNERS`;
2. extend the registry with bounded watch and include-routing metadata;
3. add a nightly registry/toolchain consistency audit;
4. leave new adjacency and watch findings advisory until observed;
5. add the report-only upstream synthetic-merge workflow after the PR
   classifier is stable.

Do not start with a service, database, semantic-index store, automatic contract
promotion, full build graph, or companion update bot. They are unnecessary for
the two-contract pilot.

## Adversarial tests

The first implementation should cover at least:

1. modification of an exact trigger selects the expected targets;
2. a new header included by a protected boundary is reported as adjacent and
   unmatched, not silently `not_applicable`;
3. an unrelated new server file remains unmodeled or ordinary rather than
   falsely "covered";
4. deletion of a required target source fails structurally;
5. rename of a required boundary reports both paths and fails with a precise
   reason;
6. same-PR registry expansion still runs old base-approved targets;
7. same-PR registry shrink runs old targets and separately reports a blocking
   policy shrink;
8. generated harness tampering remains `invalid_contract`;
9. registry/manifest/workflow image mismatch fails;
10. a submodule pointer bump records exact base and head pointers;
11. missing required build-graph input fails rather than silently degrading;
12. an upstream synthetic merge is verified with pilot policy and leaves no
    pushed commit.

The critical negative test is a new file that neither matches a target trigger
nor a protected exact path. The sentinel must report the strongest relation it
can establish, and must say `unmodeled` when none exists. It must never turn
absence of evidence into a green proof claim.

## Adversarial-review disposition

Accepted findings:

- exact-file critical areas miss arbitrary new siblings;
- there is no root formal CODEOWNERS policy;
- submodule identities are absent from plan provenance;
- image identities are duplicated more broadly than current consistency
  checks cover;
- name-only changes make rename and deletion diagnostics weak;
- no upstream-sync audit exists.

Corrected or rejected findings:

- push-to-main deterministic failures are already enforced by the workflow;
- a production registry edit already selects and runs old base targets;
- filename globs cannot discover arbitrary semantic movement;
- include closure does not cover separately compiled `.cpp` files;
- a triggered contract does not mean a changed path is formally covered.

These corrections are part of the design record so later implementation does
not inherit attractive but false claims from the review.
