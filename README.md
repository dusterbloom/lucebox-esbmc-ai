# Lucebox ESBMC-AI companion

This repository supplies the isolated planner, verifier, and advisory AI lanes
used by the `dusterbloom/lucebox-hub` formal-verification pilot.

The integration makes one narrow promise: production code at an exact PR
revision satisfies the bounded contracts approved at the exact target-branch
revision recorded in the plan. It does not claim whole-program correctness.

## Trust lanes

- `plan` reads the registry and templates from an exact base Git commit,
  selects targets from changed paths, and renders deterministic C++ harnesses.
- `verify` authenticates the plan, base policy, templates, contract snapshots,
  generated harnesses, and head checkout before invoking ESBMC without network
  access or credentials. When a target declares a native regression, it
  compiles the immutable base snapshot against the exact head sources and runs
  it inside the same constrained container.
- `propose` and `validate` form the advisory repair lane. The credential-bearing
  proposer never executes candidate code; a second secretless container applies
  and reverifies it against the exact immutable failure bundle.
- `propose-contract` and `validate-contract` perform the equivalent split for a
  critical change that has no approved contract. A validated proposal remains
  advisory and cannot satisfy the required proof result.

Neither image commits, comments, pushes, opens pull requests, or changes a
contract registry.

## Plan and verification

Create a plan from base-approved policy:

```bash
lucebox-formal plan \
  --workspace /workspace \
  --base-policy formal/contracts/registry.toml \
  --base-sha "$BASE_SHA" \
  --head-sha "$HEAD_SHA" \
  --mode pr \
  --out /plan
```

Verify that exact plan:

```bash
lucebox-formal verify \
  --workspace /workspace \
  --plan /plan/plan.json \
  --generated-root /plan \
  --out /results
```

Legacy `verify --manifest ...` remains supported during the dual-run migration.

Plan verification produces JSON, JUnit, Markdown, native ESBMC HTML reports,
and bounded evidence bundles. Its machine conclusions are `verified`,
`counterexample`, `invalid_contract`, `inconclusive`, `coverage_gap`, and
`not_applicable`. Coverage gaps are advisory in schema v1; they are never
reported as verified. A declared base-approved native regression is part of
the deterministic result: compilation failure is inconclusive and a failing
regression is a counterexample.

## Advisory AI configuration

The GitHub integration uses an approval-protected environment named
`formal-ai`. For Z.AI’s OpenAI-compatible API, configure:

```text
Environment secret:
  ZAI_API_KEY=<your key>

Environment variables:
  FORMAL_AI_MODEL=openai:glm-5
  FORMAL_AI_BASE_URL=https://api.z.ai/api/paas/v4/
```

The workflow maps `ZAI_API_KEY` to the OpenAI-compatible client only inside the
credential-bearing proposal step. Z.AI documents the general compatible base
URL and `glm-5` model in its
[GLM-5 guide](https://docs.z.ai/guides/llm/glm-5). A coding-plan subscription
may instead require the dedicated coding endpoint documented by Z.AI; set
`FORMAL_AI_BASE_URL` explicitly rather than changing repository code.

OpenAI can be used by storing `OPENAI_API_KEY`, setting the appropriate base URL,
and selecting an `openai:<model>` value. Fork PRs never reach a credentialed
job automatically.

## Exit codes

| Code | Meaning |
|---:|---|
| 0 | Required contracts verified, no contract applied, or advisory gap/proposal completed |
| 10 | At least one ESBMC counterexample |
| 11 | Verification was inconclusive |
| 12 | Legacy verifier/frontend error |
| 13 | Invalid manifest, plan, contract, or provenance |
| 20 | No advisory repair or contract proposal passed secretless validation |
| 21 | Unsafe or invalid evidence bundle, proposal, or patch |

## Development

Python 3.12 or newer is required.

```bash
python3 -m venv .venv
.venv/bin/pip install -e .
.venv/bin/python -m unittest discover -s tests -v
```

The adapter is AGPL-3.0-or-later. ESBMC and ESBMC-AI retain their own licenses;
their notices are included in published images.
