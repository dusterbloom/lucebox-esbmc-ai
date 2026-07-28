# Lucebox ESBMC-AI companion

This repository supplies the isolated formal-verification and bounded,
approval-only repair lane used by the `dusterbloom/lucebox-hub` pilot.

The integration makes one narrow promise: when a declared verification capsule
passes, the checked production transition code satisfies the properties and
bounds recorded by that capsule. It does not claim whole-program correctness.

## Two trust lanes

- `verifier` contains ESBMC and this deterministic adapter. It has no LLM
  dependencies, receives the Lucebox checkout read-only, and runs without
  network access.
- `repair` additionally contains ESBMC-AI and a compiler. The workflow invokes
  it twice in separate ephemeral containers: `propose` has the model credential
  but never executes candidate code; `validate` has no credential or network
  and is the only process allowed to apply, compile, run, and reverify a patch.
  It emits an accepted patch only after the immutable formal contract and native
  test pass again.

Neither process pushes, comments, commits, or opens pull requests. The repair
lane is advisory; a human must inspect and apply any accepted candidate.

## Exit codes

| Code | Meaning |
|---:|---|
| 0 | Capsules passed, a proposal was produced, or a candidate reverified |
| 10 | At least one ESBMC counterexample |
| 11 | At least one capsule timed out |
| 12 | ESBMC or its frontend failed |
| 13 | Invalid manifest |
| 20 | No repair candidate passed the immutable contract |
| 21 | Unsafe or invalid failure bundle/patch |

## Local verifier use

```bash
lucebox-formal verify \
  --manifest /workspace/formal/manifest.toml \
  --mode all \
  --out /results
```

The Lucebox repository wraps the container invocation in `scripts/formal.sh`.
Image references live in `formal/manifest.toml` and are pinned by digest after
publication.

## Repair input and secrets

`lucebox-formal propose` accepts a verifier-generated
`failure-bundle-*.tar.gz` and writes an untrusted proposal. In a new container,
`lucebox-formal validate` accepts that bundle and patch and writes
`candidate.patch` only on success.

The GitHub workflow is designed for an environment named `formal-ai`; store
`OPENAI_API_KEY` there and require reviewers before the proposer may run. The
model is configurable with `FORMAL_AI_MODEL`.

The workflow never runs on fork content with a secret. It is triggered only for
same-repository counterexamples, does not check out the failed revision, and
validates every archive and patch path before use. The validator runs with
`--network none` after the credential-bearing proposer container has exited.

## Development

Python 3.12 or newer is required.

```bash
python3 -m venv .venv
.venv/bin/pip install -e .
.venv/bin/python -m unittest discover -s tests -v
```

The adapter is licensed under AGPL-3.0-or-later. ESBMC and ESBMC-AI retain
their own licenses; their notices are included in the published images.
