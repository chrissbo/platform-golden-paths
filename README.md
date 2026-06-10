# platform-golden-paths

Reusable GitHub Actions workflows, Rego policies, and Kyverno policies for an
end-to-end CI/CD pipeline simulation.

This repo is the **golden-paths** in a three-repo simulation:

- [`ledger-service`](https://github.com/chrissbo/ledger-service) — the Go service that consumes these workflows via `uses:`.
- `platform-golden-paths` (this repo) — reusable workflows, policies, the centrally pinned linter config.
- [`platform-deploy`](https://github.com/chrissbo/platform-deploy) — GitOps deploy repo.

## What lives here

```
.github/workflows/
  ci-fast-check.yml        # Pipeline 1
  ci-pr-gate.yml           # Pipeline 2
  ci-post-merge.yml        # Pipeline 3 (build, SBOM, Cosign, SLSA L3)
  ci-release-gate.yml      # Pipeline 4 (OPA verdict, Kyverno, can-i-deploy)
  ci-nightly.yml           # Pipeline 5 (thin)
policies/
  rego/                    # OPA/Conftest policy bundle
  kyverno/                 # Cluster admission policies
config/
  golangci.yml             # Centrally pinned lint config
```

Plan and feasibility analysis live in the parent thought-work repo:
[`research/cicd-toolchain/local-simulation-feasibility.md`](https://github.com/chrissbo/upvest-platform/blob/main/research/cicd-toolchain/local-simulation-feasibility.md).

## Status

Phase 0 — bootstrap. Workflows and policies still to come.
