# Contributing to MikroTik Exporter

Thanks for your interest. This project ships a network-facing Prometheus exporter; correctness and
metric compatibility matter more than speed. Please read this document before opening a PR.

## Ground Rules

These apply to human contributors and AI agents alike:

- One concern per commit and per PR. If you cannot describe the change in one imperative sentence,
  split it.
- Metric names, units, types, labels, configuration semantics, and public Rust APIs are contracts.
  Compatibility changes (including added labels) need a breaking changelog entry, migration guidance,
  and maintainer sign-off.
- Never `unwrap()`/`expect()` on network I/O or parsed router output. Use `AppError`/`Result<T>`.
- Never log or commit credentials. Passwords are `secrecy::SecretString` and stay opaque.
- Production collection uses the internal `MikroTikClient::with_pool`; transport tests may exercise
  connections directly. Do not expose internal APIs solely to make integration tests compile.
- Treat router output as untrusted: bound framing, preserve typed errors, validate numeric fields
  and snapshots before metric updates, and discard connections after cancelled/failed commands.
- Keep secrets opaque, verify TLS identities, and never add an insecure certificate bypass.
- New configuration variables require updates to `.env.example`, `README.md`, and `CHANGELOG.md`
  in the same PR.

## Development Setup

1. Install the pinned toolchain (rustup will pick it up automatically):

   ```bash
   rustup show          # confirms the 1.98.0 toolchain from rust-toolchain.toml
   ```

2. Build and test:

   ```bash
   cargo build --locked
   cargo test --all-features --locked
   ```

3. Optional: enable the commit template:

   ```bash
   git config commit.template .gitmessage
   ```

## Before You Open a PR

Branches are typed and lowercase — `fix/`, `feat/`, `refactor/`, `chore/`, `docs/` — and branch from
an up-to-date `main`. `main` is protected; direct pushes are rejected.

Rust 1.98.0 is both the compiler pin and MSRV (edition 2024). Keep `rust-toolchain.toml`,
`Cargo.toml` `rust-version`, `clippy.toml`, the Docker builder, and CI's SHA-pinned toolchain
action synchronized. The action revision selects the toolchain; it does not automatically read
the local pin.

Run the full local Rust gate:

```bash
cargo check --all-targets --all-features --locked
cargo fmt --all -- --check
cargo clippy --all-targets --all-features --locked -- -D warnings
cargo test --all-features --locked
cargo deny --locked check
cargo audit           # security advisories
```

Update `CHANGELOG.md` under `[Unreleased]` for any user-visible change. New public behavior needs a
test in the same PR; a bug fix needs a regression test that fails before the fix.

For workflow/build-script changes also run `actionlint` and `shellcheck build-docker.sh`; validate
container changes with a local build. CI additionally runs coverage and native amd64/arm64 Docker
validation. Report unrun checks explicitly. When changing `Cargo.toml`, use Cargo to update
`Cargo.lock` (`cargo check`); never edit the lockfile by hand. Do not weaken license, advisory, or
duplicate-dependency checks to make an update pass; document any narrowly approved exceptions.

## Testing

Unit tests belong beside private implementation; integration tests use the public library surface.
Protocol/property, TLS, pool-cancellation, and orchestration tests use deterministic fixtures or
loopback servers. Prefer Tokio's paused time over wall-clock sleeps. Document public APIs and
keep network examples `no_run`; run `cargo test --doc --all-features --locked` after doc changes.

Normal `cargo test` does not contact real routers even when `.env` or router environment variables
exist. The real-device test is explicitly ignored. Only with permission and configured test devices:

```bash
cargo test --all-features --locked --test integration_tests test_real_router_connectivity -- --ignored --exact
```

That test reads `.env` plus environment overrides and fails when no routers are configured. Do not
enable ignored tests in ordinary CI.

## Implementation Conventions

- Use `AppError` and `Result<T>`, `?`, and explicit recovery paths for I/O; assertions on controlled
  fixtures are acceptable in tests.
- Follow rustfmt and existing module conventions; preserve MIT SPDX/copyright headers.
- Comments and rustdoc should explain contracts and non-obvious protocol, cancellation, and unsafe
  safety invariants. Avoid comments that merely restate code.
- Keep per-router collection independent and non-overlapping. Retain and supervise the
  `JoinHandle<Result<()>>` from `start_collection_loop`; signal, cancel as needed, and join on shutdown.
- Keep process probes independent of router availability. `/health` reports cached diagnostics.
- Use Prometheus base units (seconds, bytes, ratios) and stable identity labels. Apply counters as
  deltas and gauges directly; preserve freshness/completeness when processing partial results.
- Register metrics in `src/metrics/registry/init.rs`, define labels in `src/metrics/labels.rs`, and
  update cleanup with collection logic. Initialize zero-valued per-router service families via
  `initialize_router_metrics`; empty families are otherwise omitted by `prometheus-client`.
- Add tests for encoded names, units, labels, initialization, stale cleanup, and bounded cardinality
  when changing metric behavior. Avoid cardinality growth through metadata or partial snapshots.

## Commit Messages

[Conventional Commits](https://www.conventionalcommits.org/), lowercase, no scopes, imperative mood,
subject ≤ 72 characters:

```
fix: validate snapshot bounds
feat: expose WireGuard peer counters
chore: bump dependencies
```

One logical change per commit. Breaking changes use `!` and a `BREAKING CHANGE:` footer, plus a
changelog entry and maintainer sign-off.

## Pull Requests

1. Open the PR as a **draft** until CI is green, then mark it ready.
2. Fill in `.github/pull_request_template.md` completely.
3. Rebase local unpublished work before review if needed. Once shared/reviewed, use follow-up commits
   and coordinate base updates with the maintainer; do not rewrite reviewed history or force-push a
   shared branch. Do not bypass linear-history protection.
4. Wait for all required checks: `Check`, `Test Suite`, `Rustfmt`, `Clippy`, `Cargo Deny`,
   `Security Audit`. Never merge with red or pending checks.
5. PRs are **squash-merged**, one commit per PR; the squash subject must be a valid Conventional
    Commit. Delete the branch after merge.

Pull requests, scheduled runs, manual runs, and pushes to `main` run the quality suite with
path-aware job selection. A `changes` job classifies the diff: when no Rust-related path changed,
the heavy Rust steps are skipped while the required jobs still report success, and workflow and
Docker validation run only for the files they cover. Schedules and manual runs always execute the
full suite. Feature-branch pushes are intentionally covered by the pull-request run instead of
repeating the same suite before a PR exists. `Check` is an always-run aggregate gate: it fails when
any job fails or is cancelled, and it requires the Rust jobs to have run and succeeded whenever a
Rust-related path changed. Preserve required check names; changing them requires coordinating the
repository ruleset. Actions are pinned to full commit SHAs.
Main image publication follows the successful aggregate gate.

Automated agents need explicit user approval before commits, pushes, PR creation, merges, tags,
or publication. Approval to edit files is not approval to publish or rewrite history. Maintainer
approval for a breaking change does not waive verification or release approvals.

## Review Checklist

- [ ] Single purpose; diff is minimal and reversible.
- [ ] Local gate passed (`fmt`, `clippy -D warnings`, `test`).
- [ ] Cargo check, dependency policy, and security audit passed; additional checks reported.
- [ ] `Cargo.toml` and `Cargo.lock` updated together if dependencies changed.
- [ ] No `unwrap()`/`expect()` on network I/O or parsed router output.
- [ ] No new secrets and no `SecretString` logging.
- [ ] Metric names/units/types/labels treated as a public contract; breaking changes flagged.
- [ ] `CHANGELOG.md` updated; docs updated (`README.md`, `EXAMPLES.md`, `DEPLOYMENT.md`).
- [ ] Tests added for new behavior.
- [ ] No unrelated reformatting or renames.

## Releases

The project is pre-1.0 (`0.Y.Z`): bug fixes bump the patch digit; new metrics, features, or config
variables bump the minor digit (the minor is the user-facing "major" while in 0.x); breaking changes
(metric/label renames, config default changes) also bump the minor digit and require a
`BREAKING CHANGE:` footer plus maintainer sign-off.

A dependency minor update is normally `chore:`, not automatically `feat:` or a project minor bump.
Choose the project version from user-visible impact and compatibility. Adding metric labels or
changing units/types is breaking. `1.0.0` requires explicit maintainer approval. Release only when
`[Unreleased]` contains meaningful user-facing changes; avoid empty/docs-only releases.

Releases are tag-driven and automated: a release PR (`release/vX.Y.Z`) updates `Cargo.toml`,
`Cargo.lock`, and `CHANGELOG.md` as `chore: release vX.Y.Z`; after it squash-merges, a signed
`vX.Y.Z` tag is pushed on the merge commit, which builds cross-platform binaries, GitHub Release
assets, and multi-arch GHCR images. The release commit touches only those three files; run Cargo
to synchronize the lockfile and complete the local gate before the release PR.

Before tagging, require green checks on the exact squash-merge commit on `main`, then obtain
explicit approval to create and push the signed tag. Never tag the branch head or delete/move an
already-published tag. A bad release is corrected by a new version.

The workflow resolves an existing exact annotated, signed `vX.Y.Z` tag, checks Cargo version and
`main` ancestry, requires a successful main push CI run and the required check names on that SHA.
Manual dispatch must run from `main` with that existing tag. Native
Linux/macOS amd64+arm64 and Windows amd64 jobs build locked binaries; checksums and provenance
attestations accompany release assets. Images are promoted from the same verified SHA after the
binary release succeeds; Docker is not rebuilt during release. Do not disable provenance permissions
or bypass these gates.

Crates.io publication is a separate final step (`cargo publish`) requiring explicit approval;
the tag workflow does not publish the crate automatically.

## Reporting Issues

- Bugs and feature requests: use the GitHub issue templates.
- Security vulnerabilities: follow [`SECURITY.md`](SECURITY.md); do not open a public issue.
