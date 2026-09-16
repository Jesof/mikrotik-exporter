# Security Policy

## Supported Versions

Only the latest released minor line receives security fixes.

| Version | Supported          |
|---------|--------------------|
| 0.5.x   | :white_check_mark: |
| < 0.5   | :x:                |

## Reporting a Vulnerability

Do **not** open a public issue for security problems. Instead, report privately via
[GitHub Security Advisories](https://github.com/Jesof/mikrotik-exporter/security/advisories/new)
("Report a vulnerability").

Please include:

- A description of the issue and its impact.
- Steps to reproduce, including a minimal configuration with credentials and private topology removed.
- Affected version(s) and platform(s).
- Any suggested remediation.

You can expect an acknowledgement within 72 hours. We will coordinate a fix and a release, and
credit you in the advisory unless you prefer to remain anonymous.

## Scope

This project is a Prometheus exporter that connects to MikroTik RouterOS devices and handles
router credentials. Areas of particular interest:

- Credential handling (`secrecy::SecretString` must never be logged or exposed).
- The RouterOS wire protocol encoding/decoding.
- Authentication and login challenge-response.
- TLS trust/identity verification and cancellation-safe pooled connections.
- The HTTP `/metrics`, `/health`, `/live`, and `/ready` endpoints.
- Supply chain (dependencies pinned in `Cargo.lock`, checked by `cargo deny`/`cargo audit`).

## Hardening Notes for Operators

- Use a dedicated RouterOS group starting with `read,api`, not the default administrator account.
  Restrict user/service and firewall access to the exporter's source address (for example `/32`).
- Enable verified router TLS explicitly with `tls: {}` or a `tls` object specifying `server_name`
  and/or a PEM `ca_file`. A custom CA file replaces system trust roots. Port 8729 alone does not
  enable TLS: omitted/null `tls` selects plaintext. Legacy `ROUTEROS_TLS` takes a JSON object;
  leaving it unset selects plaintext. See [README.md](README.md#router-json-and-tls).
- Configure an API-SSL server certificate with a matching identity and trusted chain. There is no
  insecure verification bypass or support for certificate-less anonymous TLS. Treat a trust/name
  error as a configuration/security problem, not a reason to disable certificate validation.
- Plaintext RouterOS API exposes credentials and data to network observers. Use TLS or an
  independently encrypted, isolated management path; disable unused plaintext services.
- Restrict the exporter HTTP listener to trusted scrapers. All endpoints are unauthenticated and
  metrics/diagnostics may reveal topology, addresses, comments, and device identities. Terminate
  authenticated TLS at a reverse proxy when needed; the exporter does not serve HTTP TLS itself.
- Store credentials outside Git in a secret manager or protected files. Kubernetes Secret base64
  encoding is not encryption, and runtime administrators can inspect container environments.
- Run non-root, drop capabilities, mount trust files read-only, and restrict ingress/egress.
- Keep the exporter and its container image up to date.
- Verify release checksums and provenance; pin tested container digests. Release automation gates
  binaries and images on the verified tag SHA and successful quality checks.
- Ordinary tests use fixtures/loopback servers. Run ignored real-device tests only with explicit
  authorization for the target devices, as documented in [CONTRIBUTING.md](CONTRIBUTING.md#testing).
