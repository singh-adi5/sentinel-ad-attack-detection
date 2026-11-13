# Security policy

## What this repository contains

Detection content and documentation for a lab. The `simulations/` directory holds
commands for well-known public tools (Impacket, Rubeus, Kerbrute, Mimikatz). They
generate the telemetry the detections are tested against.

Run them only against a lab you own and built for this purpose. Running them against
any system without written authorisation is illegal in most jurisdictions, including
under the UK Computer Misuse Act 1990.

## What this repository must never contain

- Tenant, subscription or workspace identifiers, workspace keys, passwords, tokens.
- Hashes, tickets or other credential material dumped from a lab, even a throwaway one.
- Screenshots that show any of the above. Redact before committing to `docs/evidence/`.

`.gitignore` blocks the common file types. Check `git diff --staged` before each commit.

## Reporting a problem

If you find a secret committed here, or a detection that is wrong in a way that would
mislead a defender, open a GitHub issue. For a committed secret, do not paste the
value into the issue. Point to the file and line.

## Supply chain

- GitHub Actions are pinned to full commit SHAs.
- The workflow token is read-only (`permissions: contents: read`) and the checkout
  does not persist credentials.
- Python and npm dependencies are pinned to exact versions. npm installs from the
  lockfile with install scripts disabled.
