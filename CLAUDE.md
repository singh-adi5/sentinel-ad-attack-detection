# Project conventions

Guidance for anyone, human or coding agent, changing this repository.

## What this is

An Active Directory attack detection lab on Microsoft Sentinel. Four detections,
each with a KQL query, a Sentinel scheduled analytics rule in YAML, a MITRE ATT&CK
mapping, a simulation guide and tuning notes.

| Detection | Events | ATT&CK |
|---|---|---|
| Kerberoasting | 4769 | T1558.003 |
| DCSync | 4662, 4624 | T1003.006 |
| Password spraying | 4771, 4625 | T1110.003 |
| Golden Ticket | 4768, 4769, 4770 | T1558.001 |

Scope is these four. Do not add detections, cloud infrastructure or Terraform.

## Hard constraints

- **Synthetic lab only.** The domain is `contoso.local`. No real organisation, domain,
  username or internal system appears anywhere.
- **No secrets.** No tenant, subscription or workspace identifiers, no keys, no
  passwords. Use placeholders such as `<WORKSPACE_NAME>` and `<LAB_PASSWORD>`.
- **Real tables and columns only.** Queries run on `SecurityEvent`. A column a query
  reads must be listed in `scripts/securityevent.schema`, and a column is added there
  only after checking the Azure Monitor table reference.
- **`rule.yaml` and `query.kql` stay identical.** Edit `query.kql`, then copy it into
  the `query:` block of `rule.yaml`. CI fails on drift.
- **Do not claim what was not run.** A detection is marked validated only when
  `docs/evidence/` holds a screenshot of it firing in a real workspace.
- **Plain writing.** Short declarative sentences. No filler.

## Checks

```bash
pip install -r requirements-dev.txt
python scripts/validate_rules.py          # rule structure, ATT&CK ids, query parity
python -m unittest discover -s tests      # validator and converter tests
npm ci --ignore-scripts && npm run kql-check   # KQL syntax and column analysis
```

All three must pass before a commit.

## Style

- Commit messages: short, imperative, lower case. One detection per commit.
- KQL: a header comment block with `Name`, `Purpose`, `Data source`, `ATT&CK` and
  `Fires when`. Tunable values go in `let` statements at the top.
- Markdown: relative links only, so they resolve on GitHub and in a clone.
