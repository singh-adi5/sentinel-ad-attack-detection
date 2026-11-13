# Progress

Build log for the repository. Honest about what is automated-checked versus what
still needs a live Azure run.

## Done and verified by automation

- [x] Repo skeleton: README, CLAUDE.md, LICENSE (MIT), SECURITY.md, .gitignore, PROGRESS.md
- [x] docs/ARCHITECTURE.md with data-flow diagram and the seven-event-ID rationale
- [x] docs/SETUP.md: Azure, DC, attacker host, workspace, AMA, DCR, step by step
- [x] Detection 1 Kerberoasting: query.kql, rule.yaml, README, simulation
- [x] Detection 2 DCSync: query.kql, rule.yaml, README, simulation
- [x] Detection 3 Password spraying: query.kql, rule.yaml, README, simulation
- [x] Detection 4 Golden Ticket: query.kql, rule.yaml, README, simulation
- [x] deployment/: yaml_to_arm.py converter + dcr-securityevent.json + deploy-rules.md
- [x] scripts/: validate_rules.py, kql_check.js (Kusto parser), securityevent.schema
- [x] tests/: 13 unit tests for the validator and the converter
- [x] CI: .github/workflows/kql-validate.yml, Actions pinned to SHAs, read-only token

### Automated checks, all passing

- `python scripts/validate_rules.py` -> 4 of 4 rules PASS
- `python -m unittest discover -s tests` -> 13 tests OK
- `npm run kql-check` -> 4 of 4 queries parse and analyse clean against the SecurityEvent schema

What the checks prove: every query is valid KQL, references only real SecurityEvent
columns, carries its header block and false-positive filter; every rule has all
required Sentinel fields, a correct ATT&CK id, and a query identical to its .kql
file; the converter emits four disabled rules with no identifiers.

## NEEDS HUMAN — requires your Azure tenant and hands

These cannot be done by an agent. They need a subscription, a running DC, and real
attacks against it.

- [ ] Stand up the lab with docs/SETUP.md.
- [ ] Deploy the rules with deployment/deploy-rules.md and enable them.
- [ ] Run the four simulations/ guides and confirm each rule fires.
- [ ] Capture the screenshots listed in docs/evidence/README.md and commit them.
- [ ] Flip each row in the README results table from "Logic validated" to
      "Fired in lab" as its evidence lands.

Until that is done, the detections are logic-validated, not lab-proven, and the
README says so.

## Notes

- Windows Server 2022 for the DC on purpose: still issues RC4 tickets on request,
  which the Kerberoasting simulation needs.
- The DCSync rule needs the `domain_controllers` list kept current, in query.kql
  and rule.yaml. Default `["dc01$"]` suits the single-DC lab.
- The Golden Ticket rule is a correlation and the noisiest of the four. Enable it
  only after confirming Kerberos events are collected from every DC.
- Simulation guides reference the public tools (Impacket, Rubeus, Kerbrute,
  Mimikatz) and the MITRE Atomic Red Team tests for exact invocation rather than
  inlining full offensive command chains; the detection and its telemetry are the
  focus here.
