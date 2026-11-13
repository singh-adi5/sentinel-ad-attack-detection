# Simulations

Each guide generates the telemetry for one detection, then says what to look for.

**Lab only.** Run these against the lab from [docs/SETUP.md](../docs/SETUP.md) and
nothing else. Using these tools against systems you do not own or have written
authorisation to test is illegal, including under the UK Computer Misuse Act 1990.
See [SECURITY.md](../SECURITY.md).

## How these guides are written

The emphasis is on the **defensive side**: the Windows events each technique
produces, and how to confirm the matching rule fires. For the attacker step, each
guide names the standard public tool and the specific documented function, and
links to that tool's own documentation and to the relevant
[MITRE Atomic Red Team](https://github.com/redcanaryco/atomic-red-team) test for the
exact, maintained invocation. The guides deliberately do not reproduce full
credential-theft or ticket-forging command chains; the tool docs and Atomic tests
are the maintained source for those, and the value here is the detection.

Run the guides in this order. Golden Ticket depends on the `krbtgt` key, which in a
real intrusion comes from the DCSync step.

| Order | Guide | Technique | Rule it should fire |
|---|---|---|---|
| 1 | [kerberoasting.md](kerberoasting.md) | T1558.003 | Kerberoasting |
| 2 | [password-spraying.md](password-spraying.md) | T1110.003 | Password spraying |
| 3 | [dcsync.md](dcsync.md) | T1003.006 | DCSync |
| 4 | [golden-ticket.md](golden-ticket.md) | T1558.001 | Golden Ticket |

Conventions:

- The domain controller is `dc01.contoso.local` at 10.10.1.4.
- `<PLACEHOLDER>` values are yours to fill in. Never commit them, and never commit
  tool output. `.gitignore` blocks `*.ccache`, `*.kirbi`, `*.hashes` and similar.
- Events take a few minutes to reach the workspace, and a rule only runs on its
  schedule. To confirm a detection at once, paste the query from
  `detections/<name>/query.kql` into Sentinel **Logs**.
