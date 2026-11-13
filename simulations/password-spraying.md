# Simulate Password spraying

Detection: [`detections/password-spraying`](../detections/password-spraying/README.md) · ATT&CK T1110.003

## What generates the telemetry

Password spraying tries one or two common passwords against many accounts, so each
account sees a single failure and lockout thresholds are never reached. At the wire
level it is a burst of authentication failures from one source across many
usernames.

Standard tools that produce this telemetry, with their documented function:

- **Kerbrute** `passwordspray` — sprays over Kerberos pre-authentication and writes
  event 4771. Docs: <https://github.com/ropnop/kerbrute>.
- A short loop over SMB or LDAP authentication writes event 4625. Any spraying tool
  that authenticates (rather than pre-authenticating) produces this family.
- **Atomic Red Team T1110.003** — maintained lab commands:
  <https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1110.003/T1110.003.md>.

To exercise the rule you need failures against **at least ten distinct accounts**
from one source. The lab's `user01`–`user15` accounts
([SETUP.md step 6](../docs/SETUP.md#6-create-lab-accounts)) give enough targets.
Use a wrong password on purpose so every attempt fails. Keep attempts to one or two
per account so the pattern is a spray, not a brute force.

Supply the account list as a file of the lab usernames. Do not use a real
organisation's user list.

## Expected log artifacts

On DC01, many failures from one `IpAddress` across many `TargetUserName` values:

| Event | When it appears | Key field |
|---|---|---|
| 4771 | Kerberos pre-auth failed | `Status` = `0x18` (wrong password) |
| 4625 | NTLM / interactive logon failed | `SubStatus` = `0xC000006A` wrong password, or `0xC0000064` unknown user |

The rule keys on the source address: 10+ distinct accounts, 5 or fewer attempts
each, inside the 30-minute window.

## Confirm the detection

Paste `detections/password-spraying/query.kql` into Sentinel **Logs** over the last
30 minutes. One row should return for the attacker address, with `TargetedAccounts`
of 10 or more and a low `AttemptsPerAccount`. The scheduled rule then raises an
alert with the source address as the entity. Screenshot it into
[`docs/evidence/`](../docs/evidence/).

After the spray, run the follow-up search in the detection README to confirm no
account authenticated successfully from that source.

## Reset the lab

No lab state changes. If an account locked out, unlock it with
`Unlock-ADAccount -Identity <name>` on DC01.
