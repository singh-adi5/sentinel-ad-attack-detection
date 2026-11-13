# Simulate Kerberoasting

Detection: [`detections/kerberoasting`](../detections/kerberoasting/README.md) · ATT&CK T1558.003

## What generates the telemetry

Kerberoasting is, at the wire level, an ordinary Kerberos service-ticket request
(TGS-REQ) for a user-backed SPN, asked for with RC4 encryption so the result cracks
faster offline. Any authenticated domain user can make the request.

Standard tools that produce this telemetry, with their documented function:

- **Impacket `GetUserSPNs.py`** — enumerates SPNs over LDAP and, with its request
  option, asks for the service tickets. Docs:
  <https://github.com/fortra/impacket>.
- **Rubeus** `kerberoast` action, on a domain-joined Windows host. Docs:
  <https://github.com/GhostPack/Rubeus>.
- **Atomic Red Team T1558.003** — maintained, copy-paste lab commands:
  <https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1558.003/T1558.003.md>.

Run the request as the low-privilege user `alice.lab` so the detection sees a normal
user, not an administrator. The lab has three SPN accounts (`svc-sql`, `svc-web`,
`svc-backup`), which meets the rule's threshold of three distinct SPNs.

## Expected log artifacts

On DC01, one **4769** per service ticket, with:

| Field | Value | Meaning |
|---|---|---|
| `TicketEncryptionType` | `0x17` | RC4, requested because it cracks faster than AES |
| `Status` | `0x0` | the request succeeded |
| `ServiceName` | `svc-sql`, `svc-web`, `svc-backup` | the roasted accounts |
| `TargetUserName` | `alice.lab@CONTOSO.LOCAL` | the requester |
| `IpAddress` | the attacker address | source |

A normal logon also produces 4769 events, but for machine SPNs (`host/...`, names
ending `$`) and often with AES. The RC4 + user-backed-SPN combination is the signal.

## Confirm the detection

Paste `detections/kerberoasting/query.kql` into Sentinel **Logs** over the last
hour. One row should return for `alice.lab`, with `SpnCount` of 3 and the three
service names in `Services`. When the scheduled rule next runs it raises an alert
with the account, source address and host as entities. Screenshot it into
[`docs/evidence/`](../docs/evidence/) (redact any real address first).

## Reset the lab

Nothing persistent changes. The requested tickets expire on their own. Delete any
`*.hashes` output; do not commit it.
