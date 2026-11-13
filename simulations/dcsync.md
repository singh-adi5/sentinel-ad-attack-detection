# Simulate DCSync

Detection: [`detections/dcsync`](../detections/dcsync/README.md) · ATT&CK T1003.006

> This simulation retrieves directory secrets, including the `krbtgt` key, from the
> lab domain controller. Run it **only** against the disposable lab in
> [docs/SETUP.md](../docs/SETUP.md), and tear the lab down afterwards
> ([teardown](../docs/SETUP.md#11-teardown)). The output is credential material:
> never commit it. `.gitignore` blocks the common output files.

## What generates the telemetry

DCSync abuses the Directory Replication Service: an account holding the replication
extended rights asks a DC for an object's secrets over the network, imitating
another domain controller. It needs an account with those rights — in the lab,
`labadmin`, which is a domain admin.

Standard tools that produce this telemetry, with their documented function:

- **Impacket `secretsdump.py`** — its DRSUAPI method performs the replication pull.
  Docs: <https://github.com/fortra/impacket>.
- **Mimikatz** `lsadump::dcsync`. Docs:
  <https://github.com/gentilkiwi/mimikatz/wiki>.
- **Atomic Red Team T1003.006** — maintained lab commands:
  <https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1003.006/T1003.006.md>.

For the rule, the request has to come from an account that is **not** a listed
domain controller. Running the pull as `labadmin` (a user, not a DC computer
account) meets that. Target a single account rather than the whole domain if you
only need to confirm the detection; the `krbtgt` account is the one the
[Golden Ticket](golden-ticket.md) guide needs next.

## Expected log artifacts

On DC01, event **4662** with:

| Field | Value |
|---|---|
| `ObjectServer` | `DS` |
| `Properties` | contains `1131f6aa-...` (Get-Changes) and/or `1131f6ad-...` (Get-Changes-All) |
| `SubjectUserName` | `labadmin` — a user account, not a DC |

The replication-rights GUIDs are listed in the
[detection README](../detections/dcsync/README.md#detection-logic). The rule joins
on logon ID to a nearby 4624 to add the source address.

## Confirm the detection

Paste `detections/dcsync/query.kql` into Sentinel **Logs** over the last hour. One
row should return with `Actor` = `labadmin`, the replication right in
`ReplicationRights`, and the source address if a matching 4624 was collected. The
scheduled rule (High severity, 15-minute cadence) then raises an alert. Screenshot
it into [`docs/evidence/`](../docs/evidence/).

## Reset the lab

The `krbtgt` key has now left the DC. This lab is compromised by design: do not
connect it to any other network. After the Golden Ticket guide, delete the resource
group. Securely delete any dumped output on the attacker host.
