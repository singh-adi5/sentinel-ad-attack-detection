# DCSync

| | |
|---|---|
| ATT&CK | [T1003.006](https://attack.mitre.org/techniques/T1003/006/) OS Credential Dumping: DCSync |
| Tactic | Credential Access |
| Data source | `SecurityEvent`, EventID 4662, joined to EventID 4624 |
| Severity | High |
| Files | [`query.kql`](query.kql), [`rule.yaml`](rule.yaml), [simulation](../../simulations/dcsync.md) |

## Technique

Domain controllers keep each other in step through the Directory Replication
Service protocol. An account holding the replication rights on the domain object
can call the same interface and ask a DC for any object's secrets, including
password hashes and the `krbtgt` key. The attacker never logs on to the DC and
never touches `ntds.dit`. They impersonate a domain controller over the network.

## Detection logic

Using a replication right writes event 4662 on the DC that served the request. The
`Properties` field holds the GUID of the right:

| Right | GUID |
|---|---|
| DS-Replication-Get-Changes | `1131f6aa-9c07-11d1-f79f-00c04fc2dcd2` |
| DS-Replication-Get-Changes-All | `1131f6ad-9c07-11d1-f79f-00c04fc2dcd2` |
| DS-Replication-Get-Changes-In-Filtered-Set | `89e95b76-444d-4c62-991a-0facbeda640c` |

Real replication is done by domain controller computer accounts. The query keeps
any 4662 with one of these GUIDs where the subject is **not** in the
`domain_controllers` list and not in `approved_replication_accounts`.

Event 4662 has no network address. The query joins on logon ID to the 4624 network
logon on the same DC to recover the source address. If no logon is found inside the
query period the alert still fires, with `SourceIp` empty.

## Why a list of domain controllers, not "ends with $"

Many public versions of this rule exclude every machine account. That misses a
DCSync run with a compromised computer account that has been granted replication
rights, which is a known persistence method. Naming the DCs is more work to
maintain and closes that gap.

## False positives and tuning

- **Directory synchronisation.** Microsoft Entra Connect uses an account, usually
  named `MSOL_` followed by a hex string, that replicates by design. Add it to
  `approved_replication_accounts`, in lower case. It should only ever come from the
  sync server, so an alert for that account from another address is real.
- **A new domain controller** that is not yet in `domain_controllers` will alert.
  Add it as part of the DC build process.
- **Other products that replicate**: some password filters, identity governance
  tools and AD backup agents. Confirm with the owner, then allow-list the account.

This rule should be quiet. Every allow-list entry is an account that can dump the
domain, so keep the list short and review it.

## Known gaps

- Needs "Audit Directory Service Access" on every DC and the default audit entries
  on the domain object. If an attacker with domain admin rights removes those
  entries first, no 4662 is written.
- 4662 must be collected. Sentinel's "Common" event tier leaves it out. See
  [ARCHITECTURE.md](../../docs/ARCHITECTURE.md#why-these-seven-event-ids).
- An attacker who runs DCSync as a real domain controller account is not detected here.

## Response

1. Treat it as full domain compromise until shown otherwise.
2. Identify the account and source address. Isolate the source host.
3. Find how the account obtained replication rights: group membership or a direct
   ACL entry on the domain object.
4. Reset the `krbtgt` password twice, with the replication interval between resets,
   and reset every privileged account.

## Mitigations

- M1026 Privileged Account Management: keep replication rights to domain controllers only.
- M1015 Active Directory Configuration: audit the ACL on the domain object for unexpected replication rights.
- M1027 Password Policies: limits what dumped hashes are worth once cracked.
