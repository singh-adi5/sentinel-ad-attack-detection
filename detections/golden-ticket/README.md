# Golden Ticket

| | |
|---|---|
| ATT&CK | [T1558.001](https://attack.mitre.org/techniques/T1558/001/) Steal or Forge Kerberos Tickets: Golden Ticket |
| Tactic | Credential Access |
| Data source | `SecurityEvent`, EventIDs 4768, 4769, 4770 |
| Severity | High |
| Files | [`query.kql`](query.kql), [`rule.yaml`](rule.yaml), [simulation](../../simulations/golden-ticket.md) |

## Technique

Every TGT in a domain is encrypted with the `krbtgt` account's key. An attacker who
has that key, usually from a DCSync, can build a TGT offline for any user with any
group membership. The KDC trusts it because it decrypts correctly.

## What the logs can and cannot show

The forged TGT is built on the attacker's machine. The domain controller never
issues it, so there is **no 4768** for it. The forged lifetime, often ten years, is
inside the ticket and is not written to any Security event. A detection that claims
to read ticket lifetime from `SecurityEvent` is not reading a real field.

What the DC does log is the next step. To use the TGT the attacker asks for a
service ticket, and that writes a normal **4769**. The result is a service ticket
request with no TGT request before it.

## Detection logic

1. Collect 4768 (TGT issued, status 0x0) and 4770 (ticket renewed) for the last 12
   hours. That is every account and source address pair holding a legitimate TGT.
   The default TGT lifetime is 10 hours.
2. Collect successful 4769 events from the last hour, excluding requests for the
   `krbtgt` service and machine accounts.
3. Anti-join. Keep service ticket requests whose account and source address have no
   TGT on record.

The join key is the account name and the source address after normalisation:
lower-cased, realm removed, `::ffff:` prefix stripped. Event 4768 logs `alice` and
event 4769 logs `alice@CONTOSO.LOCAL`, so comparing raw values matches nothing.

## False positives and tuning

This is a correlation, and it is noisier than the other three rules. Expect to tune it.

- **A domain controller whose events are not collected.** If a client got its TGT
  from DC02 and DC02 is not sending logs, every service ticket it requests from
  DC01 looks forged. Collect 4768 to 4770 from **every** DC before enabling this.
- **Address changes.** A laptop that moves from Wi-Fi to VPN keeps its TGT but
  arrives from a new address. Add roaming accounts to `excluded_accounts`, or key
  the join on account only and accept weaker detection.
- **NAT.** Usually harmless, because the TGT and service ticket share the
  translated address.
- **Longer ticket lifetimes.** If domain policy allows TGTs over 10 hours, raise
  `tgt_lookback`. The rule's `queryPeriod` must be at least as long.
- **Ingestion gaps.** A dropped 4768 creates a false positive. Check agent health
  before trusting an alert.

## Known gaps

- **The attacker already has a real TGT for that account from that address.** The
  forged ticket hides behind it. The simulation guide explains how to avoid this
  when testing.
- **Machine accounts are excluded**, so a forged ticket for a computer account is missed.
- **Silver tickets** forge the service ticket itself and never contact the KDC. No
  4769 is written. This rule cannot see them.
- **Diamond and sapphire tickets** modify a real TGT. A 4768 exists, so the gap
  this rule looks for is not there.

## Other signals worth adding

Not implemented here, to keep the scope at one tested rule:

- 4769 with RC4 encryption for a privileged account in a domain that is AES only.
- 4769 for an account name that does not exist in the directory.
- Kerberos failures 0x1F or 0x40 across many accounts straight after a `krbtgt` reset.

## Response

1. Treat it as domain compromise. A golden ticket means the `krbtgt` key is known.
2. Reset the `krbtgt` password twice, with the replication interval between resets.
   One reset is not enough: the previous key stays valid.
3. Find the earlier credential theft. Look for a DCSync alert or access to `ntds.dit`.
4. Isolate the source address and review everything the account did.

## Mitigations

- M1015 Active Directory Configuration: rotate `krbtgt` on a schedule and after any DC compromise.
- M1026 Privileged Account Management: limit who can replicate or log on to DCs.
- M1041 Encrypt Sensitive Information: AES-only Kerberos makes RC4 forgeries stand out.
