# Kerberoasting

| | |
|---|---|
| ATT&CK | [T1558.003](https://attack.mitre.org/techniques/T1558/003/) Steal or Forge Kerberos Tickets: Kerberoasting |
| Tactic | Credential Access |
| Data source | `SecurityEvent`, EventID 4769 |
| Severity | Medium |
| Files | [`query.kql`](query.kql), [`rule.yaml`](rule.yaml), [simulation](../../simulations/kerberoasting.md) |

## Technique

Any authenticated domain user can ask the KDC for a service ticket to any SPN. Part
of that ticket is encrypted with a key derived from the service account's password.
The attacker requests tickets for SPNs that belong to user accounts, takes them
offline and cracks the password. Nothing is sent to the service itself, and the
request is valid Kerberos, so there is no failure to alert on.

## Detection logic

The domain controller logs one 4769 per service ticket. The query keeps a request when:

1. It succeeded (`Status` 0x0).
2. The ticket was RC4 encrypted (`TicketEncryptionType` 0x17 or 0x18). Roasting
   tools ask for RC4 because it cracks far faster than AES. In a domain where
   accounts support AES, a normal client gets AES tickets.
3. The service is not a machine account (name ending `$`) and not `krbtgt`. Machine
   account passwords are random and not worth cracking.
4. The requester is not a machine account and is not asking for its own SPN.

It then counts distinct SPNs per requester and source address and fires at three or
more inside the hour. One RC4 ticket is common. Several different SPNs from one
account in one hour is an enumeration.

## False positives and tuning

- **Legacy services that only support RC4.** A user of three such services in an
  hour looks the same as a roast. Fix the cause: set
  `msDS-SupportedEncryptionTypes` to AES on the service accounts. Until then, raise
  `spn_threshold`.
- **Vulnerability scanners and AD assessment tools** that request tickets on
  purpose. Add their account to `excluded_requesters`.
- **`spn_threshold`** defaults to 3. A domain with many RC4-only services needs it
  higher. A domain with none can drop it to 1, which turns any RC4 ticket for a
  user-backed SPN into an alert.

## Known gaps

- **AES roasting.** `Rubeus kerberoast /aes` and similar options request AES
  tickets. This rule does not see them. Catching that needs a volume baseline per
  account rather than an encryption-type filter.
- **Slow roasting.** One SPN an hour stays under the threshold.
- **A honeypot SPN is a stronger signal.** A service account that nothing uses,
  with an SPN and a long random password, should never receive a ticket request.
  Alerting on any 4769 for it has almost no false positives. That is an environment
  change, so it is not part of this rule.

## Response

1. Identify the requester and source address from the alert entities.
2. List the SPNs in `Services`. Treat each of those service account passwords as exposed.
3. Reset those passwords to long random values, or move the accounts to group
   managed service accounts.
4. Investigate how the requesting account was compromised.

## Mitigations

- M1027 Password Policies: 25+ character random passwords on service accounts, or gMSA.
- M1041 Encrypt Sensitive Information: enforce AES and disable RC4 for Kerberos.
- M1026 Privileged Account Management: service accounts hold no more rights than the service needs.
