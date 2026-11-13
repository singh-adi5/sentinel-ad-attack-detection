# Password spraying

| | |
|---|---|
| ATT&CK | [T1110.003](https://attack.mitre.org/techniques/T1110/003/) Brute Force: Password Spraying |
| Tactic | Credential Access |
| Data source | `SecurityEvent`, EventID 4771 and EventID 4625 |
| Severity | Medium |
| Files | [`query.kql`](query.kql), [`rule.yaml`](rule.yaml), [simulation](../../simulations/password-spraying.md) |

## Technique

Instead of many passwords against one account, the attacker tries one or two common
passwords against every account. Each account sees a single failure, so lockout
thresholds are never reached and per-account failure alerts stay silent.

## Detection logic

The signal is on the source, not the account. The query collects two kinds of failure:

| Event | Protocol | Filter |
|---|---|---|
| 4771 | Kerberos pre-authentication | `Status` 0x18, wrong password |
| 4625 | NTLM and interactive logon | `SubStatus` 0xC000006A wrong password, 0xC0000064 unknown user |

It groups them by source address and fires when one address fails against **10 or
more distinct accounts** in the 30 minute period with **5 or fewer attempts per
account**. The second condition separates a spray (wide and shallow) from a brute
force (narrow and deep) and from a single broken service account retrying.

Both events are needed. Kerbrute sprays over Kerberos and writes only 4771. SMB and
LDAP spraying tools write 4625. A rule on one of them misses the other family.

## False positives and tuning

- **Shared egress addresses.** A VPN concentrator, reverse proxy, RDP gateway or
  terminal server puts many users behind one address. After a password-expiry
  wave it looks like a spray. Add the address to `excluded_sources`, or better,
  raise `account_threshold` for it.
- **A domain-wide password change** or an expired service credential deployed on
  many hosts produces failures from many sources, not one. This rule ignores it.
- **`account_threshold`** defaults to 10. Size it to the estate: a spray against
  5,000 users is not subtle, and 10 can be too low behind NAT.
- **`max_attempts_per_account`** defaults to 5. Raise it if attackers are seen
  trying several passwords per run.

## Known gaps

- **Low and slow.** Nine accounts every 30 minutes stays under the threshold.
  Catching it needs a longer period and a daily distinct-account count.
- **Distributed sprays** from many addresses. Each source stays under the threshold.
- **Failures logged elsewhere.** A 4625 for an SMB spray against a member server is
  written on that server, not the DC. This lab collects from the DC only.
- **Account enumeration** before the spray (4768 with status 0x6, unknown
  principal) is a separate signal and is not in this rule.
- **The spray that works.** This rule sees failures. Follow every alert with a
  search for a successful logon from the same source.

## Response

1. Search for 4624 and successful 4768 events from `SourceIp` in the same window. A
   success means an account is compromised.
2. Reset any account that authenticated successfully from that address.
3. Block or isolate the source.
4. Check `Accounts` for names that do not exist in the domain. An accurate list
   suggests earlier reconnaissance.

## Mitigations

- M1032 Multi-factor Authentication.
- M1027 Password Policies: ban common passwords.
- M1036 Account Use Policies: a lockout threshold with an observation window.
