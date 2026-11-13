# Simulate Golden Ticket

Detection: [`detections/golden-ticket`](../detections/golden-ticket/README.md) · ATT&CK T1558.001

> This forges a Kerberos TGT from the lab's `krbtgt` key. Run it **only** against
> the disposable lab, and delete the lab afterwards
> ([teardown](../docs/SETUP.md#11-teardown)). Do not commit any ticket file;
> `.gitignore` blocks `*.kirbi` and `*.ccache`.

## What generates the telemetry

A golden ticket is a TGT built offline from the `krbtgt` key (obtained in the
[DCSync](dcsync.md) step). Because it is forged on the attacker's machine, the KDC
**never issues it**, so there is no 4768 for it, and the forged lifetime is inside
the ticket and is not written to any Security event. The detectable moment is the
**next** step: using the forged TGT to request a service ticket, which writes a
normal 4769 with no preceding TGT request. See the
[detection README](../detections/golden-ticket/README.md#what-the-logs-can-and-cannot-show)
for why this is the honest signal.

Standard tools that produce this telemetry, with their documented function:

- **Mimikatz** `kerberos::golden`. Docs:
  <https://github.com/gentilkiwi/mimikatz/wiki>.
- **Rubeus** `golden`. Docs: <https://github.com/GhostPack/Rubeus>.
- **Impacket `ticketer.py`**. Docs: <https://github.com/fortra/impacket>.
- **Atomic Red Team T1558.001** — maintained lab commands:
  <https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1558.001/T1558.001.md>.

The inputs are the domain SID, the domain name, and the `krbtgt` key from the DCSync
step. Forge a ticket for `labadmin`, then **use it** to reach a service on DC01 (for
example, list a share), which triggers the 4769.

### Making the test produce a clean signal

The rule looks for a 4769 whose account+source pair has no 4768/4770 in the last 12
hours. If the same account has recently logged on normally from the attacker host,
its real TGT masks the forged one. To get a clean detection, run the forged-ticket
step from a host and account context that has **not** just authenticated normally —
or key the test on an account that otherwise never appears from that address.

## Expected log artifacts

On DC01, a successful **4769** where:

- `TargetUserName` is `labadmin@CONTOSO.LOCAL`,
- `IpAddress` is the attacker address,
- and there is **no** 4768 (TGT issued) or 4770 (renewed) for that account+address
  in the preceding 12 hours.

## Confirm the detection

Paste `detections/golden-ticket/query.kql` into Sentinel **Logs** over the last
hour. The anti-join should return a row for `labadmin` from the attacker address.
The scheduled rule (High severity) then raises an alert. Screenshot it into
[`docs/evidence/`](../docs/evidence/).

If nothing returns, the usual cause is a masking real TGT (see above) or Kerberos
events not being collected from every DC
([detection gaps](../detections/golden-ticket/README.md#false-positives-and-tuning)).

## Reset the lab

The lab is now fully compromised. **Delete the resource group**
([teardown](../docs/SETUP.md#11-teardown)). If you want to keep the lab, reset the
`krbtgt` password **twice** with the replication interval between resets, as
described in the [detection README](../detections/golden-ticket/README.md#response);
one reset leaves the old key valid.
