# Evidence

A detection is only proven when it fires on real data. The rules and queries in this
repository are validated by automated checks (parser, schema, query parity), but
those checks do not run the queries against a live workspace. That last step is the
lab owner's to do, and its proof goes here.

## Status

**Not yet captured.** The detections have not been run against a live Sentinel
workspace. See [PROGRESS.md](../../PROGRESS.md). When these screenshots are added,
update the Status column in the [README results table](../../README.md#detections)
from `Logic validated` to `Fired in lab`.

## What to add

For each of the four detections, after running its
[simulation](../../simulations/), capture:

1. **The incident.** Sentinel > Incidents, the incident opened by the rule, showing
   its title, severity and the mapped entities (account, source address, host).
2. **The query result.** Sentinel > Logs, the detection's `query.kql` returning the
   simulated activity.
3. **The rule page.** Analytics > the rule, showing it enabled with its schedule.

Suggested file names:

```
kerberoasting-incident.png      kerberoasting-logs.png
dcsync-incident.png             dcsync-logs.png
password-spraying-incident.png  password-spraying-logs.png
golden-ticket-incident.png      golden-ticket-logs.png
```

A short `evidence.md` noting the date each was captured and the lab build helps a
reviewer place them.

## Before you commit a screenshot

- Redact any real public IP address, tenant or subscription ID, or workspace name.
- Crop out the Azure portal account name in the top-right.
- Never include a screenshot that shows a hash, a ticket, or a password, even from a
  disposable lab. See [SECURITY.md](../../SECURITY.md).
