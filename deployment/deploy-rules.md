# Deploy the analytics rules

The four rules live in `detections/*/rule.yaml`. That is the format Microsoft uses
for rule templates in the Azure-Sentinel GitHub repository. The Sentinel portal does
not import that YAML directly: it imports ARM template JSON. So there is one small
conversion step.

> The converter and its output have unit tests, but the template has not yet been
> deployed to a live workspace by the author. Tracked in [PROGRESS.md](../PROGRESS.md).

## Before you deploy

1. Events are arriving. See [SETUP.md step 10](../docs/SETUP.md#10-check-that-events-arrive).
2. In `detections/dcsync/query.kql` **and** `detections/dcsync/rule.yaml`, set
   `domain_controllers` to the lower-case computer account of every domain
   controller. The default is `["dc01$"]`, which is right for this lab.
3. `python scripts/validate_rules.py` prints `PASS` for all four.

## Option A: Azure CLI

```bash
pip install -r requirements-dev.txt

python deployment/yaml_to_arm.py > sentinel-rules.arm.json

az deployment group create \
  --resource-group <RESOURCE_GROUP> \
  --template-file sentinel-rules.arm.json \
  --parameters workspace=<WORKSPACE_NAME>
```

`sentinel-rules.arm.json` is generated output and is in `.gitignore`.

Redeploying updates the rules in place, because each rule keeps the GUID from the
`id` field of its YAML.

## Option B: portal import

1. Generate `sentinel-rules.arm.json` as above.
2. In Sentinel, open **Analytics** > **Import**.
3. Select the file. All four rules are created.

## Option C: by hand

For one rule, without any tooling:

1. In Sentinel, open **Analytics** > **Create** > **Scheduled query rule**.
2. Copy `name`, `description`, `severity`, tactic and technique from `rule.yaml`.
3. Paste the contents of `query.kql` as the rule query.
4. Set **Run query every** to `queryFrequency` and **Lookup data from the last** to `queryPeriod`.
5. Add the entity mappings listed under `entityMappings`.
6. Alert threshold: **Is greater than 0**.

## Enable the rules

The converter creates every rule **disabled**. This is deliberate: a rule should be
switched on after its allow-lists are set, not before.

In **Analytics**, select each rule and choose **Enable**. Then run the matching
guide in [`simulations/`](../simulations/).

| Rule | Runs every | Looks back | Severity |
|---|---|---|---|
| Kerberoasting | 1 hour | 1 hour | Medium |
| DCSync | 15 minutes | 1 hour | High |
| Password spraying | 30 minutes | 30 minutes | Medium |
| Golden Ticket | 1 hour | 12 hours | High |

A rule only evaluates on its schedule. After a simulation, either wait for the next
run or paste the query into **Logs** to see the result at once.

## Remove the rules

Delete them in **Analytics**, or delete the resource group as described in
[SETUP.md](../docs/SETUP.md#11-teardown).
