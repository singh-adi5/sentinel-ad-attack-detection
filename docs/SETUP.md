# Lab setup

Stand up the lab end to end: network, domain controller, attacker host, Sentinel
workspace, agent and collection rule. Allow about two hours the first time.

Commands are Azure CLI in Bash (Azure Cloud Shell works) unless a step says
PowerShell on DC01. Replace every `<PLACEHOLDER>`. Do not commit the real values.

> This guide was written from the Azure and Windows documentation and has not yet
> been run start to finish by the author. If a step fails, open an issue or fix it
> in a pull request. See [PROGRESS.md](../PROGRESS.md) for what is and is not verified.

## Cost

An Azure free trial covers this lab if the VMs are shut down between sessions.

- Two `Standard_B2s` VMs. Stop (deallocate) them when you are not working.
- Sentinel has a 31-day free trial on a new workspace, up to 10 GB a day. The
  filtered collection rule in this lab sends a few megabytes a day.
- Delete the resource group when you finish. See [Teardown](#11-teardown).

## 1. Variables

```bash
RG=rg-adlab
LOCATION=uksouth
VNET=vnet-adlab
SUBNET=snet-lab
NSG=nsg-adlab
WORKSPACE=law-adlab
DC_IP=10.10.1.4
ATTACKER_IP=10.10.1.10
MY_IP=<YOUR_PUBLIC_IP>          # the address you connect from, e.g. from https://ifconfig.me
```

## 2. Resource group and network

```bash
az group create --name $RG --location $LOCATION

az network nsg create --resource-group $RG --name $NSG

# RDP and SSH from your address only. Never open these to the internet.
az network nsg rule create --resource-group $RG --nsg-name $NSG \
  --name allow-admin-from-operator --priority 100 --direction Inbound --access Allow \
  --protocol Tcp --source-address-prefixes "$MY_IP/32" --destination-port-ranges 22 3389

az network vnet create --resource-group $RG --name $VNET \
  --address-prefix 10.10.0.0/16 \
  --subnet-name $SUBNET --subnet-prefix 10.10.1.0/24 \
  --network-security-group $NSG
```

Traffic inside the virtual network is allowed by the default NSG rules, so the
attacker host can reach the domain controller.

## 3. Domain controller VM

```bash
az vm create --resource-group $RG --name dc01 \
  --image Win2022Datacenter --size Standard_B2s \
  --vnet-name $VNET --subnet $SUBNET --nsg "" \
  --private-ip-address $DC_IP \
  --admin-username labadmin \
  --assign-identity '[system]'
```

The command prompts for the admin password. Use a long random one and keep it in a
password manager. `--assign-identity` gives the VM the managed identity that the
Azure Monitor Agent needs.

Windows Server 2022 is used on purpose. It still issues RC4 service tickets on
request, which the Kerberoasting simulation depends on. Newer releases restrict RC4
and may not reproduce that detection without extra configuration.

Azure renames the built-in Administrator account (RID 500) to the admin username
you choose. In this lab that account is `labadmin`. There is no account called
`Administrator`. The Golden Ticket simulation relies on this.

## 4. Promote DC01 to a domain controller

RDP to the public address of `dc01` as `labadmin`. In an elevated PowerShell:

```powershell
Install-WindowsFeature AD-Domain-Services -IncludeManagementTools

Install-ADDSForest `
  -DomainName contoso.local `
  -DomainNetbiosName CONTOSO `
  -InstallDns `
  -SafeModeAdministratorPassword (Read-Host -AsSecureString "DSRM password")
```

The server restarts. Log back in as `CONTOSO\labadmin`.

Point the virtual network at the new DNS server so other VMs can find the domain:

```bash
az network vnet update --resource-group $RG --name $VNET --dns-servers $DC_IP
```

## 5. Turn on the audit policy

The detections read events that Windows does not all log by default. On DC01, in an
elevated PowerShell:

```powershell
auditpol /set /subcategory:"Kerberos Authentication Service"     /success:enable /failure:enable
auditpol /set /subcategory:"Kerberos Service Ticket Operations"  /success:enable /failure:enable
auditpol /set /subcategory:"Directory Service Access"            /success:enable /failure:enable
auditpol /set /subcategory:"Logon"                               /success:enable /failure:enable

auditpol /get /category:"Account Logon","DS Access","Logon/Logoff"
```

| Subcategory | Events it produces | Needed by |
|---|---|---|
| Kerberos Authentication Service | 4768, 4771 | Golden Ticket, Password spraying |
| Kerberos Service Ticket Operations | 4769, 4770 | Kerberoasting, Golden Ticket |
| Directory Service Access | 4662 | DCSync |
| Logon | 4624, 4625 | DCSync, Password spraying |

`auditpol` changes the local policy. If a Group Policy Object later sets advanced
audit policy for domain controllers, the GPO wins. For a lab that outlives one
session, set the same four subcategories in the Default Domain Controllers Policy
under Computer Configuration > Policies > Windows Settings > Security Settings >
Advanced Audit Policy Configuration.

Event 4662 for replication also depends on the audit entries (SACL) on the domain
object. A new domain audits use of the replication rights by default. If the DCSync
simulation produces no 4662, check the Auditing tab on the `contoso.local` object in
Active Directory Users and Computers (Advanced Features on).

## 6. Create lab accounts

The simulations need accounts to attack. On DC01:

```powershell
$password = Read-Host -AsSecureString "Password for the lab accounts"

# One low-privilege user the attacker starts with.
New-ADUser -Name "alice.lab" -SamAccountName "alice.lab" `
  -AccountPassword $password -Enabled $true

# Fifteen ordinary users. Password spraying needs at least ten targets.
1..15 | ForEach-Object {
  $name = "user{0:d2}" -f $_
  New-ADUser -Name $name -SamAccountName $name -AccountPassword $password -Enabled $true
}

# Three service accounts with SPNs. Kerberoasting needs at least three.
"svc-sql", "svc-web", "svc-backup" | ForEach-Object {
  New-ADUser -Name $_ -SamAccountName $_ -AccountPassword $password -Enabled $true `
    -ServicePrincipalNames "$($_.Replace('svc-', ''))/app01.contoso.local"
}

Get-ADUser -Filter 'ServicePrincipalName -like "*"' -Properties ServicePrincipalName |
  Select-Object SamAccountName, ServicePrincipalName
```

The last command should list `krbtgt` and the three `svc-` accounts.

## 7. Attacker VM

```bash
az vm create --resource-group $RG --name attacker01 \
  --image Ubuntu2204 --size Standard_B2s \
  --vnet-name $VNET --subnet $SUBNET --nsg "" \
  --private-ip-address $ATTACKER_IP \
  --admin-username labadmin --generate-ssh-keys
```

SSH in and install the tools:

```bash
sudo apt-get update && sudo apt-get install -y pipx
pipx ensurepath && exec $SHELL
pipx install impacket

# Kerbrute: download the linux_amd64 build from the project's GitHub releases page,
# check its published checksum, then:
chmod +x kerbrute_linux_amd64 && sudo mv kerbrute_linux_amd64 /usr/local/bin/kerbrute

# Kerberos needs name resolution and clocks within five minutes of the DC.
echo "10.10.1.4 dc01.contoso.local contoso.local dc01" | sudo tee -a /etc/hosts
```

Depending on how Impacket is installed, the tools are named `GetUserSPNs.py` or
`impacket-GetUserSPNs`. The simulation guides use the `.py` names.

A Kali image from the Azure Marketplace also works. It needs its marketplace terms
accepted first, which some trial subscriptions do not allow. Ubuntu avoids that.

## 8. Workspace and Sentinel

```bash
az monitor log-analytics workspace create --resource-group $RG \
  --workspace-name $WORKSPACE --location $LOCATION
```

Enable Sentinel on it in the portal: search for **Microsoft Sentinel**, select
**Create**, pick `law-adlab`, select **Add**.

Then install the data connector. In Sentinel, open **Content hub**, find
**Windows Security Events**, select **Install**.

## 9. Agent and Data Collection Rule

There are two ways. Use one.

### Option A: portal

1. In Sentinel, open **Data connectors** > **Windows Security Events via AMA** >
   **Open connector page** > **Create data collection rule**.
2. Name it `dcr-adlab-securityevent`, same resource group.
3. On **Resources**, select `dc01`. This installs the Azure Monitor Agent on it.
4. On **Collect**, choose **Custom** and paste this XPath filter:

   ```text
   Security!*[System[(EventID=4624 or EventID=4625 or EventID=4662 or EventID=4768 or EventID=4769 or EventID=4770 or EventID=4771)]]
   ```

5. **Review + create**.

### Option B: Azure CLI

```bash
# Agent
az vm extension set --resource-group $RG --vm-name dc01 \
  --name AzureMonitorWindowsAgent --publisher Microsoft.Azure.Monitor \
  --enable-auto-upgrade true

# Fill the placeholders in a local copy. The copy is in .gitignore.
SUB=$(az account show --query id -o tsv)
sed -e "s/<LOCATION>/$LOCATION/" -e "s/<SUBSCRIPTION_ID>/$SUB/" \
    -e "s/<RESOURCE_GROUP>/$RG/" -e "s/<WORKSPACE_NAME>/$WORKSPACE/" \
    deployment/dcr-securityevent.json > dcr-securityevent.local.json

az monitor data-collection rule create --resource-group $RG \
  --name dcr-adlab-securityevent --location $LOCATION \
  --rule-file dcr-securityevent.local.json

# Associate the rule with the domain controller
DCR_ID=$(az monitor data-collection rule show -g $RG -n dcr-adlab-securityevent --query id -o tsv)
VM_ID=$(az vm show -g $RG -n dc01 --query id -o tsv)
az monitor data-collection rule association create \
  --name dcra-dc01 --rule-id "$DCR_ID" --resource "$VM_ID"
```

## 10. Check that events arrive

Wait ten to fifteen minutes after creating the rule. Log off and on to DC01 once to
generate events. In Sentinel > **Logs**:

```kusto
SecurityEvent
| where TimeGenerated > ago(1h)
| summarize Events = count() by EventID, Computer
| order by EventID asc
```

You should see 4624, 4768 and 4769 at minimum. If the table is empty:

- Confirm the `AzureMonitorWindowsAgent` extension shows **Provisioning succeeded**.
- Confirm the VM has a system-assigned managed identity.
- Confirm the DCR lists `dc01` under **Resources**.
- Confirm the audit policy from step 5 with `auditpol /get /category:*`.

Next: deploy the rules with [`deployment/deploy-rules.md`](../deployment/deploy-rules.md),
then run the four guides in [`simulations/`](../simulations/).

## 11. Teardown

Stop the VMs between sessions:

```bash
az vm deallocate --resource-group $RG --name dc01
az vm deallocate --resource-group $RG --name attacker01
```

Delete everything when you are finished:

```bash
az group delete --name $RG --yes --no-wait
```

The lab holds deliberately weak accounts and, after the simulations, a compromised
`krbtgt` key. Do not connect it to any other network, and do not reuse it.
