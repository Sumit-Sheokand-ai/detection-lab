# Lab setup

Reproducible setup for the detection-lab Windows track. Every step ends with a
verification command. Record the versions you actually installed in the
[Version record](#version-record) table. Results are only reproducible if
those versions are known.

Placeholders used throughout (never commit real values):

| Placeholder             | Meaning                                              |
|-------------------------|------------------------------------------------------|
| `<WAZUH_IP>`            | Wazuh manager/indexer address on the host-only net   |
| `<HOSTONLY_SUBNET>`     | Host-only subnet, e.g. `192.168.56.0/24`             |
| `<LAB_VICTIM_HOSTNAME>` | Victim VM hostname = Wazuh agent name                |
| `<WAZUH_VERSION>`       | Wazuh version, identical on manager and agent        |

---

## 1. Network isolation (host-only)

Topology:

```
 Host (Windows) ── host-only net <HOSTONLY_SUBNET> ──┬── Victim VM (Win 11 eval, single NIC)
   runs evaluate.py → :9200                          └── Wazuh VM (manager + indexer + dashboard)
                                                           optional 2nd NIC: NAT (updates/NTP upstream)
```

| Hypervisor | Victim NIC setting                         |
|------------|--------------------------------------------|
| VirtualBox | Adapter 1 = Host-only Adapter, others off  |
| VMware     | Host-only (VMnet1), no NAT adapter         |
| Hyper-V    | Internal virtual switch (not External)     |

Rules:
- The victim has exactly one NIC and it is host-only. There is no NAT and no bridged adapter.
- Disable shared folders, shared clipboard and drag-and-drop on the victim while tests run.
- Tools that need downloading (Sysmon, Wazuh agent MSI, Atomic Red Team) are installed during a
  **provisioning window**: temporarily attach NAT, install, detach NAT, then snapshot (section 2).
- If Wazuh runs in Docker on the host: Docker Desktop publishes ports on all host interfaces by
  default. Bind published ports to the host-only IP in `docker-compose.yml`
  (e.g. `"<HOST_HOSTONLY_IP>:9200:9200"`) or restrict them with Windows Firewall.

Ports the victim needs: `1514/tcp` (agent events), `1515/tcp` (enrollment), `123/udp` (NTP, if the
Wazuh VM serves time). Port the host needs: `9200/tcp` (indexer) and `443/tcp` (dashboard).

**Verify (on victim, PowerShell as admin):**

```powershell
Get-NetAdapter | Format-Table Name, InterfaceDescription, Status
Get-NetIPConfiguration | Format-List InterfaceAlias, IPv4Address, IPv4DefaultGateway, DNSServer

Test-NetConnection <WAZUH_IP> -Port 1514        # expect TcpTestSucceeded : True
Test-NetConnection <WAZUH_IP> -Port 1515        # expect TcpTestSucceeded : True
Test-NetConnection 1.1.1.1 -Port 443 -WarningAction SilentlyContinue   # expect False
Resolve-DnsName example.com                      # expect failure
```

**Verify (on host):**

```powershell
Test-NetConnection <WAZUH_IP> -Port 9200         # expect True
```

---

## 2. Snapshot strategy (victim)

| Snapshot              | Taken after                                                              |
|-----------------------|--------------------------------------------------------------------------|
| `00-clean-os`         | Windows installed, local admin created, timezone set to UTC              |
| `01-telemetry`        | Sections 3–7 done and `verify_telemetry.py` passes (Gate A)              |
| `02-art-ready`        | Atomic Red Team staged, NAT detached, isolation re-verified (section 1)  |

Procedure:
- Revert to `02-art-ready` before every full sweep, so each sweep starts from the same state.
- The agent is enrolled **before** `01-telemetry`, so the agent ID and key survive reverts.
  Do not re-enroll after a revert.
- After every revert, resync the clock first. A restored VM resumes at the snapshot's
  time, and stale timestamps corrupt time-to-detect:

  ```powershell
  w32tm /resync /force
  w32tm /query /status
  [DateTime]::UtcNow.ToString('o')
  ```
- The Windows 11 evaluation expires after 90 days. Record the expiry date (`slmgr /dli`).

---

## 3. Sysmon with sysmon-modular

Pin the config to a specific commit of
[olafhartong/sysmon-modular](https://github.com/olafhartong/sysmon-modular) so results are
reproducible. Use the prebuilt `sysmonconfig.xml` from the repo root (the default config).

Do this during the provisioning window. Run PowerShell as admin:

```powershell
New-Item -ItemType Directory -Path C:\Tools\Sysmon -Force | Out-Null
Set-Location C:\Tools\Sysmon

# Sysmon from Sysinternals (official)
Invoke-WebRequest https://download.sysinternals.com/files/Sysmon.zip -OutFile Sysmon.zip
Expand-Archive .\Sysmon.zip -DestinationPath . -Force

# sysmon-modular default config, pinned to a commit SHA you choose and record below
$sha = '<SYSMON_MODULAR_COMMIT_SHA>'
Invoke-WebRequest "https://raw.githubusercontent.com/olafhartong/sysmon-modular/$sha/sysmonconfig.xml" -OutFile sysmonconfig.xml
Get-FileHash .\sysmonconfig.xml -Algorithm SHA256     # record in Version record

.\Sysmon64.exe -accepteula -i .\sysmonconfig.xml

# Larger log so events survive agent hiccups (256 MB)
wevtutil sl Microsoft-Windows-Sysmon/Operational /ms:268435456
```

**Verify:**

```powershell
Get-Service Sysmon64                                   # Running
.\Sysmon64.exe -c | Select-Object -First 15            # shows active config + schema version
Get-WinEvent -LogName 'Microsoft-Windows-Sysmon/Operational' -MaxEvents 200 |
  Group-Object Id | Sort-Object Name | Format-Table Name, Count
```

> **Coverage note.** sysmon-modular's default config uses include/exclude filters. Event IDs 10
> (ProcessAccess), 11 (FileCreate), 12 and 13 (Registry) are logged only for matched
> targets and paths. A missing event is not always a pipeline fault: it can be the config. Check with
> `Sysmon64.exe -c` and record gaps in Phase 3. Do not loosen the config just to pass a check.

---

## 4. PowerShell logging (script block + module)

Applies to Windows PowerShell 5.1, which Atomic Red Team mostly uses.

```powershell
$sb = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'
if (-not (Test-Path $sb)) { New-Item -Path $sb -Force | Out-Null }
Set-ItemProperty -Path $sb -Name EnableScriptBlockLogging -Value 1 -Type DWord

$ml = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging'
if (-not (Test-Path "$ml\ModuleNames")) { New-Item -Path "$ml\ModuleNames" -Force | Out-Null }
Set-ItemProperty -Path $ml -Name EnableModuleLogging -Value 1 -Type DWord
Set-ItemProperty -Path "$ml\ModuleNames" -Name '*' -Value '*'

wevtutil sl Microsoft-Windows-PowerShell/Operational /ms:268435456
```

(`Test-Path` guard: `New-Item -Force` on an existing registry key wipes its values.)

**Verify:**

```powershell
Get-ItemProperty $sb, $ml | Format-List PSPath, Enable*
powershell.exe -NoProfile -Command "Write-Output 'dl-4104-check'"
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational'; Id=4104} -MaxEvents 50 |
  Where-Object Message -match 'dl-4104-check' | Select-Object -First 1 TimeCreated, Id
```

> **Gap.** PowerShell 7 (`pwsh.exe`) uses a different policy path
> (`HKLM:\SOFTWARE\Policies\Microsoft\PowerShellCore\...`) and writes to the
> `PowerShellCore/Operational` channel, which is not collected below. Do not install pwsh 7 on the
> victim, or add that channel too.

---

## 5. Event 4688 with command line

Process Creation subcategory GUID: `{0CCE922B-69AE-11D9-BED3-505054503030}`. The GUID is used
instead of the name because subcategory names change with the OS locale.

```powershell
auditpol /set /subcategory:"{0CCE922B-69AE-11D9-BED3-505054503030}" /success:enable

$a = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit'
if (-not (Test-Path $a)) { New-Item -Path $a -Force | Out-Null }
Set-ItemProperty -Path $a -Name ProcessCreationIncludeCmdLine_Enabled -Value 1 -Type DWord
```

**Verify:**

```powershell
auditpol /get /subcategory:"{0CCE922B-69AE-11D9-BED3-505054503030}"   # Success
cmd.exe /c "echo dl-4688-check"
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4688} -MaxEvents 50 |
  Where-Object Message -match 'dl-4688-check' | Select-Object -First 1 -ExpandProperty Message
# expect a "Process Command Line:" line containing dl-4688-check
```

---

## 6. Time sync (all timestamps UTC)

Time-to-detect compares the victim's clock (`run_atomics.ps1` start time) with the manager's clock
(`@timestamp` at ingest), so the two clocks must agree.

Victim timezone, for readability. Windows event times are UTC internally either way:

```powershell
Set-TimeZone -Id 'UTC'
Get-TimeZone
```

Pick **one** time source per VM. If hypervisor guest time sync and w32time both run, they fight.

**Option A: hypervisor time sync.** Enable the guest-tools time sync on both the victim and the Wazuh
VM, and keep the host itself on NTP. For Wazuh in Docker on the host, the containers use the
host clock.

**Option B: Wazuh VM serves NTP to the host-only net.** Use this when the Wazuh VM has an upstream
via NAT. On the Wazuh VM (chrony):

```bash
# /etc/chrony/chrony.conf
allow <HOSTONLY_SUBNET>
local stratum 10
```
```bash
sudo systemctl restart chrony && chronyc tracking
# open udp/123 from <HOSTONLY_SUBNET> in the VM firewall if one is active
```

On the victim:

```powershell
w32tm /config /manualpeerlist:"<WAZUH_IP>,0x8" /syncfromflags:manual /reliable:no /update
Restart-Service w32time
w32tm /resync /force
```

**Verify:**

```powershell
w32tm /query /status                                              # Source = expected peer
w32tm /stripchart /computer:<WAZUH_IP> /samples:5 /dataonly      # Option B: offsets well under 1s
```

`verify_telemetry.py` also prints `@timestamp - data.win.system.systemTime` for every sample. That
value should be a small positive number (the ingest lag). A **negative** value means the victim clock
is ahead of the manager.

---

## 7. Wazuh agent enrollment

Do this during the provisioning window. The agent version must equal the manager version. The agent
name must equal the hostname in `LAB_VICTIM_HOSTNAME`: the harness safety check and every
evaluation query filter on it.

```powershell
hostname        # this value goes into .env as LAB_VICTIM_HOSTNAME

# MSI: https://packages.wazuh.com/4.x/windows/wazuh-agent-<WAZUH_VERSION>-1.msi
msiexec.exe /i wazuh-agent-<WAZUH_VERSION>-1.msi /q WAZUH_MANAGER="<WAZUH_IP>" WAZUH_AGENT_NAME="<LAB_VICTIM_HOSTNAME>"
# if the manager enforces password enrollment, add: WAZUH_REGISTRATION_PASSWORD="<...>"

Get-Service -DisplayName 'Wazuh*' | Start-Service
```

### Agent `ossec.conf` eventchannel entries

File: `C:\Program Files (x86)\ossec-agent\ossec.conf` (edit as admin). Inside `<ossec_config>`:

1. Confirm that the default `Security` entry exists and that its `<query>` does **not** exclude 4688.
   The stock query only excludes noisy IDs such as 5145, 5156 and 4656:

   ```xml
   <localfile>
     <location>Security</location>
     <log_format>eventchannel</log_format>
     <query>Event/System[EventID != 5145 and EventID != 5156 and EventID != 5447 and
       EventID != 4656 and EventID != 4658 and EventID != 4663 and EventID != 4660 and
       EventID != 4670 and EventID != 4690 and EventID != 4703 and EventID != 4907 and
       EventID != 5152 and EventID != 5157]</query>
   </localfile>
   ```

2. Add Sysmon and PowerShell Operational:

   ```xml
   <localfile>
     <location>Microsoft-Windows-Sysmon/Operational</location>
     <log_format>eventchannel</log_format>
   </localfile>

   <localfile>
     <location>Microsoft-Windows-PowerShell/Operational</location>
     <log_format>eventchannel</log_format>
   </localfile>
   ```

```powershell
Get-Service -DisplayName 'Wazuh*' | Restart-Service
```

**Verify (victim):**

```powershell
$log = 'C:\Program Files (x86)\ossec-agent\ossec.log'
Select-String -Path $log -Pattern 'Connected to the server' | Select-Object -Last 1
Select-String -Path $log -Pattern 'Analyzing event log' | Select-Object -Last 5
# expect lines for Security, Microsoft-Windows-Sysmon/Operational, Microsoft-Windows-PowerShell/Operational
Select-String -Path $log -Pattern 'ERROR' | Select-Object -Last 5          # expect none new
```

**Verify (manager):**

```bash
sudo /var/ossec/bin/agent_control -l           # agent listed as Active
# Docker: docker exec <manager-container> /var/ossec/bin/agent_control -l
```

---

## 8. Design decision: query raw events from `wazuh-archives-*`

**Problem.** `wazuh-alerts-*` only holds events for which a native Wazuh rule fired at or above
`log_alert_level` (default 3). Most Sysmon, 4104 and 4688 events match only base rules at level 0, so
they never reach the alerts index. Sigma queries need the **raw** decoded events.

**Decision.**
- **Detection queries** (converted Sigma) run against `wazuh-archives-*`, which holds every decoded
  event because `logall_json` is enabled.
- **Baseline comparison.** "Did Wazuh's default ruleset alert?" is answered from `wazuh-alerts-*` for
  the same time window and agent.

**Cost.** Archives store every event. Expect several GB/day per busy Windows host. Use a retention
policy (below), and check disk on the Wazuh VM.

### 8.1 Manager: enable `logall_json`

`/var/ossec/etc/ossec.conf` on the manager:

```xml
<ossec_config>
  <global>
    ...
    <logall>no</logall>
    <logall_json>yes</logall_json>
  </global>
</ossec_config>
```

```bash
sudo systemctl restart wazuh-manager
sudo tail -n 1 /var/ossec/logs/archives/archives.json | python3 -m json.tool | head -40
```

### 8.2 Filebeat: ship the archives fileset

`/etc/filebeat/filebeat.yml` on the manager (all-in-one):

```yaml
filebeat.modules:
  - module: wazuh
    alerts:
      enabled: true
    archives:
      enabled: true
```

```bash
sudo systemctl restart filebeat
sudo filebeat test output
```

**Docker (wazuh-docker single-node):** the manager config is mounted from
`config/wazuh_cluster/wazuh_manager.conf`, so add `logall_json` there and restart the manager
container. Filebeat runs inside the manager container. If you edit `/etc/filebeat/filebeat.yml` inside
the container, the change is lost when the container is recreated, so bind-mount an edited copy.
*The mount path differs between wazuh-docker releases, so check the release you deployed before
relying on this.*

### 8.3 Verify the index exists and is filling

```bash
curl -k -u admin "https://<WAZUH_IP>:9200/_cat/indices/wazuh-archives-*?v&s=index"
# expect wazuh-archives-4.x-YYYY.MM.DD with docs.count increasing
```

Optional: in the dashboard, go to Dashboards Management → Index patterns and create
`wazuh-archives-*` with time field `timestamp`.

### 8.4 Optional: retention for archives (ISM)

Applies only to indices created after the policy exists. Do not delete archives that `evaluate.py` has
not yet processed.

```
PUT _plugins/_ism/policies/detection-lab-archives-retention
{
  "policy": {
    "description": "Delete wazuh-archives indices after 14 days",
    "default_state": "hot",
    "states": [
      { "name": "hot", "actions": [],
        "transitions": [ { "state_name": "delete", "conditions": { "min_index_age": "14d" } } ] },
      { "name": "delete", "actions": [ { "delete": {} } ], "transitions": [] }
    ],
    "ism_template": [ { "index_patterns": ["wazuh-archives-*"], "priority": 100 } ]
  }
}
```

### 8.5 Indexer access from the host

Port `9200` must be reachable from the host, and only from `<HOSTONLY_SUBNET>`. The admin account is
enough for Gate A. Before Phase 4, create a read-only user scoped to
`wazuh-archives-*` and `wazuh-alerts-*`, and put it in `.env`.

---

## 9. Atomic Red Team staging

During the provisioning window, install Invoke-AtomicRedTeam and the atomics folder to
`C:\AtomicRedTeam`, following the official Atomic Red Team wiki. Configure any Microsoft Defender
setting for that folder yourself, from Microsoft's documentation. Keep it scoped to
`C:\AtomicRedTeam` only, and record the exact setting here: `<record scope + date>`.

Then detach NAT, re-run the section 1 isolation checks, and take the `02-art-ready` snapshot.

---

## 10. Gate A: telemetry verification (host)

1. Copy `.env.example` to `.env` and fill it in. `TLS_VERIFY` accepts `true`, `false`, or a path to
   the Wazuh `root-ca.pem`.
2. On the victim, generate ordinary activity for about 10 minutes: open Edge and Notepad, run a few
   PowerShell commands, and run the `dl-4104-check` / `dl-4688-check` commands from sections 4–5.
3. On the host:

   ```powershell
   .\.venv\Scripts\python.exe scripts\verify_telemetry.py
   # if some Sysmon IDs are missing, widen the window before concluding it's a gap:
   .\.venv\Scripts\python.exe scripts\verify_telemetry.py --minutes 60
   ```

Exit codes: `0` = all event types present, `1` = some missing, `2` = config, connectivity, or
no events from the agent at all.

Field names in this repo's pipeline come **only** from this script's output against real data.

---

## Version record

| Component                 | Version / ID | Recorded on |
|---------------------------|--------------|-------------|
| Hypervisor                |              |             |
| Windows 11 eval build     |              |             |
| Eval expiry (`slmgr /dli`)|              |             |
| Sysmon                    |              |             |
| sysmon-modular commit SHA |              |             |
| sysmonconfig.xml SHA256   |              |             |
| Wazuh manager / indexer   |              |             |
| Wazuh agent               |              |             |
| Invoke-AtomicRedTeam      |              |             |
| atomics folder commit     |              |             |
