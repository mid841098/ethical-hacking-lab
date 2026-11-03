# Target Verification & Isolated Scope Confirmation

**Track:** Ethical Hacking (Task 2: Local Reconnaissance and Attack Surface Map)  
**Assessor:** Authorized Security Intern  
**Target URI:** `http://127.0.0.1:3000`  
**Host Scope:** Workstation Localhost (RFC 1122 Loopback)  
**Verification Date:** November 03, 2026  

---

## 1. Target Address Recording

Before initializing reconnaissance tools or port discovery commands, the target address was recorded and validated against the signed **Rules of Engagement (RoE)**:

- **Target Domain / Hostname:** `localhost` / `127.0.0.1`
- **Assigned Service Port:** TCP Port `3000`
- **Target Protocol:** HTTP/1.1
- **Interface Identifier:** Local Loopback Adapter (`lo` / `MS TCP Loopback interface`)
- **MAC Address / Physical Wire:** None (Virtual software bus)
- **External Public Exposure:** **ZERO** (Strictly bound to `127.0.0.1`, not `0.0.0.0`)

---

## 2. Technical Evidence of Loopback Containment

The following checks confirm that the target resides strictly inside the isolated local laboratory:

### Check 1: DNS Resolution & Loopback IP Mapping
```powershell
Resolve-DnsName -Name localhost
```
**Output:**
```text
Name       Type TTL Section IPAddress
----       ---- --- ------- ---------
localhost  A    -   Answer  127.0.0.1
localhost  AAAA -   Answer  ::1
```
*Conclusion:* `localhost` resolves strictly to internal loopback pointers.

### Check 2: Socket State & Bound Interface Inspection
```powershell
Get-NetTCPConnection -LocalPort 3000 | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State
```
**Output:**
```text
LocalAddress LocalPort RemoteAddress RemotePort State
------------ --------- ------------- ---------- -----
127.0.0.1    3000      0.0.0.0       0          Listen
```
*Conclusion:* The socket is bound explicitly to `127.0.0.1`. It does not listen on the host's LAN address (`10.42.149.115`) or any public adapter.

### Check 3: Packet Routing Table Inspection
```powershell
Get-NetRoute -DestinationPrefix "127.0.0.1/32"
```
**Output:**
```text
DestinationPrefix NextHop RouteMetric InterfaceAlias
----------------- ------- ----------- --------------
127.0.0.1/32      0.0.0.0 256         Loopback Pseudo-Interface 1
```
*Conclusion:* Packets destined for `127.0.0.1` are routed exclusively through the internal loopback pseudo-interface. They cannot leave the machine.

---

## 3. Pre-Reconnaissance Authorization Sign-Off

- [x] Target address is confirmed to be `127.0.0.1:3000`.
- [x] Target is verified to be within the authorized test sandbox.
- [x] No external IP ranges or third-party hosts are targeted.
- [x] Rules of engagement are active and signed.
- [x] Low-rate, non-destructive tools only are configured.
