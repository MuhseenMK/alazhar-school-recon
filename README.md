# alazhar-school-recon
Passive footprinting &amp; reconnaissance report on alazharschoolkano.com using Kali Linux tools
# 📡 Footprinting & Reconnaissance Report — `alazharschoolkano.com`

> **Course:** Cybersecurity & Ethical Hacking  
> **Target:** `alazharschoolkano.com` (`162.241.85.111`)  
> **Assessment Type:** Passive Reconnaissance & Risk Analysis  
> **Date:** 2026-09-15  
> **Author:** *[Muhammad Muhsin Khamis]*  
> **Scope:** Publicly available information only — **no exploitation performed**

> ⚠️ **Disclaimer:** This report is for **educational purposes only**. It uses only passive, public-source reconnaissance. Do not test, scan, or exploit any system without explicit **written authorization** from the owner. Unauthorized access is illegal.

---

## 📑 Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Target Profile](#2-target-profile)
3. [Tool-by-Tool Reconnaissance](#3-tool-by-tool-reconnaissance)
4. [Vulnerability Ratings](#4-vulnerability-ratings)
5. [Overall Risk Rating](#5-overall-risk-rating)
6. [Attacker's Kill Chain](#6-attackers-kill-chain)
7. [Recommendations](#7-recommendations)
8. [Final Verdict](#8-final-verdict)
9. [Screenshots](#9-screenshots)
10. [Tools Used](#10-tools-used)

---

## 1. Executive Summary

Passive reconnaissance was performed against `alazharschoolkano.com` using six built-in Kali Linux tools: **whois, whatweb, nslookup, curl, wafw00f, and dnsrecon**. None of these tools touch the target directly — they only read **publicly available information**.

**Key findings:**
- The site is hosted on **WebHostBox / cPanel** with IP `162.241.85.111`.
- Web server is **nginx 1.29.8** behind an **Apache** backend.
- **ModSecurity (SpiderLabs) WAF** is active.
- DNS server runs **BIND 9.11.4-P2** (old, RedHat).
- **Multiple high/critical risks** were identified based on observed versions.

**Verdict:** The site is **not a hard target**. If the hosting stack is unpatched, an attacker could achieve **full server compromise** via cPanel, or cause a **domain-wide outage** via BIND/nginx DoS.

---

## 2. Target Profile

| Item | Value |
|---|---|
| Domain | `alazharschoolkano.com` |
| Registrar | OwnRegistrar, Inc. |
| Created | 2022-06-23 |
| Expires | 2027-06-23 |
| Hosting Provider | WebHostBox (cPanel) |
| Name Servers | `cns4001.webhostbox.net`, `cns4002.webhostbox.net` |
| Web Server | nginx/1.29.8 (Apache behind) |
| WAF | ModSecurity (SpiderLabs) |
| DNS Server | BIND 9.11.4-P2 (RedHat) |
| Mail Server | `mail.alazharschoolkano.com` → same IP |
| IP Address | `162.241.85.111` |
| Country | United States (US) |
| Cookies Observed | `rm_session`, `school_cookie_name` |

---

## 3. Tool-by-Tool Reconnaissance

### Task 1 — WHOIS (Domain Registration)

**Command:**
```bash
whois alazharschoolkano.com
```

**Key Output:**

| Field | Value |
|---|---|
| Domain Name | ALAZHARSCHOOLKANO.COM |
| Registry Domain ID | 2705942169_DOMAIN_COM-VRSN |
| Registrar WHOIS Server | whois.ownregistrar.com |
| Registrar URL | http://www.ownregistrar.com |
| Updated Date | 2026-06-25T11:27:01Z |
| Creation Date | 2022-06-23T12:06:28Z |
| Registry Expiry Date | 2027-06-23T12:06:28Z |
| Registrar | OwnRegistrar, Inc. |
| Registrar IANA ID | 1250 |
| Registrar Abuse Email | abuse@ownregistrar.com |
| Registrar Abuse Phone | +1.2124016235 |
| Domain Status | clientTransferProhibited |
| Name Server 1 | CNS4001.WEBHOSTBOX.NET |
| Name Server 2 | CNS4002.WEBHOSTBOX.NET |
| DNSSEC | unsigned |

**Attacker Insight:** Reveals registrar, hosting provider (**WebHostBox**), and domain lifecycle. The domain expires **June 2027** — a future takeover opportunity if not renewed. Abuse contact enables social engineering.

---

### Task 2 — whatweb (Web Technology Fingerprint)

**Command:**
```bash
whatweb alazharschoolkano.com
```

**Key Output:**
```
http://alazharschoolkano.com [200 OK]
Bootstrap, Cookies[rm_session,school_cookie_name],
Country[UNITED STATES][US], HTML5,
HTTPServer[nginx/1.29.8],
HttpOnly[rm_session],
IP[162.241.85.111],
JQuery, Script,
Title[404 Page Not Found],
UncommonHeaders[x-server-cache,x-proxy-cache],
nginx[1.29.8]
```

**Attacker Insight:**
- Exposes server software: **nginx 1.29.8**.
- Real IP: **162.241.85.111**.
- Cookies `rm_session` and `school_cookie_name` suggest a **custom PHP school management system** (not WordPress).
- **404 title** suggests the root URL redirects or uses a non-standard homepage path.

---

### Task 3 — nslookup (Domain → IP Resolution)

**Command:**
```bash
nslookup alazharschoolkano.com
```

**Key Output:**
```
Server:         8.8.8.8
Address:        8.8.8.8#53

Non-authoritative answer:
Name:   alazharschoolkano.com
Address: 162.241.85.111
```

**Attacker Insight:** Confirms real IP `162.241.85.111`. Enables direct server scanning, reverse-IP lookups for neighboring sites, and infrastructure mapping.

---

### Task 4 — curl -I (HTTP Response Headers)

**Command:**
```bash
curl -I https://alazharschoolkano.com
```

**Key Output:**
```http
HTTP/2 200
expires: Thu, 19 Nov 1981 08:52:00 GMT
cache-control: no-store, no-cache, must-revalidate
pragma: no-cache
set-cookie: school_cookie_name=f2afe8507c95194dd503811c324910b1; expires=Tue, 15-Sep-2026 02:00:49 GMT; Max-Age=7200; path=/; SameSite=Strict
set-cookie: rm_session=e0d0f9477b0bfcd0555f0605070f1fa7624d9ce8; expires=Tue, 15-Sep-2026 02:00:49 GMT; Max-Age=7200; path=/; HttpOnly; SameSite=Lax
content-type: text/html; charset=UTF-8
date: Tue, 15 Sep 2026 00:00:49 GMT
server: Apache
```

**Attacker Insight:**
- Server banner leaks: **Apache** (nginx likely reverse proxy).
- `rm_session` has `HttpOnly` ✔ — but **`school_cookie_name` does NOT** ✘ → **XSS cookie theft vector**.
- The **1981 expiry** is a classic PHP session default (`session.cookie_lifetime = 0`).
- `SameSite=Strict` on one cookie but `Lax` on the other — inconsistent hardening.

---

### Task 5 — wafw00f (WAF Detection)

**Command:**
```bash
wafw00f alazharschoolkano.com
```

**Key Output:**
```
[*] Checking https://alazharschoolkano.com
[+] The site https://alazharschoolkano.com is behind ModSecurity (SpiderLabs) WAF.
[~] Number of requests: 2
```

**Attacker Insight:** Confirms **ModSecurity** is active. Naive SQLi/XSS payloads will be blocked — but ModSecurity itself has known bypasses (see V4 below).

---

### Task 6 — dnsrecon (DNS Enumeration)

**Command:**
```bash
dnsrecon -d alazharschoolkano.com
```

**Key Output:**
```
[*] SOA cns4001.webhostbox.net 162.241.85.109
[*] NS  cns4001.webhostbox.net 162.241.85.109
[*] Bind Version for 162.241.85.109 "9.11.4-P2-RedHat-9.11.4-26.P2.el7_9.9"
[*] NS  cns4002.webhostbox.net 162.241.85.110
[*] Bind Version for 162.241.85.110 "9.11.4-P2-RedHat-9.11.4-26.P2.el7_9.9"
[*] MX  mail.alazharschoolkano.com 162.241.85.111
[*] A   alazharschoolkano.com 162.241.85.111
[*] TXT alazharschoolkano.com v=spf1 ip4:162.241.85.100 a mx include:websitewelcome.com ~all
[*] SRV _carddavs._tcp.alazharschoolkano.com cs2001.webhostbox.net 162.241.85.100 2080
[*] SRV _autodiscover._tcp.alazharschoolkano.com cpanelemaildiscovery.cpanel.net 184.94.204.x 443
[*] SRV _caldav._tcp.alazharschoolkano.com cs2001.webhostbox.net 162.241.85.100 2079
[*] SRV _carddav._tcp.alazharschoolkano.com cs2001.webhostbox.net 162.241.85.100 2079
[*] SRV _caldavs._tcp.alazharschoolkano.com cs2001.webhostbox.net 162.241.85.100 2080
[*] 12 Records Found
```

**Attacker Insight:**
- **BIND 9.11.4-P2** — old, RedHat, possible CVEs.
- Web and mail on **same IP** (`162.241.85.111`) → single point of failure.
- **SPF `~all`** = soft fail → weak email policy → phishing risk.
- **No DNSSEC** → DNS cache-poisoning / spoofing risk.
- cPanel SRV records confirm **cPanel hosting**.

---

## 4. Vulnerability Ratings

**Rating Scale:**  
🔴 Critical = 9.0–10.0 | 🟠 High = 7.0–8.9 | 🟡 Medium = 4.0–6.9 | 🟢 Low = 0.1–3.9

| ID | Vulnerability | Evidence | Severity | CVSS | Impact |
|---|---|---|---|---|---|
| **V1** | cPanel/WHM auth bypass (CVE-2026-41940) | `webhostbox.net`, cPanel SRV records | 🔴 **Critical** | 9.8 | Full root compromise of hosting account |
| **V2** | Outdated BIND 9.11.4-P2 (CVE-2018-5740) | `dnsrecon` output | 🟠 **High** | 7.5 | DNS server crash → domain-wide outage |
| **V3** | Outdated nginx 1.29.8 HTTP/2 DoS (CVE-2026-49975) | `whatweb` output | 🟠 **High** | 7.5 | Website denial of service |
| **V4** | ModSecurity WAF bypass (CVE-2026-21876 / CVE-2026-52747) | `wafw00f` detected ModSecurity | 🟠 **High** | 8.1 | WAF bypass → SQLi/XSS delivery |
| **V5** | Cookie `school_cookie_name` missing `HttpOnly` | `curl -I` output | 🟡 **Medium** | 6.1 | Session theft via XSS |
| **V6** | Weak SPF record (`~all`) | `dnsrecon` TXT record | 🟡 **Medium** | 5.3 | Email spoofing / phishing |
| **V7** | Information disclosure via headers & WHOIS | `curl`, `whois` | 🟢 **Low** | 3.7 | Aids attacker reconnaissance |
| **V8** | Web and mail on same IP | `nslookup`, `dnsrecon` | 🟢 **Low** | 4.0 | Single point of failure |
| **V9** | No DNSSEC | `dnsrecon` — no answer | 🟢 **Low** | 3.7 | DNS spoofing / cache poisoning |

> **Note:** CVSS scores are approximate. CVE references correspond to known risks for the observed versions — verify against vendor advisories before acting.

---

### Vulnerability Details

#### 🔴 V1 — cPanel / WHM Authentication Bypass
The hosting environment is **cPanel** (confirmed by `webhostbox.net` nameservers and `cpanel.net` SRV records).  
**CVE-2026-41940** is a pre-authentication bypass with CVSS **9.8**, caused by a **CRLF injection** in the session writer, granting **root-level access**.

#### 🟠 V2 — Outdated BIND
**BIND 9.11.4-P2** is vulnerable to **CVE-2018-5740** (assertion failure → DNS process crash). Impact: complete DoS for website, email, and all domain services.

#### 🟠 V3 — Outdated nginx
**nginx 1.29.8** affected by **CVE-2026-49975** (HTTP/2 memory allocation flaw → DoS). Impact: site becomes unavailable.

#### 🟠 V4 — ModSecurity Bypass
Recent CVEs (**CVE-2026-21876**, **CVE-2026-52747**) allow multipart/line-break based bypasses. Impact: deliver SQLi/XSS past the WAF.

#### 🟡 V5 — Missing `HttpOnly`
`school_cookie_name` lacks `HttpOnly`. Any XSS can steal it → session hijacking.

#### 🟡 V6 — Weak SPF
`~all` = soft fail. Attacker can send **spoofed emails** as `@alazharschoolkano.com`.

#### 🟢 V7–V9 — Low-Risk Findings
Information disclosure, co-located services, and missing DNSSEC all reduce attacker effort and enable chained attacks.

---

## 5. Overall Risk Rating

> ### **Conditional: 🔴 CRITICAL if cPanel is unpatched. Otherwise 🟠 HIGH.**

The highest-value target is **V1 — cPanel/WHM auth bypass**. If unpatched, an attacker gains **root without authentication**.  
If cPanel is patched, the site remains **High risk** due to outdated BIND, nginx, and WAF bypass possibilities.

---

## 6. Attacker's Kill Chain

```
1. Recon          → discover IP, hosting, versions, DNS, mail
2. Exploit cPanel → root access → full control of website/email/DB
3. If patched     → exploit BIND or nginx for DoS → site down
4. If WAF bypassed → XSS → steal school_cookie_name → session hijack
5. Weak SPF       → phishing emails impersonating the school
```

---

## 7. Recommendations

| # | Recommendation | Priority |
|---|---|---|
| 1 | Patch cPanel/WHM immediately | 🔴 Critical |
| 2 | Update BIND to supported version | 🟠 High |
| 3 | Update nginx to latest stable | 🟠 High |
| 4 | Add `HttpOnly`, `Secure`, `SameSite=Strict` to **all** cookies | 🟡 Medium |
| 5 | Harden SPF — change `~all` → `-all` | 🟡 Medium |
| 6 | Enable DNSSEC | 🟢 Low |
| 7 | Separate mail and web services onto different IPs | 🟢 Low |
| 8 | Hide server banners (`server_tokens off`) | 🟢 Low |
| 9 | Keep ModSecurity rules updated; test bypasses | 🟠 High |
| 10 | Monitor logs for exploitation attempts | 🟠 High |

---

## 8. Final Verdict

**Is `alazharschoolkano.com` vulnerable?**  
**Yes** — passive reconnaissance reveals multiple high- and critical-risk weaknesses.

- The most severe is the potential **cPanel authentication bypass (V1)** → full server compromise.
- Even without it, **outdated BIND and nginx** expose the site to DoS attacks.
- The **missing `HttpOnly` flag** on `school_cookie_name` and the **weak SPF** lower the barrier for XSS and phishing.

> ⚠️ **Do not attempt exploitation without explicit written authorization.**

---

## 9. Screenshots

### Screenshot 1 — WHOIS
![WHOIS](screenshots/whois.png)

### Screenshot 2 — whatweb & nslookup
![whatweb & nslookup](screenshots/whatweb-nslookup.png)

### Screenshot 3 — curl -I
![curl](screenshots/curl.png)

### Screenshot 4 — wafw00f & dnsrecon
![wafw00f & dnsrecon](screenshots/wafw00f-dnsrecon.png)

### Screenshot 5 — dnsrecon SRV Records
![dnsrecon SRV](screenshots/dnsrecon-srv.png)

### Screenshot 6 — WHOIS Terms / Connection Refused
![whois terms](screenshots/whois-terms.png)

---

## 10. Tools Used

| Tool | Purpose | Command |
|---|---|---|
| `whois` | Domain registration lookup | `whois alazharschoolkano.com` |
| `whatweb` | Web tech fingerprinting | `whatweb alazharschoolkano.com` |
| `nslookup` | Domain → IP resolution | `nslookup alazharschoolkano.com` |
| `curl` | HTTP header inspection | `curl -I https://alazharschoolkano.com` |
| `wafw00f` | WAF detection | `wafw00f alazharschoolkano.com` |
| `dnsrecon` | DNS enumeration | `dnsrecon -d alazharschoolkano.com` |

---

## 📚 References

- ICANN WHOIS Status Codes: https://icann.org/epp
- OWASP WSTG — Information Gathering
- NIST SP 800-115 — Technical Guide to Information Security Testing

---

**Report compiled by:** *[Muhammad Muhsin Khamis]*    
**Date:** 2026-09-15  
**License:** Educational use only — see disclaimer above.
