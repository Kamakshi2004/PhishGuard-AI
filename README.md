# 🛡️ PhishGuard AI — Phishing URL Detection System

A lightweight, browser-based cybersecurity tool that analyses website URLs in real time to detect potential phishing threats using a rule-based scoring engine. No external APIs, no database, no machine learning — just smart Python rules.

---

## 📸 Features

| Feature | Description |
|---|---|
| 🔍 **Single URL Analysis** | Enter any URL and get an instant risk score, badge, score bar, and safety recommendations |
| 📊 **Explainable Risk Score** | See exactly which rules fired and how many points each contributed |
| 🕒 **Analysis History** | Every analysed URL is saved in-session with timestamp, score, and risk level |
| 📈 **Risk Distribution Chart** | Live bar chart + score trend line showing the spread of High / Medium / Low results |
| ⬇️ **Downloadable Security Report** | Export a full `.txt` report per URL including breakdown, indicators, and recommendations |
| 📂 **Bulk URL Analysis** | Upload a CSV file with a `URL` column — analyse all entries, view results, download as CSV |

---

## 🚀 Quick Start (Windows)

### 1. Prerequisites

Make sure Python 3.8 or later is installed:

```powershell
py --version
```

### 2. Install dependencies (one-time)

```powershell
py -3 -m pip install streamlit pandas
```

### 3. Run the application

```powershell
py -3 -m streamlit run app.py
```

A browser window will open automatically at **`http://localhost:8501`**.  
To stop the server press **Ctrl + C** in the terminal.

---

## 📁 Project Structure

```
cybersecurity/
├── app.py                          # Entire application — single file
├── README.md                       # This file
└── PhishGuard_AI_Project_Report.docx  # Full project report
```

---

## 🧠 Detection Engine — 11 Rules

The `analyze_url()` function scores every URL against 11 independent heuristic rules. Scores are accumulated and capped at **100**.

| # | Rule | Points | Severity |
|---|---|---|---|
| 1 | HTTP instead of HTTPS | +10 | Medium |
| 2 | Raw IP address as hostname | +30 | High |
| 3 | Suspicious free TLD (`.tk`, `.xyz`, `.icu` …) | +20 | High |
| 4 | More than 4 subdomain levels | +15 | Medium |
| 5 | Brand / sensitive keyword in subdomain or path | +25 | High |
| 6 | 3 or more hyphens in domain name | +15 | Medium |
| 7 | URL length exceeds 100 characters | +15 | Medium |
| 8 | High Shannon entropy on domain name (> 3.8) | +15 | Medium |
| 9 | Sensitive keyword in URL path (`/login`, `/verify` …) | +10 | Medium |
| 10 | `@` symbol in URL | +30 | High |
| 11 | Double slash `//` in URL path | +10 | Medium |

**Risk levels:**

```
Score ≥ 60  →  🔴 High Risk
Score 30–59 →  🟡 Medium Risk
Score < 30  →  🟢 Low Risk
```

---

## 📂 Bulk Analysis — CSV Format

Upload a `.csv` file with at least one column named `URL` (case-insensitive):

```csv
URL
https://google.com
http://paypal-secure-login.xyz/verify/account
https://amazon-update.tk/signin
http://192.168.1.1/login
```

Results are displayed in an interactive table and can be downloaded as a new CSV containing the risk level, score, all indicators, and timestamp for each URL.

---

## 🧪 Sample Test Results

| URL | Risk Level | Score | Primary Trigger |
|---|---|---|---|
| `https://google.com` | 🟢 Low | 0 | No rules triggered |
| `https://github.com/features` | 🟢 Low | 0 | No rules triggered |
| `http://paypal-secure-login.xyz/verify` | 🔴 High | 100 | HTTP + TLD + brand keyword + hyphens + path keyword |
| `http://192.168.1.1/login` | 🔴 High | 50 | HTTP + raw IP address + path keyword |
| `https://amazon-update.tk/signin` | 🔴 High | 70 | Suspicious TLD + brand keyword + path keyword |
| `https://my-bank-account-verify-now.com/confirm` | 🟡 Medium | 50 | Brand keyword + many hyphens + path keyword |
| `http://user@evil.com/steal` | 🔴 High | 70 | HTTP + @ symbol in URL |

---

## 🗂️ Tech Stack

| Component | Technology |
|---|---|
| Web Framework | Streamlit 1.x |
| Language | Python 3.8+ |
| Data Manipulation | pandas 2.x |
| URL Parsing | `urllib.parse` (stdlib) |
| CSV / IO | `csv`, `io` (stdlib) |
| Regex | `re` (stdlib) |
| Math (entropy) | `math` (stdlib) |

---

## ⚠️ Limitations

- The rule engine cannot detect sophisticated phishing URLs that use legitimate-looking domains with clean TLDs.
- No network requests are made — the tool does not check live blocklists (Google Safe Browsing, PhishTank).
- History is stored in Streamlit session state only — it is lost when the browser tab is closed.
- Single-user by default (one session per browser tab).

---

## 🔮 Future Enhancements

- Integration with Google Safe Browsing or PhishTank API for live blocklist checking
- Machine-learning classification layer (Random Forest on ISCXURL2016 dataset)
- SQLite-backed persistent history across sessions
- WHOIS domain age lookup (newly registered domains are a strong phishing signal)
- Browser extension version for automatic tab URL analysis

---

## 📄 License

This project is for educational purposes only. Do not use it as a sole security measure in a production environment.

---

## 📚 References

1. Anti-Phishing Working Group (APWG) — [Phishing Activity Trends Report](https://apwg.org/trendsreports/)
2. Streamlit Documentation — [docs.streamlit.io](https://docs.streamlit.io/)
3. Python `urllib.parse` — [docs.python.org](https://docs.python.org/3/library/urllib.parse.html)
4. Shannon, C. E. (1948). *A Mathematical Theory of Communication.* Bell System Technical Journal, 27(3), 379–423.
5. Mohammad et al. (2014). *Predicting phishing websites based on self-structuring neural network.* Neural Computing and Applications.
6. ISCX URL 2016 Dataset — [University of New Brunswick](https://www.unb.ca/cic/datasets/url-2016.html)
