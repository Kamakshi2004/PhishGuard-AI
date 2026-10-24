"""
PhishGuard AI — Phishing URL Detection System
Features: single-URL analysis, history, risk chart, downloadable report,
          bulk CSV analysis, explainable risk score.
Run: streamlit run app.py
"""

import re
import math
import io
import csv
import datetime
import streamlit as st
import pandas as pd
from urllib.parse import urlparse

# ──────────────────────────────────────────────
#  Page config  (must be the very first Streamlit call)
# ──────────────────────────────────────────────
st.set_page_config(
    page_title="PhishGuard AI",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed",
)

# ──────────────────────────────────────────────
#  Global CSS — dark dashboard theme
# ──────────────────────────────────────────────
st.markdown(
    """
    <style>
    /* ── Base ── */
    html, body, [data-testid="stAppViewContainer"] {
        background-color: #0d1117;
        color: #e6edf3;
        font-family: 'Segoe UI', system-ui, sans-serif;
    }
    [data-testid="stHeader"] { background: transparent; }
    [data-testid="stSidebar"] { background-color: #161b22; }

    /* ── Metric cards ── */
    div[data-testid="metric-container"] {
        background: #161b22;
        border: 1px solid #30363d;
        border-radius: 12px;
        padding: 20px 24px;
    }
    div[data-testid="metric-container"] label {
        color: #8b949e !important;
        font-size: 0.82rem;
        text-transform: uppercase;
        letter-spacing: 0.06em;
    }
    div[data-testid="metric-container"] [data-testid="stMetricValue"] {
        color: #e6edf3 !important;
        font-size: 2rem !important;
        font-weight: 700;
    }

    /* ── Input box ── */
    input[type="text"], .stTextInput input {
        background-color: #161b22 !important;
        color: #e6edf3 !important;
        border: 1px solid #30363d !important;
        border-radius: 8px !important;
    }

    /* ── Primary button ── */
    .stButton > button {
        background: linear-gradient(135deg, #238636, #2ea043);
        color: #ffffff;
        border: none;
        border-radius: 8px;
        padding: 0.55rem 2rem;
        font-size: 1rem;
        font-weight: 600;
        cursor: pointer;
        width: 100%;
        transition: opacity 0.2s;
    }
    .stButton > button:hover { opacity: 0.88; }

    /* ── Result card ── */
    .result-card {
        background: #161b22;
        border: 1px solid #30363d;
        border-radius: 12px;
        padding: 28px 32px;
        margin-top: 24px;
    }
    .risk-badge {
        display: inline-block;
        padding: 4px 16px;
        border-radius: 20px;
        font-weight: 700;
        font-size: 1rem;
        margin-left: 10px;
        vertical-align: middle;
    }
    .badge-high   { background: #3d1a1a; color: #f85149; border: 1px solid #f85149; }
    .badge-medium { background: #2d2000; color: #e3b341; border: 1px solid #e3b341; }
    .badge-low    { background: #0d2a1a; color: #3fb950; border: 1px solid #3fb950; }

    /* ── Score bar ── */
    .score-bar-bg {
        background: #21262d;
        border-radius: 8px;
        height: 14px;
        margin: 10px 0 4px;
        overflow: hidden;
    }
    .score-bar-fill {
        height: 100%;
        border-radius: 8px;
        transition: width 0.4s ease;
    }

    /* ── Indicators list ── */
    .indicator-item {
        display: flex;
        align-items: flex-start;
        gap: 10px;
        padding: 8px 0;
        border-bottom: 1px solid #21262d;
        font-size: 0.92rem;
    }
    .indicator-item:last-child { border-bottom: none; }
    .dot-high   { color: #f85149; font-size: 1.2rem; line-height: 1.3; }
    .dot-medium { color: #e3b341; font-size: 1.2rem; line-height: 1.3; }
    .dot-low    { color: #3fb950; font-size: 1.2rem; line-height: 1.3; }

    /* ── Section headers ── */
    .section-title {
        font-size: 0.78rem;
        text-transform: uppercase;
        letter-spacing: 0.08em;
        color: #8b949e;
        margin: 22px 0 8px;
    }

    /* ── Divider ── */
    hr { border-color: #21262d !important; }

    /* ── History table ── */
    .history-table {
        width: 100%;
        border-collapse: collapse;
        font-size: 0.88rem;
        margin-top: 8px;
    }
    .history-table th {
        background: #21262d;
        color: #8b949e;
        text-transform: uppercase;
        font-size: 0.75rem;
        letter-spacing: 0.06em;
        padding: 10px 12px;
        text-align: left;
        border-bottom: 1px solid #30363d;
    }
    .history-table td {
        padding: 9px 12px;
        border-bottom: 1px solid #21262d;
        color: #e6edf3;
        word-break: break-all;
    }
    .history-table tr:last-child td { border-bottom: none; }
    .history-table tr:hover td     { background: #1c2128; }

    /* ── Score breakdown table ── */
    .breakdown-table {
        width: 100%;
        border-collapse: collapse;
        font-size: 0.86rem;
        margin-top: 6px;
    }
    .breakdown-table th {
        background: #21262d;
        color: #8b949e;
        font-size: 0.74rem;
        text-transform: uppercase;
        letter-spacing: 0.05em;
        padding: 8px 10px;
        text-align: left;
        border-bottom: 1px solid #30363d;
    }
    .breakdown-table td {
        padding: 7px 10px;
        border-bottom: 1px solid #21262d;
        color: #e6edf3;
    }
    .breakdown-table tr:last-child td { border-bottom: none; }
    .pts-high   { color: #f85149; font-weight: 700; }
    .pts-medium { color: #e3b341; font-weight: 700; }
    .pts-low    { color: #3fb950; font-weight: 700; }

    /* ── Bulk results dataframe overrides ── */
    [data-testid="stDataFrame"] {
        background: #161b22 !important;
        border: 1px solid #30363d;
        border-radius: 10px;
    }
    </style>
    """,
    unsafe_allow_html=True,
)

# ──────────────────────────────────────────────
#  Session state
# ──────────────────────────────────────────────
for key, default in [
    ("total", 0), ("high", 0), ("medium", 0), ("low", 0),
    ("history", []),          # Feature 1 – analysis history
    ("last_result", None),    # last single-URL result for the report download
]:
    if key not in st.session_state:
        st.session_state[key] = default

# ──────────────────────────────────────────────
#  Phishing detection logic  (pure Python rules)
# ──────────────────────────────────────────────
SUSPICIOUS_TLDS = {
    ".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".club",
    ".online", ".site", ".icu", ".pw", ".cc", ".work", ".click",
}

BRAND_KEYWORDS = [
    "paypal", "apple", "amazon", "google", "microsoft", "netflix",
    "facebook", "instagram", "bank", "secure", "account", "login",
    "verify", "update", "confirm", "signin", "password", "ebay",
    "wellsfargo", "chase", "citibank", "irs", "gov-",
]

IP_PATTERN = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")


def calculate_entropy(s: str) -> float:
    """Shannon entropy — high-entropy domains look randomly generated."""
    if not s:
        return 0.0
    freq = {c: s.count(c) / len(s) for c in set(s)}
    return -sum(p * math.log2(p) for p in freq.values())


def analyze_url(raw_url: str) -> dict:
    """
    Return a dict with keys:
      score (0-100), level, indicators, recommendations, breakdown
    'breakdown' is a list of (rule_name, points, severity, description)
    used for the Explainable Risk Score feature.
    """
    indicators = []   # list of (severity, message)
    breakdown  = []   # list of (rule, pts, severity, description)  ← Feature 5
    score      = 0

    def _add(pts, severity, short_rule, message):
        nonlocal score
        score += pts
        indicators.append((severity, message))
        breakdown.append((short_rule, pts, severity, message))

    # ── Normalise ──
    url = raw_url.strip()
    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    try:
        parsed = urlparse(url)
    except Exception:
        msg = "URL could not be parsed — likely malformed."
        return {
            "score": 100,
            "level": "High",
            "indicators": [("high", msg)],
            "recommendations": ["Do not visit this URL."],
            "breakdown": [("Parse Error", 100, "high", msg)],
        }

    hostname = parsed.hostname or ""
    path     = parsed.path or ""

    # Rule 1 — HTTP
    if parsed.scheme == "http":
        _add(10, "medium", "No HTTPS", "Uses HTTP instead of HTTPS — connection is unencrypted.")

    # Rule 2 — IP address
    if hostname and IP_PATTERN.match(hostname):
        _add(30, "high", "Raw IP Address",
             f"Hostname is a raw IP address ({hostname}) — legitimate sites use domain names.")

    # Rule 3 — Suspicious TLD
    for tld in SUSPICIOUS_TLDS:
        if hostname.endswith(tld):
            _add(20, "high", f"Suspicious TLD ({tld})",
                 f"Uses a high-risk free TLD '{tld}' commonly abused in phishing campaigns.")
            break

    # Rule 4 — Excessive subdomains
    parts = hostname.split(".")
    if len(parts) > 4:
        _add(15, "medium", "Excessive Subdomains",
             f"Unusually deep subdomain chain ({hostname}) — a common URL-hiding trick.")

    # Rule 5 — Brand keyword
    registered          = ".".join(parts[-2:]) if len(parts) >= 2 else hostname
    subdomain_and_path  = ".".join(parts[:-2]) + path.lower()
    for kw in BRAND_KEYWORDS:
        if kw in subdomain_and_path:
            _add(25, "high", f"Brand Keyword ({kw})",
                 f"Brand/sensitive keyword '{kw}' found in subdomain or path — classic impersonation signal.")
            break

    # Rule 6 — Hyphens
    hyphen_count = hostname.count("-")
    if hyphen_count >= 3:
        _add(15, "medium", f"Many Hyphens ({hyphen_count})",
             f"Domain contains {hyphen_count} hyphens — often used to mimic legitimate domains.")
    elif hyphen_count >= 1:
        score += 5  # minor penalty, no indicator shown

    # Rule 7 — URL length
    url_len = len(url)
    if url_len > 100:
        _add(15, "medium", f"Long URL ({url_len} chars)",
             f"URL is very long ({url_len} chars) — attackers add noise to obscure the real destination.")
    elif url_len > 75:
        score += 5

    # Rule 8 — High entropy
    domain_only = parts[0] if len(parts) == 1 else parts[-2]
    entropy = calculate_entropy(domain_only)
    if entropy > 3.8:
        _add(15, "medium", f"High Entropy ({entropy:.2f})",
             f"Domain '{domain_only}' has high character entropy ({entropy:.2f}) — may be algorithmically generated.")

    # Rule 9 — Sensitive path keywords
    path_keywords = ["login", "signin", "verify", "secure", "account",
                     "update", "confirm", "password", "wp-admin"]
    for kw in path_keywords:
        if kw in path.lower():
            _add(10, "medium", f"Path Keyword (/{kw})",
                 f"Path contains sensitive keyword '/{kw}' — frequently used in credential-harvesting pages.")
            break

    # Rule 10 — @ in URL
    if "@" in url:
        _add(30, "high", "@ Symbol in URL",
             "URL contains '@' — browsers ignore everything before '@', a deceptive redirect trick.")

    # Rule 11 — Double slash in path
    if "//" in path:
        _add(10, "medium", "Double Slash in Path",
             "Double-slash found in path — can be used to confuse URL parsers.")

    # ── Cap ──
    score = min(score, 100)

    # ── Level ──
    if score >= 60:
        level = "High"
    elif score >= 30:
        level = "Medium"
    else:
        level = "Low"

    recommendations = _build_recommendations(level, indicators)

    if not indicators:
        indicators.append(("low", "No obvious phishing signals detected in this URL."))

    return {
        "score": score,
        "level": level,
        "indicators": indicators,
        "recommendations": recommendations,
        "breakdown": breakdown,   # Feature 5
    }


def _build_recommendations(level: str, indicators: list) -> list:
    recs    = []
    sev_set = {i[0] for i in indicators}

    if level == "High":
        recs.append("🚫 Do NOT enter any personal information on this site.")
        recs.append("🔒 Close this page immediately if you navigated to it.")
        recs.append("📢 Report this URL to your IT/security team or phishtank.com.")
    elif level == "Medium":
        recs.append("⚠️  Proceed with caution — verify the site's legitimacy before entering credentials.")
        recs.append("🔍 Double-check the domain name against the official website.")
    else:
        recs.append("✅ URL appears relatively safe, but always stay vigilant.")
        recs.append("🔒 Ensure the padlock icon is visible in your browser's address bar.")

    if "high" in sev_set:
        recs.append("🛡️  Enable phishing protection in your browser (e.g. Google Safe Browsing).")
    if any("http" in i[1].lower() for i in indicators):
        recs.append("🔐 Prefer HTTPS sites — never submit passwords over HTTP.")

    return recs


# ──────────────────────────────────────────────
#  Helper — build downloadable text report      (Feature 3)
# ──────────────────────────────────────────────
def build_text_report(url: str, result: dict, timestamp: str) -> str:
    lines = [
        "=" * 62,
        "          PHISHGUARD AI — SECURITY ANALYSIS REPORT",
        "=" * 62,
        f"URL Analysed : {url}",
        f"Timestamp    : {timestamp}",
        f"Risk Level   : {result['level']}",
        f"Risk Score   : {result['score']} / 100",
        "",
        "── SUSPICIOUS INDICATORS ─────────────────────────────",
    ]
    for sev, msg in result["indicators"]:
        bullet = "⚠" if sev == "high" else ("•" if sev == "medium" else "✓")
        lines.append(f"  {bullet} [{sev.upper():6}]  {msg}")

    lines += [
        "",
        "── SCORE BREAKDOWN ───────────────────────────────────",
        f"  {'Rule':<28} {'Points':>6}  Severity",
        "  " + "-" * 44,
    ]
    for rule, pts, sev, _ in result.get("breakdown", []):
        lines.append(f"  {rule:<28} {pts:>+6}  {sev.upper()}")

    lines += [
        "",
        "── SAFETY RECOMMENDATIONS ────────────────────────────",
    ]
    for rec in result["recommendations"]:
        lines.append(f"  {rec}")

    lines += [
        "",
        "=" * 62,
        "  Generated by PhishGuard AI  |  For educational use only",
        "=" * 62,
    ]
    return "\n".join(lines)


# ──────────────────────────────────────────────
#  Helper — build bulk CSV bytes               (Feature 4)
# ──────────────────────────────────────────────
def build_bulk_csv(rows: list) -> bytes:
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["URL", "Risk Level", "Risk Score", "Indicators", "Timestamp"])
    for r in rows:
        indicators_text = " | ".join(msg for _, msg in r["indicators"])
        writer.writerow([
            r["url"],
            r["level"],
            r["score"],
            indicators_text,
            r["timestamp"],
        ])
    return buf.getvalue().encode("utf-8")


# ──────────────────────────────────────────────
#  Helper — risk-level badge (inline HTML)
# ──────────────────────────────────────────────
def badge(level: str) -> str:
    cls = f"badge-{level.lower()}"
    return f'<span class="risk-badge {cls}" style="margin-left:0;">{level}</span>'


# ══════════════════════════════════════════════
#  UI
# ══════════════════════════════════════════════

# ── Header ──────────────────────────────────
st.markdown(
    """
    <div style="padding: 12px 0 8px;">
        <h1 style="margin:0; font-size:2rem; font-weight:800; color:#e6edf3;">
            🛡️ PhishGuard <span style="color:#3fb950;">AI</span>
        </h1>
        <p style="margin:4px 0 0; color:#8b949e; font-size:0.95rem;">
            Real-time phishing URL analyser — no AI models, no external APIs, just smart rules.
        </p>
    </div>
    <hr>
    """,
    unsafe_allow_html=True,
)

# ── Dashboard metric cards ───────────────────
c1, c2, c3, c4 = st.columns(4)
c1.metric("🔍 Total Analysed", st.session_state["total"])
c2.metric("🔴 High Risk",      st.session_state["high"])
c3.metric("🟡 Medium Risk",    st.session_state["medium"])
c4.metric("🟢 Low Risk",       st.session_state["low"])

st.markdown("<hr>", unsafe_allow_html=True)

# ════════════════════════════════════════════════════════════════
#  TABS  — Single URL | Bulk Analysis | History | Chart
# ════════════════════════════════════════════════════════════════
tab_single, tab_bulk, tab_history, tab_chart = st.tabs([
    "🔍 Analyse URL",
    "📂 Bulk Analysis",
    "🕒 History",
    "📊 Risk Chart",
])

# ──────────────────────────────────────────────────────────────
#  TAB 1 — Single URL analysis
# ──────────────────────────────────────────────────────────────
with tab_single:
    st.markdown("### 🔗 Enter a URL to Analyse")
    url_input = st.text_input(
        label="URL",
        placeholder="e.g. https://paypal-secure-login.xyz/verify/account",
        label_visibility="collapsed",
        key="single_url_input",
    )

    analyze_clicked = st.button("🔍 Analyze URL", use_container_width=True, key="btn_analyze")

    if analyze_clicked:
        if not url_input.strip():
            st.warning("Please enter a URL before clicking Analyze.")
        else:
            result    = analyze_url(url_input)
            timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

            # ── Update counters ──
            st.session_state["total"] += 1
            st.session_state[result["level"].lower()] += 1

            # ── Save to history  (Feature 1) ──
            st.session_state["history"].insert(0, {
                "url":       url_input,
                "score":     result["score"],
                "level":     result["level"],
                "timestamp": timestamp,
                "result":    result,
            })

            # ── Save last result for report download  (Feature 3) ──
            st.session_state["last_result"] = {
                "url":       url_input,
                "result":    result,
                "timestamp": timestamp,
            }

            score = result["score"]
            level = result["level"]

            bar_color = "#f85149" if level == "High" else ("#e3b341" if level == "Medium" else "#3fb950")
            badge_class = f"badge-{level.lower()}"

            # ── Indicators HTML ──
            indicators_html = "".join(
                f'<div class="indicator-item">'
                f'  <span class="dot-{sev}">{"●" if sev == "high" else ("◉" if sev == "medium" else "○")}</span>'
                f'  <span>{msg}</span>'
                f'</div>'
                for sev, msg in result["indicators"]
            )

            # ── Recommendations HTML ──
            recs_html = "".join(
                f'<div style="padding:5px 0; font-size:0.92rem;">{r}</div>'
                for r in result["recommendations"]
            )

            # ── Feature 5: Score breakdown table ──
            breakdown_rows = "".join(
                f'<tr>'
                f'  <td>{rule}</td>'
                f'  <td class="pts-{sev}">+{pts}</td>'
                f'  <td><span class="dot-{sev}">{"●" if sev == "high" else ("◉" if sev == "medium" else "○")}</span> {sev.capitalize()}</td>'
                f'</tr>'
                for rule, pts, sev, _ in result["breakdown"]
            ) if result["breakdown"] else "<tr><td colspan='3' style='color:#8b949e;'>No rules triggered.</td></tr>"

            breakdown_html = f"""
            <table class="breakdown-table">
                <thead>
                    <tr>
                        <th>Rule Triggered</th>
                        <th>Points</th>
                        <th>Severity</th>
                    </tr>
                </thead>
                <tbody>{breakdown_rows}</tbody>
            </table>
            <div style="margin-top:8px; font-size:0.82rem; color:#8b949e;">
                Total before cap: {sum(p for _,p,_,_ in result['breakdown'])} pts
                &nbsp;→&nbsp; Capped score: <strong style="color:{bar_color};">{score}/100</strong>
            </div>
            """

            # ── Full result card ──
            st.markdown(
                f"""
                <div class="result-card">
                    <div style="display:flex; align-items:center; flex-wrap:wrap; gap:8px;">
                        <span style="font-size:1.15rem; font-weight:700; color:#e6edf3;">Analysis Result</span>
                        <span class="risk-badge {badge_class}">{level} Risk</span>
                        <span style="margin-left:auto; color:#8b949e; font-size:0.85rem; word-break:break-all;">
                            {url_input[:80]}{"…" if len(url_input) > 80 else ""}
                        </span>
                    </div>

                    <div class="section-title">Risk Score</div>
                    <div style="display:flex; align-items:center; gap:12px;">
                        <div class="score-bar-bg" style="flex:1;">
                            <div class="score-bar-fill"
                                 style="width:{score}%; background:{bar_color};"></div>
                        </div>
                        <span style="font-size:1.5rem; font-weight:800; color:{bar_color};">{score}/100</span>
                    </div>

                    <div class="section-title">Explainable Score Breakdown</div>
                    {breakdown_html}

                    <div class="section-title">Suspicious Indicators</div>
                    <div>{indicators_html}</div>

                    <div class="section-title">Safety Recommendations</div>
                    <div>{recs_html}</div>

                    <div style="margin-top:16px; font-size:0.8rem; color:#8b949e;">
                        Analysed at {timestamp}
                    </div>
                </div>
                """,
                unsafe_allow_html=True,
            )

            # ── Feature 3: Download report button ──
            report_text = build_text_report(url_input, result, timestamp)
            st.download_button(
                label="⬇️ Download Security Report (.txt)",
                data=report_text,
                file_name=f"phishguard_report_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.txt",
                mime="text/plain",
                use_container_width=True,
            )

            st.rerun()

    # ── Show last result's download button persistently ──
    elif st.session_state["last_result"]:
        lr = st.session_state["last_result"]
        report_text = build_text_report(lr["url"], lr["result"], lr["timestamp"])
        st.download_button(
            label="⬇️ Download Last Security Report (.txt)",
            data=report_text,
            file_name=f"phishguard_report_{lr['timestamp'].replace(' ', '_').replace(':', '')}.txt",
            mime="text/plain",
            use_container_width=True,
            key="dl_last_report",
        )


# ──────────────────────────────────────────────────────────────
#  TAB 2 — Bulk URL analysis  (Feature 4)
# ──────────────────────────────────────────────────────────────
with tab_bulk:
    st.markdown("### 📂 Bulk URL Analysis")
    st.markdown(
        "<p style='color:#8b949e; font-size:0.9rem;'>"
        "Upload a CSV file that contains a column named <code>URL</code>. "
        "All other columns are ignored.</p>",
        unsafe_allow_html=True,
    )

    uploaded_file = st.file_uploader(
        "Upload CSV",
        type=["csv"],
        label_visibility="collapsed",
        key="bulk_upload",
    )

    if uploaded_file is not None:
        # ── Parse the CSV ──
        try:
            df_input = pd.read_csv(uploaded_file)
        except Exception as e:
            st.error(f"Could not read the file: {e}")
            df_input = None

        if df_input is not None:
            # Check for 'URL' column (case-insensitive)
            col_map = {c.strip().lower(): c for c in df_input.columns}
            if "url" not in col_map:
                st.error(
                    "No column named **URL** found in the uploaded file. "
                    "Please add a column header `URL` to your CSV."
                )
            else:
                url_col   = col_map["url"]
                url_list  = df_input[url_col].dropna().astype(str).tolist()
                valid_urls = [u.strip() for u in url_list if u.strip()]

                if not valid_urls:
                    st.warning("The URL column is empty — nothing to analyse.")
                else:
                    st.info(f"Found **{len(valid_urls)}** URLs. Analysing…")
                    progress = st.progress(0)
                    bulk_rows = []

                    for idx, raw_url in enumerate(valid_urls):
                        res  = analyze_url(raw_url)
                        ts   = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                        bulk_rows.append({
                            "url":       raw_url,
                            "score":     res["score"],
                            "level":     res["level"],
                            "indicators": res["indicators"],
                            "timestamp": ts,
                        })
                        # Update global counters
                        st.session_state["total"] += 1
                        st.session_state[res["level"].lower()] += 1
                        # Also add to history
                        st.session_state["history"].insert(0, {
                            "url":       raw_url,
                            "score":     res["score"],
                            "level":     res["level"],
                            "timestamp": ts,
                            "result":    res,
                        })
                        progress.progress((idx + 1) / len(valid_urls))

                    progress.empty()
                    st.success(f"✅ Analysed {len(bulk_rows)} URLs.")

                    # ── Results table ──
                    display_df = pd.DataFrame([
                        {
                            "URL":        r["url"],
                            "Risk Level": r["level"],
                            "Score":      r["score"],
                            "# Indicators": len([i for i in r["indicators"] if i[0] != "low" or i[1].startswith("No obvious")]),
                            "Analysed At": r["timestamp"],
                        }
                        for r in bulk_rows
                    ])
                    st.dataframe(display_df, use_container_width=True, height=350)

                    # ── Download bulk CSV ──
                    bulk_csv_bytes = build_bulk_csv(bulk_rows)
                    st.download_button(
                        label="⬇️ Download Results as CSV",
                        data=bulk_csv_bytes,
                        file_name=f"phishguard_bulk_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                        mime="text/csv",
                        use_container_width=True,
                    )

                    st.rerun()


# ──────────────────────────────────────────────────────────────
#  TAB 3 — History  (Feature 1)
# ──────────────────────────────────────────────────────────────
with tab_history:
    st.markdown("### 🕒 URL Analysis History")

    history = st.session_state["history"]

    col_clear, col_spacer = st.columns([1, 4])
    with col_clear:
        if st.button("🗑️ Clear History", key="btn_clear_history"):
            st.session_state["history"] = []
            st.rerun()

    if not history:
        st.markdown(
            "<p style='color:#8b949e; margin-top:16px;'>No URLs analysed yet. "
            "Use the <em>Analyse URL</em> or <em>Bulk Analysis</em> tab to get started.</p>",
            unsafe_allow_html=True,
        )
    else:
        rows_html = "".join(
            f"<tr>"
            f"  <td style='color:#8b949e; font-size:0.8rem;'>{i+1}</td>"
            f"  <td style='max-width:360px;'>{h['url'][:80]}{'…' if len(h['url']) > 80 else ''}</td>"
            f"  <td>{badge(h['level'])}</td>"
            f"  <td style='font-weight:700; color:{'#f85149' if h['level']=='High' else ('#e3b341' if h['level']=='Medium' else '#3fb950')};'>"
            f"      {h['score']}/100</td>"
            f"  <td style='color:#8b949e; font-size:0.82rem; white-space:nowrap;'>{h['timestamp']}</td>"
            f"</tr>"
            for i, h in enumerate(history)
        )
        st.markdown(
            f"""
            <div style="overflow-x:auto;">
            <table class="history-table">
                <thead>
                    <tr>
                        <th>#</th>
                        <th>URL</th>
                        <th>Risk Level</th>
                        <th>Score</th>
                        <th>Timestamp</th>
                    </tr>
                </thead>
                <tbody>{rows_html}</tbody>
            </table>
            </div>
            """,
            unsafe_allow_html=True,
        )


# ──────────────────────────────────────────────────────────────
#  TAB 4 — Risk Distribution Chart  (Feature 2)
# ──────────────────────────────────────────────────────────────
with tab_chart:
    st.markdown("### 📊 Risk Distribution")

    high_n   = st.session_state["high"]
    medium_n = st.session_state["medium"]
    low_n    = st.session_state["low"]
    total_n  = st.session_state["total"]

    if total_n == 0:
        st.markdown(
            "<p style='color:#8b949e; margin-top:16px;'>No URLs analysed yet. "
            "Analyse some URLs first and come back here to see the distribution.</p>",
            unsafe_allow_html=True,
        )
    else:
        # ── Bar chart via Streamlit native (no extra deps) ──
        chart_df = pd.DataFrame({
            "Risk Level": ["🔴 High", "🟡 Medium", "🟢 Low"],
            "Count":      [high_n, medium_n, low_n],
        }).set_index("Risk Level")

        st.bar_chart(chart_df, color="#3b82d4", use_container_width=True, height=320)

        # ── Percentage breakdown ──
        st.markdown("<div class='section-title'>Percentage Breakdown</div>", unsafe_allow_html=True)
        pct_col1, pct_col2, pct_col3 = st.columns(3)

        def pct(n):
            return f"{(n / total_n * 100):.1f}%" if total_n else "0%"

        pct_col1.metric("🔴 High Risk",   f"{high_n} URLs",   pct(high_n))
        pct_col2.metric("🟡 Medium Risk", f"{medium_n} URLs", pct(medium_n))
        pct_col3.metric("🟢 Low Risk",    f"{low_n} URLs",    pct(low_n))

        # ── Recent trend ──
        history = st.session_state["history"]
        if len(history) >= 2:
            st.markdown("<div class='section-title' style='margin-top:24px;'>Score Trend (most recent 20)</div>",
                        unsafe_allow_html=True)
            recent = list(reversed(history[:20]))
            trend_df = pd.DataFrame({
                "URL #":  range(1, len(recent) + 1),
                "Score":  [h["score"] for h in recent],
            }).set_index("URL #")
            st.line_chart(trend_df, color="#3fb950", use_container_width=True, height=240)
