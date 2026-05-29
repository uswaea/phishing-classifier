import streamlit as st
import joblib
import numpy as np
from urllib.parse import urlparse
import re

# Load model, scaler, features
model = joblib.load('best_model.pkl')
scaler = joblib.load('scaler.pkl')
feature_names = joblib.load('feature_names.pkl')

def extract_features(url):
    parsed = urlparse(url)
    domain = parsed.netloc
    path = parsed.path
    full = url

    features = {
        'URLLength': len(full),
        'DomainLength': len(domain),
        'IsDomainIP': 1 if re.match(r'^\d{1,3}(\.\d{1,3}){3}$', domain) else 0,
        'TLDLegitimateProb': 0.5,
        'URLCharProb': len(re.findall(r'[a-zA-Z0-9]', full)) / len(full) if len(full) > 0 else 0,
        'TLDLength': len(domain.split('.')[-1]) if '.' in domain else 0,
        'NoOfSubDomain': max(0, len(domain.split('.')) - 2),
        'HasObfuscation': 1 if '%' in full or '0x' in full else 0,
        'ObfuscationRatio': full.count('%') / len(full) if len(full) > 0 else 0,
        'IsHTTPS': 1 if parsed.scheme == 'https' else 0,
        'LineOfCode': 0,
        'LargestLineLength': 0,
        'DegitRatioInURL': len(re.findall(r'\d', full)) / len(full) if len(full) > 0 else 0,
        'LetterRatioInURL': len(re.findall(r'[a-zA-Z]', full)) / len(full) if len(full) > 0 else 0,
        'SpacialCharRatioInURL': len(re.findall(r'[^a-zA-Z0-9]', full)) / len(full) if len(full) > 0 else 0,
        'CharContinuationRate': 0.5,
        'NoOfLettersInURL': len(re.findall(r'[a-zA-Z]', full)),
        'NoOfDegitsInURL': len(re.findall(r'\d', full)),
        'NoOfEqualsInURL': full.count('='),
        'NoOfQMarkInURL': full.count('?'),
        'NoOfAmpersandInURL': full.count('&'),
        'NoOfOtherSpecialCharsInURL': len(re.findall(r'[^a-zA-Z0-9\-._~:/?#\[\]@!$&\'()*+,;=%]', full))
    }

    return np.array([features[f] for f in feature_names]).reshape(1, -1)


# ── PAGE CONFIG ──────────────────────────────────────────────────────────────
st.set_page_config(page_title="Phishing URL Classifier", page_icon="🔐", layout="centered")

# ── GLOBAL CSS ───────────────────────────────────────────────────────────────
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Press+Start+2P&family=VT323:wght@400&family=Share+Tech+Mono&display=swap');

/* ── base ── */
html, body, [class*="css"] {
    background-color: #0a0a0f !important;
    color: #e0e0ff !important;
    font-family: 'Share Tech Mono', monospace !important;
}

/* ── scanline overlay ── */
body::before {
    content: "";
    position: fixed;
    top: 0; left: 0; width: 100%; height: 100%;
    background: repeating-linear-gradient(
        0deg,
        transparent,
        transparent 2px,
        rgba(0,0,0,0.07) 2px,
        rgba(0,0,0,0.07) 4px
    );
    pointer-events: none;
    z-index: 9999;
}

/* ── hide streamlit chrome ── */
#MainMenu, footer, header {visibility: hidden;}
.block-container {padding-top: 2rem !important; max-width: 760px !important;}

/* ── pixel title ── */
.pixel-title {
    font-family: 'Press Start 2P', monospace;
    font-size: 1.45rem;
    color: #cc99ff;
    text-shadow: 4px 4px 0px #330055, 0 0 30px #aa55ff33;
    -webkit-text-stroke: 1px #9944cc;
    text-align: center;
    letter-spacing: 3px;
    margin-bottom: 0.5rem;
    line-height: 2;
}

.pixel-subtitle {
    font-family: 'VT323', monospace;
    font-size: 1.35rem;
    color: #556677;
    text-align: center;
    letter-spacing: 4px;
    margin-bottom: 2.5rem;
}

/* ── pixel frame / card ── */
.pixel-card {
    background: #0d0d1a;
    border: 3px solid #00ffcc;
    box-shadow: 4px 4px 0px #005544, 0 0 20px #00ffcc22;
    padding: 1.5rem 1.8rem;
    margin-bottom: 1.2rem;
    image-rendering: pixelated;
    position: relative;
}

/* ── result boxes ── */
.result-phishing {
    background: #1a0505;
    border: 3px solid #ff3355;
    box-shadow: 4px 4px 0px #550011, 0 0 20px #ff335544;
    padding: 1.2rem 1.5rem;
    font-family: 'Share Tech Mono', monospace;
    font-size: 1rem;
    color: #ff6677;
    line-height: 1.9;
    animation: blink-border 1s step-end infinite;
}

.result-suspicious {
    background: #1a1200;
    border: 3px solid #ffcc00;
    box-shadow: 4px 4px 0px #554400, 0 0 20px #ffcc0044;
    padding: 1.2rem 1.5rem;
    font-family: 'Share Tech Mono', monospace;
    font-size: 1rem;
    color: #ffdd55;
    line-height: 1.9;
}

.result-safe {
    background: #041408;
    border: 3px solid #00ff88;
    box-shadow: 4px 4px 0px #004422, 0 0 20px #00ff8844;
    padding: 1.2rem 1.5rem;
    font-family: 'Share Tech Mono', monospace;
    font-size: 1rem;
    color: #44ffaa;
    line-height: 1.9;
}

@keyframes blink-border {
    0%, 100% { border-color: #ff3355; }
    50%       { border-color: #ff335588; }
}

/* ── confidence bar ── */
.conf-label {
    font-family: 'VT323', monospace;
    font-size: 1.1rem;
    color: #7788aa;
    margin-bottom: 4px;
}

.conf-bar-wrap {
    background: #111122;
    border: 2px solid #334455;
    height: 18px;
    width: 100%;
    margin-bottom: 0.8rem;
    image-rendering: pixelated;
}

.conf-bar-fill {
    height: 100%;
    background: repeating-linear-gradient(
        90deg,
        #00ffcc 0px, #00ffcc 8px,
        #009977 8px, #009977 10px
    );
    transition: width 0.4s steps(10);
}

/* ── stat grid ── */
.stat-grid {
    display: grid;
    grid-template-columns: 1fr 1fr 1fr;
    gap: 10px;
    margin-top: 1rem;
}

.stat-box {
    background: #080814;
    border: 2px solid #223344;
    padding: 0.6rem 0.8rem;
    text-align: center;
    position: relative;
}

.stat-box::after {
    content: '';
    position: absolute;
    bottom: 0; right: 0;
    width: 6px; height: 6px;
    background: #00ffcc;
}

.stat-label {
    font-family: 'VT323', monospace;
    font-size: 1.05rem;
    color: #8899aa;
    display: block;
    margin-bottom: 6px;
    text-transform: uppercase;
    letter-spacing: 1px;
}

.stat-value {
    font-family: 'Share Tech Mono', monospace;
    font-size: 1rem;
    font-weight: bold;
    color: #00ffcc;
}

.stat-value.warn { color: #ffdd44; }
.stat-value.safe { color: #44ffaa; }
.stat-value.danger { color: #ff5577; }

/* ── section label ── */
.section-label {
    font-family: 'VT323', monospace;
    font-size: 1rem;
    color: #445566;
    letter-spacing: 3px;
    text-transform: uppercase;
    margin-bottom: 0.5rem;
}

/* ── hide empty input label box ── */
.stTextInput > label {display: none !important;}
.stTextInput > div {margin-top: 0 !important;}

/* ── input override ── */
.stTextInput > div > div > input {
    background: #080814 !important;
    border: 2px solid #00ffcc !important;
    border-radius: 0 !important;
    color: #00ffcc !important;
    font-family: 'Share Tech Mono', monospace !important;
    font-size: 1rem !important;
    padding: 0.6rem 1rem !important;
    box-shadow: 3px 3px 0px #005544 !important;
}

.stTextInput > div > div > input::placeholder {
    color: #334455 !important;
}

.stTextInput > div > div > input:focus {
    box-shadow: 3px 3px 0px #005544, 0 0 12px #00ffcc44 !important;
    outline: none !important;
}

/* ── button override ── */
.stButton > button {
    background: #00ffcc !important;
    color: #000 !important;
    font-family: 'Press Start 2P', monospace !important;
    font-size: 0.65rem !important;
    border: none !important;
    border-radius: 0 !important;
    padding: 0.75rem 2rem !important;
    box-shadow: 4px 4px 0px #005544 !important;
    letter-spacing: 1px;
    transition: all 0.05s steps(2) !important;
    width: 100%;
}

.stButton > button:hover {
    background: #00ddaa !important;
    box-shadow: 2px 2px 0px #005544 !important;
    transform: translate(2px, 2px) !important;
}

.stButton > button:active {
    transform: translate(4px, 4px) !important;
    box-shadow: 0px 0px 0px #005544 !important;
}

/* ── pixel corner decorations ── */
.corner-deco {
    font-family: 'VT323', monospace;
    font-size: 0.8rem;
    color: #00ffcc33;
    display: flex;
    justify-content: space-between;
    margin-bottom: -0.5rem;
}

/* ── footer ── */
.pixel-footer {
    font-family: 'VT323', monospace;
    font-size: 1.2rem;
    color: #334455;
    text-align: center;
    letter-spacing: 2px;
    margin-top: 2rem;
    padding-top: 1rem;
    border-top: 1px solid #112233;
    line-height: 1.8;
}

/* ── mobile responsive ── */
@media (max-width: 600px) {
    .pixel-title { font-size: 0.75rem !important; }
    .pixel-subtitle { font-size: 1rem !important; }
    .stat-grid { grid-template-columns: 1fr 1fr !important; }
    .result-phishing, .result-suspicious, .result-safe { font-size: 0.85rem !important; }
    .block-container { padding-left: 1rem !important; padding-right: 1rem !important; }
}
[data-testid="stMetricDelta"] { display: none; }
[data-testid="stMetric"] {
    background: #080814;
    border: 2px solid #223344;
    padding: 0.5rem;
}
</style>
""", unsafe_allow_html=True)


# ── HEADER ───────────────────────────────────────────────────────────────────
st.markdown('<div class="pixel-title">🔐 PHISHING URL CLASSIFIER</div>', unsafe_allow_html=True)
st.markdown('<div class="pixel-subtitle">stay safe out there. don\'t click random links. 🛡️</div>', unsafe_allow_html=True)

# ── INPUT CARD ───────────────────────────────────────────────────────────────
st.markdown('<div class="section-label">&gt;&gt; ENTER TARGET URL</div>', unsafe_allow_html=True)
url_input = st.text_input("", placeholder="https://example.com", label_visibility="collapsed")
classify_btn = st.button("[ SCAN URL ]")

# ── CLASSIFICATION ───────────────────────────────────────────────────────────
if classify_btn:
    if not url_input.strip():
        st.markdown('<div class="result-suspicious">⚠ PLEASE ENTER A URL FIRST</div>', unsafe_allow_html=True)
    else:
        # Auto-prepend https:// if missing
        url_input = url_input.strip()
        if not url_input.startswith("http://") and not url_input.startswith("https://"):
            url_input = "https://" + url_input
        # Validate it looks like a real URL after prepending
        parsed_check = urlparse(url_input)
        netloc = parsed_check.netloc
        tld_valid = re.match(r'^[^.]+\.[a-zA-Z]{2,}', netloc)
        if not tld_valid or not re.match(r'^https?://[^\s/$.?#].[^\s]*$', url_input):
            st.markdown('<div class="result-suspicious">⚠ INVALID INPUT<br>PLEASE ENTER A VALID URL<br>e.g. google.com or https://example.com</div>', unsafe_allow_html=True)
        else:
            features = extract_features(url_input)
            features_scaled = scaler.transform(features)
            probability = model.predict_proba(features_scaled)[0]
            confidence = max(probability) * 100
            predicted_class = model.predict(features_scaled)[0]

            is_https = url_input.startswith("https")
            has_hyphen_domain = "-" in urlparse(url_input).netloc
            high_subdomains = url_input.count(".") >= 3
            many_special = len([c for c in url_input if not c.isalnum() and c not in [".", "/", ":", "-"]]) >= 3
            has_brand_impersonation = any(brand in url_input.lower() for brand in ["paypal", "amazon", "google", "netflix", "microsoft", "apple", "bank"])
            has_ip = bool(re.match(r".*\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}.*", url_input))

            suspicious_signals = sum([has_hyphen_domain, high_subdomains, many_special, has_brand_impersonation])

            if predicted_class == 1 and suspicious_signals >= 2:
                verdict = "suspicious"
                confidence = min(confidence, 65)
                st.markdown('<div class="result-suspicious">⚠ SUSPICIOUS DETECTED<br>STRUCTURE LOOKS UNUSUAL<br>PROCEED WITH CAUTION</div>', unsafe_allow_html=True)
            elif predicted_class == 0:
                verdict = "phishing"
                st.markdown('<div class="result-phishing">☠ PHISHING DETECTED<br>THIS URL IS MALICIOUS<br>DO NOT PROCEED</div>', unsafe_allow_html=True)
            else:
                verdict = "safe"
                st.markdown('<div class="result-safe">✓ LEGITIMATE URL<br>NO THREATS DETECTED<br>SAFE TO PROCEED</div>', unsafe_allow_html=True)

            # Confidence bar
            st.markdown(f"""
            <div style="margin-top:1.2rem;">
                <div class="conf-label">CONFIDENCE: {confidence:.1f}%</div>
                <div class="conf-bar-wrap">
                    <div class="conf-bar-fill" style="width:{confidence}%;"></div>
                </div>
            </div>
            """, unsafe_allow_html=True)

            # Stat grid
            def sv(val, good_val=None, bad_val=None):
                if good_val is not None and val == good_val:
                    return "safe"
                if bad_val is not None and val == bad_val:
                    return "danger"
                return "warn"

            url_len = len(url_input)
            subdomains = url_input.count(".") - 1
            special_chars = len([c for c in url_input if not c.isalnum()])

            https_cls = "safe" if is_https else "danger"
            hyph_cls = "danger" if has_hyphen_domain else "safe"
            ip_cls = "danger" if has_ip else "safe"
            len_cls = "danger" if url_len > 75 else "safe"
            sub_cls = "danger" if subdomains > 2 else ("warn" if subdomains > 1 else "safe")
            sp_cls = "danger" if special_chars > 8 else ("warn" if special_chars > 4 else "safe")

            st.markdown(f"""
            <div style="margin-top:1rem;">
                <div class="section-label">&gt;&gt; URL ANALYSIS</div>
                <div class="stat-grid">
                    <div class="stat-box">
                        <span class="stat-label">URL LENGTH</span>
                        <span class="stat-value {len_cls}">{url_len}</span>
                    </div>
                    <div class="stat-box">
                        <span class="stat-label">IS HTTPS</span>
                        <span class="stat-value {https_cls}">{"YES ✓" if is_https else "NO ✗"}</span>
                    </div>
                    <div class="stat-box">
                        <span class="stat-label">SUBDOMAINS</span>
                        <span class="stat-value {sub_cls}">{subdomains}</span>
                    </div>
                    <div class="stat-box">
                        <span class="stat-label">SPECIAL CHARS</span>
                        <span class="stat-value {sp_cls}">{special_chars}</span>
                    </div>
                    <div class="stat-box">
                        <span class="stat-label">IP ADDRESS</span>
                        <span class="stat-value {ip_cls}">{"YES ✗" if has_ip else "NO ✓"}</span>
                    </div>
                    <div class="stat-box">
                        <span class="stat-label">HYPHEN DOMAIN</span>
                        <span class="stat-value {hyph_cls}">{"YES ✗" if has_hyphen_domain else "NO ✓"}</span>
                    </div>
                </div>
            </div>
            """, unsafe_allow_html=True)

# ── FOOTER ───────────────────────────────────────────────────────────────────
st.markdown("""
<div style="margin-top: 3rem; font-family: 'VT323', monospace;">
    <div style="border: 1px solid #1a2e3a; background: #070710; padding: 1.2rem 1.5rem; position: relative; box-shadow: 0 0 30px #0a1520;">
        <div style="position: absolute; top: -0.6rem; left: 1rem; background: #070710; padding: 0 0.5rem; font-size: 1rem; color: #2a4455; letter-spacing: 3px;">SYSTEM LOG</div>
        <div style="font-size: 1.15rem; color: #4a6677; letter-spacing: 2px; margin-bottom: 0.4rem;">&gt; Model_Status: <span style="color:#667f8f;">Active</span></div>
        <div style="font-size: 1.15rem; color: #4a6677; letter-spacing: 2px; margin-bottom: 0.4rem;">&gt; Training_Data: <span style="color:#667f8f;">235,795 URLs · PhiUSIIL Dataset</span></div>
        <div style="font-size: 1.15rem; color: #4a6677; letter-spacing: 2px; margin-bottom: 0.4rem;">&gt; Note: <span style="color:#667f8f;">trained so you don't have to click sus links 🫡</span></div>
        <div style="font-size: 1.15rem; color: #4a6677; letter-spacing: 2px; margin-bottom: 0.4rem;">&gt; Built_With: <span style="color:#667f8f;">🖤 &amp; sleep deprivation</span></div>
        <div style="border-top: 1px solid #1a2e3a; margin-top: 0.9rem; padding-top: 0.9rem; font-size: 1.15rem; color: #4a6677; letter-spacing: 2px;">&gt; Built_By: <span style="color:#c9a0ff; font-weight:bold; margin-left:0.5rem; letter-spacing:3px;">USWA</span> <span style="color:#2a3d4a; margin: 0 0.4rem;">·</span> <span style="color:#ff99cc; font-weight:bold; letter-spacing:3px;">NAWAL</span> <span style="color:#2a3d4a; margin: 0 0.4rem;">·</span> <span style="color:#ffdd77; font-weight:bold; letter-spacing:3px;">TANIA</span></div>
    </div>
</div>
""", unsafe_allow_html=True)