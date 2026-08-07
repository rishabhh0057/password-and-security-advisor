import math
import re
import hashlib
import requests
import string
import secrets
import streamlit as st
import plotly.graph_objects as go
from zxcvbn import zxcvbn

# ==========================================
# 1. PAGE CONFIGURATION & STYLING
# ==========================================
st.set_page_config(
    page_title="CyberSecurity Password Agent",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom Styling for modern look
st.markdown("""
    <style>
    .stTabs [data-baseweb="tab-list"] {
        gap: 20px;
    }
    .stTabs [data-baseweb="tab"] {
        height: 50px;
        white-space: pre-wrap;
        background-color: transparent;
        border-radius: 5px 5px 0px 0px;
        padding-top: 10px;
        padding-bottom: 10px;
        font-weight: 600;
    }
    .stTabs [aria-selected="true"] {
        background-color: rgba(34, 197, 94, 0.1);
        border-bottom: 2px solid #22C55E !important;
        color: #22C55E !important;
    }
    .metric-card {
        background-color: #1E1E1E;
        padding: 15px;
        border-radius: 10px;
        border: 1px solid #333;
        box-shadow: 0 4px 6px rgba(0,0,0,0.1);
    }
    </style>
""", unsafe_allow_html=True)


# ==========================================
# 2. CORE SECURITY FUNCTIONS
# ==========================================
def calculate_entropy(password):
    if not password: return 0.0
    pool_size = 0
    if re.search(r'[a-z]', password): pool_size += 26
    if re.search(r'[A-Z]', password): pool_size += 26
    if re.search(r'[0-9]', password): pool_size += 10
    if re.search(r'[^a-zA-Z0-9]', password): pool_size += 32
    if pool_size == 0: return 0.0
    return round(len(password) * math.log2(pool_size), 2)

def check_pwned_api(password):
    """Checks HaveIBeenPwned via k-Anonymity (safe, doesn't send full password)."""
    sha1_password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    head, tail = sha1_password[:5], sha1_password[5:]
    url = f"https://api.pwnedpasswords.com/range/{head}"
    try:
        response = requests.get(url, timeout=5)
        if response.status_code != 200: return -1
        hashes = (line.split(':') for line in response.text.splitlines())
        for h, count in hashes:
            if h == tail: return int(count)
        return 0
    except:
        return -1 # API failure

def generate_secure_password(length, use_upper, use_lower, use_digits, use_special):
    chars = ""
    if use_upper: chars += string.ascii_uppercase
    if use_lower: chars += string.ascii_lowercase
    if use_digits: chars += string.digits
    if use_special: chars += "!@#$%^&*()-_=+<>?"
    
    if not chars: return "Please select at least one character type."
    
    # Ensure at least one of each selected type is present
    password = []
    if use_upper: password.append(secrets.choice(string.ascii_uppercase))
    if use_lower: password.append(secrets.choice(string.ascii_lowercase))
    if use_digits: password.append(secrets.choice(string.digits))
    if use_special: password.append(secrets.choice("!@#$%^&*()-_=+<>?"))
    
    while len(password) < length:
        password.append(secrets.choice(chars))
        
    secrets.SystemRandom().shuffle(password)
    return "".join(password)


# ==========================================
# 3. AI REMEDIATION AGENT (GROQ)
# ==========================================
def run_ai_advisor_agent(api_key, model_name, password, zxcvbn_res, entropy):
    if not api_key:
        return "⚠️ **Groq API Key not detected.** Enter it in the sidebar to unlock AI guidance."

    try:
        from groq import Groq
        client = Groq(api_key=api_key)
        
        score = zxcvbn_res['score']
        warnings = zxcvbn_res['feedback']['warning']
        suggestions = zxcvbn_res['feedback']['suggestions']
        crack_time = zxcvbn_res.get('crack_times_display', {}).get('offline_slow_hashing_1e4_per_second', 'N/A')
        
        prompt = f"""
        You are an elite Cybersecurity Advisor. Analyze these metrics and give concise, expert advice:
        - Strength Score: {score}/4
        - Entropy: {entropy} bits
        - Crack Time Estimate: {crack_time}
        - Detected Weaknesses: {', '.join(suggestions) if suggestions else 'None'}
        
        Provide:
        1. **Vulnerability Analysis**: Why is this weak/strong?
        2. **Actionable Fixes**: 3 bullet points to improve it structurally.
        **DO NOT output actual password examples or repeat the user's password.**
        """
        
        response = client.chat.completions.create(
            model=model_name,
            messages=[{"role": "user", "content": prompt}],
            temperature=0.5
        )
        return response.choices[0].message.content
    except Exception as e:
        return f"Agent Error: {str(e)}"


# ==========================================
# 4. SIDEBAR CONFIGURATION
# ==========================================
st.sidebar.title("⚙️ Security Settings")

st.sidebar.subheader("🤖 AI Engine")
groq_api_key = st.sidebar.text_input("🔑 Groq API Key (Optional)", type="password")
groq_model = st.sidebar.selectbox("Groq Model", ["llama-3.3-70b-versatile", "llama-3.1-8b-instant", "mixtral-8x7b-32768"])

st.sidebar.markdown("---")
st.sidebar.info("💡 **Pro Tip:** Switch to the '🔐 Generator' tab to create cryptographically secure passphrases instantly.")


# ==========================================
# 5. MAIN UI - TABS
# ==========================================
st.title("🛡️ Ultimate Password Security Suite")
st.caption("Analyze vulnerabilities, generate secure keys, and check against global data breaches.")

# Initialize session state for password input across tabs
if "master_password" not in st.session_state:
    st.session_state.master_password = ""

tab1, tab2, tab3 = st.tabs(["🔍 Strength Analyzer & Breach Check", "🔐 Secure Generator", "🧰 Developer Tools & Hashes"])

# ------------------------------------------
# TAB 1: ANALYZER & BREACH CHECK
# ------------------------------------------
with tab1:
    password_input = st.text_input("Enter a password to analyze:", value=st.session_state.master_password, type="password", key="master_password")

    if password_input:
        # Run Diagnostics
        res = zxcvbn(password_input)
        entropy = calculate_entropy(password_input)
        score = res['score'] 
        
        score_labels = {0: "Critical Danger", 1: "Very Weak", 2: "Moderate", 3: "Strong", 4: "Unbreakable (Almost)"}
        score_colors = {0: "#FF4B4B", 1: "#FFA500", 2: "#FACC15", 3: "#22C55E", 4: "#10B981"}

        st.markdown("---")
        
        # 📊 Top Metrics
        c1, c2, c3, c4 = st.columns(4)
        c1.metric("🛡️ Security Score", f"{score} / 4", score_labels[score])
        c2.metric("🧩 Entropy", f"{entropy} bits")
        c3.metric("📏 Length", f"{len(password_input)} chars")
        
        # Gauge Chart
        fig = go.Figure(go.Indicator(
            mode="gauge+number",
            value=score,
            domain={'x': [0, 1], 'y': [0, 1]},
            title={'text': "Strength Meter", 'font': {'size': 20, 'color': 'white'}},
            gauge={
                'axis': {'range': [0, 4], 'tickwidth': 1, 'tickcolor': "white"},
                'bar': {'color': score_colors[score]},
                'steps': [
                    {'range': [0, 1], 'color': '#331111'},
                    {'range': [1, 2], 'color': '#442200'},
                    {'range': [2, 3], 'color': '#113311'},
                    {'range': [3, 4], 'color': '#004411'},
                ],
            }
        ))
        fig.update_layout(height=250, margin=dict(l=20, r=20, t=40, b=20), paper_bgcolor="rgba(0,0,0,0)")

        col_chart, col_details = st.columns([1, 1])
        with col_chart:
            st.plotly_chart(fig, use_container_width=True)

        with col_details:
            st.subheader("⏱️ Time to Crack")
            crack_times = res.get('crack_times_display', {})
            st.code(f"""
Online Attack (Throttled): {crack_times.get('online_throttled_100_per_hour', 'N/A')}
Offline Fast Hash (MD5):   {crack_times.get('offline_fast_hashing_1e10_per_second', 'N/A')}
Offline Slow Hash (Bcrypt):{crack_times.get('offline_slow_hashing_1e4_per_second', 'N/A')}
            """, language="text")

        st.markdown("---")
        
        # Analysis & Breach Section
        c_pwn, c_ai = st.columns(2)
        
        with c_pwn:
            st.subheader("🚨 Live Data Breach Check")
            st.caption("Checks the HaveIBeenPwned database securely using k-Anonymity.")
            if st.button("🔍 Check if breached"):
                with st.spinner("Querying breach database..."):
                    pwn_count = check_pwned_api(password_input)
                    if pwn_count > 0:
                        st.error(f"⚠️ **COMPROMISED!** This password has been seen in data breaches **{pwn_count:,} times**! Do not use it.")
                    elif pwn_count == 0:
                        st.success("✅ **Clean!** This password was not found in any known public data breaches.")
                    else:
                        st.warning("Could not reach the breach database at this time.")

            st.subheader("🔍 Local Pattern Feedback")
            if res['feedback']['warning']:
                st.warning(res['feedback']['warning'])
            for sug in res['feedback']['suggestions']:
                st.info(f"💡 {sug}")

        with c_ai:
            st.subheader("🤖 AI Security Agent")
            if st.button("💬 Generate AI Security Report"):
                with st.spinner("Analyzing threat vectors..."):
                    report = run_ai_advisor_agent(groq_api_key, groq_model, password_input, res, entropy)
                    st.markdown(f"> {report}")

# ------------------------------------------
# TAB 2: SECURE GENERATOR
# ------------------------------------------
with tab2:
    st.subheader("🛠️ Cryptographically Secure Password Generator")
    st.write("Generate military-grade passwords locally in your browser.")
    
    g_col1, g_col2 = st.columns([1, 2])
    
    with g_col1:
        pwd_len = st.slider("Password Length", min_value=8, max_value=64, value=16, step=1)
        inc_upper = st.checkbox("Uppercase (A-Z)", value=True)
        inc_lower = st.checkbox("Lowercase (a-z)", value=True)
        inc_nums = st.checkbox("Numbers (0-9)", value=True)
        inc_syms = st.checkbox("Symbols (!@#$)", value=True)
        
        if st.button("🚀 Generate Password", use_container_width=True):
            new_pwd = generate_secure_password(pwd_len, inc_upper, inc_lower, inc_nums, inc_syms)
            # Update session state so it automatically loads into Tab 1
            st.session_state.master_password = new_pwd
            st.rerun()

    with g_col2:
        st.info("Your generated password will appear in the Analyzer tab instantly. Try adjusting the length to see how it affects entropy and crack times!")
        if st.session_state.master_password:
            st.success("✅ Password generated and loaded into Analyzer!")
            st.code(st.session_state.master_password, language="text")

# ------------------------------------------
# TAB 3: DEV TOOLS & HASHES
# ------------------------------------------
with tab3:
    st.subheader("🧰 Developer Cryptography Toolkit")
    st.write("See how your password looks when processed through standard cryptographic hashing algorithms.")
    
    if st.session_state.master_password:
        pw = st.session_state.master_password.encode('utf-8')
        
        st.text("SHA-256 (Industry Standard)")
        st.code(hashlib.sha256(pw).hexdigest(), language="text")
        
        st.text("SHA-512 (High Security)")
        st.code(hashlib.sha512(pw).hexdigest(), language="text")
        
        st.text("SHA-1 (Deprecated / Vulnerable)")
        st.code(hashlib.sha1(pw).hexdigest(), language="text")
        
        st.text("MD5 (Broken / Highly Vulnerable)")
        st.code(hashlib.md5(pw).hexdigest(), language="text")
    else:
        st.warning("Go to the Analyzer tab and enter a password to see its hashes.")
