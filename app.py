import math
import re
import streamlit as st
import plotly.graph_objects as go
from zxcvbn import zxcvbn

# ==========================================
# 1. PAGE CONFIGURATION & STYLING
# ==========================================
st.set_page_config(
    page_title="Password Security Advisor Agent",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom Styling
st.markdown("""
    <style>
    .metric-card {
        background-color: #1E222D;
        padding: 15px;
        border-radius: 10px;
        border: 1px solid #2E3440;
        text-align: center;
    }
    .stProgress > div > div > div > div {
        border-radius: 10px;
    }
    </style>
""", unsafe_allow_html=True)


# ==========================================
# 2. CORE SECURITY CALCULATIONS & ANALYSIS
# ==========================================
def calculate_entropy(password):
    """Calculates Shannon entropy in bits."""
    if not password:
        return 0.0
    
    pool_size = 0
    if re.search(r'[a-z]', password):
        pool_size += 26
    if re.search(r'[A-Z]', password):
        pool_size += 26
    if re.search(r'[0-9]', password):
        pool_size += 10
    if re.search(r'[^a-zA-Z0-9]', password):
        pool_size += 32
        
    if pool_size == 0:
        return 0.0
        
    entropy = len(password) * math.log2(pool_size)
    return round(entropy, 2)


def evaluate_corporate_policy(password, min_length, req_upper, req_lower, req_digits, req_specials):
    """Checks password against explicit corporate policy compliance rules."""
    checks = {
        f"Minimum Length ({min_length} chars)": len(password) >= min_length,
        "Contains Uppercase Letter": bool(re.search(r'[A-Z]', password)) if req_upper else True,
        "Contains Lowercase Letter": bool(re.search(r'[a-z]', password)) if req_lower else True,
        "Contains Number": bool(re.search(r'[0-9]', password)) if req_digits else True,
        "Contains Special Character": bool(re.search(r'[^a-zA-Z0-9]', password)) if req_specials else True,
    }
    compliant = all(checks.values())
    return compliant, checks


# ==========================================
# 3. AI REMEDIATION AGENT (GROQ)
# ==========================================
def run_ai_advisor_agent(api_key, model_name, password, zxcvbn_res, entropy, compliance_status):
    """AI Agent that analyzes weak password patterns and provides actionable improvement strategies."""
    if not api_key:
        return """⚠️ **Groq API Key not detected.** 
        
*General Agent Advice:*
1. **Increase Length:** Use at least 12–16 characters (e.g., passphrases).
2. **Avoid Common Substitutions:** Replacing 'a' with '@' or 'e' with '3' is easily cracked by dictionary tools.
3. **Mix Character Types:** Combine uppercase, lowercase, numbers, and symbols."""

    try:
        from groq import Groq
        client = Groq(api_key=api_key)
        
        score = zxcvbn_res['score']
        warnings = zxcvbn_res['feedback']['warning']
        suggestions = zxcvbn_res['feedback']['suggestions']
        crack_time = zxcvbn_res['crack_times_display']['offline_slow_hashing_1e4_per_second']
        
        prompt = f"""
        You are a Cybersecurity Password Security Agent. Analyze the following password characteristics and give concise, high-value advice on how the user can improve their security without revealing or storing sensitive secrets.

        Password Evaluation Metrics:
        - ZXCVBN Strength Score: {score}/4
        - Calculated Entropy: {entropy} bits
        - Offline Crack Time Estimate: {crack_time}
        - Warning: {warnings if warnings else 'None'}
        - Detected Weaknesses: {', '.join(suggestions) if suggestions else 'None'}
        - Corporate Policy Compliant: {compliance_status}

        Provide:
        1. **Vulnerability Analysis**: Explain why this password layout is strong or weak in plain English.
        2. **Actionable Fixes**: Give 3 structural advice tips (e.g., recommend multi-word passphrases instead of complex short strings).
        3. **DO NOT** output actual plain-text password recommendations to avoid leakage.
        """
        
        response = client.chat.completions.create(
            model=model_name,
            messages=[
                {"role": "system", "content": "You are a professional cybersecurity consultant giving helpful password guidance."},
                {"role": "user", "content": prompt}
            ],
            temperature=0.5
        )
        return response.choices[0].message.content
    except Exception as e:
        return f"Agent Error: {str(e)}"


# ==========================================
# 4. STREAMLIT UI & SIDEBAR
# ==========================================
st.sidebar.title("⚙️ Security Agent Config")

st.sidebar.subheader("⚡ AI Engine Settings")
groq_api_key = st.sidebar.text_input("🔑 Groq API Key (Optional)", type="password", help="Enables the AI Security Advisor Agent for smart feedback.")
groq_model = st.sidebar.selectbox("Groq Model", ["llama-3.3-70b-versatile", "llama-3.1-8b-instant", "mixtral-8x7b-32768"])

st.sidebar.subheader("🏢 Corporate Policy Rules")
min_len = st.sidebar.slider("Min Password Length", 8, 32, 12)
req_upper = st.sidebar.checkbox("Require Uppercase (A-Z)", value=True)
req_lower = st.sidebar.checkbox("Require Lowercase (a-z)", value=True)
req_digits = st.sidebar.checkbox("Require Numbers (0-9)", value=True)
req_specials = st.sidebar.checkbox("Require Special Symbols (!@#$)", value=True)


# ==========================================
# 5. MAIN CONTENT AREA
# ==========================================
st.title("🛡️ Password Security Advisor & Analysis Agent")
st.caption("Evaluate password strength, entropy, crack time, and corporate compliance with AI-powered security guidance.")

password_input = st.text_input("Enter a password to analyze:", type="password", help="Analyzed entirely locally in memory. Never saved or logged.")

if password_input:
    # Run Security Diagnostics
    res = zxcvbn(password_input)
    entropy = calculate_entropy(password_input)
    score = res['score']  # 0 to 4
    is_compliant, policy_checks = evaluate_corporate_policy(
        password_input, min_len, req_upper, req_lower, req_digits, req_specials
    )

    score_labels = {0: "Very Weak", 1: "Weak", 2: "Fair", 3: "Strong", 4: "Very Strong"}
    score_colors = {0: "#FF4B4B", 1: "#FFA500", 2: "#FACC15", 3: "#22C55E", 4: "#10B981"}

    st.markdown("---")
    
    # 📊 Key Metrics Dashboard
    m1, m2, m3, m4 = st.columns(4)
    m1.metric("Strength Score", f"{score} / 4 ({score_labels[score]})")
    m2.metric("Entropy", f"{entropy} bits")
    m3.metric("Length", f"{len(password_input)} chars")
    m4.metric("Policy Status", "Pass ✅" if is_compliant else "Fail ❌")

    # Visual Gauge Chart for Strength
    fig = go.Figure(go.Indicator(
        mode="gauge+number",
        value=score,
        domain={'x': [0, 1], 'y': [0, 1]},
        title={'text': "Security Score", 'font': {'size': 20}},
        gauge={
            'axis': {'range': [0, 4], 'tickwidth': 1, 'tickcolor': "white"},
            'bar': {'color': score_colors[score]},
            'steps': [
                {'range': [0, 1], 'color': '#331111'},
                {'range': [1, 2], 'color': '#332211'},
                {'range': [2, 3], 'color': '#333311'},
                {'range': [3, 4], 'color': '#113311'},
            ],
        }
    ))
    fig.update_layout(height=220, margin=dict(l=20, r=20, t=30, b=20), paper_bgcolor="rgba(0,0,0,0)")

    col_chart, col_details = st.columns([1, 1])

    with col_chart:
        st.plotly_chart(fig, use_container_width=True)

    with col_details:
        st.subheader("⏱️ Estimated Crack Time")
        crack_times = res['crack_times_display']
        
        st.write(f"• **Online Fast Attack (100 per sec):** `{crack_times['online_throttled_100_per_hour']}`")
        st.write(f"• **Offline Fast Hashing (10B per sec):** `{crack_times['offline_fast_hashing_1e10_per_second']}`")
        st.write(f"• **Offline Slow Hashing (10k per sec):** `{crack_times['offline_slow_hashing_1e4_per_second']}`")

    st.markdown("---")

    # Policy & Pattern Breakdown
    col_pol, col_patt = st.columns(2)

    with col_pol:
        st.subheader("📋 Corporate Policy Compliance Check")
        for check_name, passed in policy_checks.items():
            status_icon = "✅" if passed else "❌"
            st.write(f"{status_icon} **{check_name}**")

    with col_patt:
        st.subheader("🔍 Pattern & Weakness Findings")
        warning = res['feedback']['warning']
        suggestions = res['feedback']['suggestions']

        if warning:
            st.error(f"**Warning:** {warning}")
        else:
            st.success("No common dictionary pattern warnings detected.")

        if suggestions:
            st.info("**Detected Issues:**")
            for sug in suggestions:
                st.write(f"• {sug}")

    st.markdown("---")

    # 🤖 AI Remediation Agent Section
    st.subheader("🤖 AI Security Advisor Agent Guidance")
    if st.button("💬 Run AI Analysis Agent"):
        with st.spinner("Agent analyzing password security posture..."):
            agent_feedback = run_ai_advisor_agent(
                groq_api_key, groq_model, password_input, res, entropy, "PASSED" if is_compliant else "FAILED"
            )
            st.markdown(agent_feedback)
else:
    st.info("👆 Enter a password in the box above to get instant feedback and security metrics.")
