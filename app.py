# Step 1: Load Important modules
import re
import math
import hashlib
import secrets
import string
import requests
import pandas as pd
import streamlit as st
import altair as alt

from langchain_google_genai import ChatGoogleGenerativeAI
from langchain.agents import create_agent

# ============ Step 2: Tools (same logic as the notebook) ============

COMMON_PATTERNS = [r"1234", r"qwerty", r"asdf", r"password", r"letmein",
                   r"admin", r"welcome", r"abc123", r"iloveyou"]
KEYBOARD_WALKS = ["qwertyuiop", "asdfghjkl", "zxcvbnm", "1234567890"]


def _char_set_size(password):
    size = 0
    if re.search(r"[a-z]", password): size += 26
    if re.search(r"[A-Z]", password): size += 26
    if re.search(r"[0-9]", password): size += 10
    if re.search(r"[^a-zA-Z0-9]", password): size += 32
    return size or 1


def check_password_strength(password: str) -> dict:
    """Rule-based, deterministic strength check — no LLM involved."""
    charset = _char_set_size(password)
    entropy = round(len(password) * math.log2(charset), 2)
    issues = []
    lower = password.lower()

    for pattern in COMMON_PATTERNS:
        if re.search(pattern, lower):
            issues.append(f"contains common weak pattern '{pattern}'")
    for walk in KEYBOARD_WALKS:
        for i in range(len(walk) - 3):
            if walk[i:i + 4] in lower:
                issues.append(f"contains keyboard-walk sequence '{walk[i:i+4]}'")
                break
    if len(password) < 8:
        issues.append("shorter than recommended 8-character minimum")
    if password.lower() == password or password.upper() == password:
        issues.append("uses only one letter case")
    if not re.search(r"\d", password):
        issues.append("contains no digits")

    if entropy < 28: category = "very weak"
    elif entropy < 36: category = "weak"
    elif entropy < 60: category = "reasonable"
    elif entropy < 128: category = "strong"
    else: category = "excellent"

    base_score = min(100, round((entropy / 128) * 100))
    score = max(0, base_score - min(base_score, len(issues) * 12))

    return {"score": score, "entropy": entropy, "category": category,
            "issues": issues, "length": len(password)}


def check_breach_database(password: str) -> dict:
    """HIBP k-anonymity check — only a 5-char hash prefix leaves the machine."""
    sha1 = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]
    try:
        resp = requests.get(f"https://api.pwnedpasswords.com/range/{prefix}", timeout=5)
        resp.raise_for_status()
    except requests.RequestException as e:
        return {"checked": False, "breached": False, "count": 0, "error": str(e)}

    for line in resp.text.splitlines():
        hash_suffix, count = line.split(":")
        if hash_suffix == suffix:
            return {"checked": True, "breached": True, "count": int(count)}
    return {"checked": True, "breached": False, "count": 0}


def generate_strong_password(style: str = "passphrase") -> str:
    """Cryptographically secure generation — not LLM-derived, so entropy is guaranteed."""
    if style == "random":
        alphabet = string.ascii_letters + string.digits + "!@#$%^&*"
        return ''.join(secrets.choice(alphabet) for _ in range(16))
    wordlist = ["orbit", "maple", "quartz", "ember", "velvet", "cobalt",
                "harbor", "falcon", "lantern", "granite", "willow", "copper",
                "marble", "thicket", "ripple", "canyon", "ash", "drift"]
    words = [secrets.choice(wordlist) for _ in range(5)]
    return "-".join(words) + str(secrets.randbelow(90) + 10)


# ============ Step 3: LLM + Agent (cached so it's built once) ============

@st.cache_resource
def load_agent():
    api_key = st.secrets.get("GOOGLE_API_KEY", "")
    if not api_key:
        return None
    llm = ChatGoogleGenerativeAI(model="gemini-2.0-flash", google_api_key=api_key)

    def strength_tool(password: str) -> str:
        """Return the deterministic strength analysis for a password."""
        r = check_password_strength(password)
        return str(r)

    def breach_tool(password: str) -> str:
        """Return the deterministic breach-check result for a password."""
        r = check_breach_database(password)
        return str(r)

    agent = create_agent(model=llm, tools=[strength_tool, breach_tool])
    return agent


def explain_with_agent(password: str, strength: dict, breach: dict) -> str:
    agent = load_agent()
    if agent is None:
        return ("Add your GOOGLE_API_KEY in Streamlit secrets to enable "
                "AI-written explanations. Showing raw analysis only for now.")
    prompt = (
        "You are SentinelAI, a security advisor. Using this real analysis "
        f"(never invent new numbers) - strength: {strength}, breach: {breach} - "
        "explain in 2-3 plain-language sentences why this password is or isn't "
        "safe, and give one concrete next step."
    )
    response = agent.invoke({"messages": [{"role": "user", "content": prompt}]})
    return response["messages"][-1].content


# ============ Step 4: Page layout ============

st.title("AI Password & Security Advisor")
st.caption("Rule-based analysis + breach check, explained by a GenAI agent")

url = "https://cdn-icons-png.flaticon.com/512/1670/1670080.png"
st.sidebar.image(url, width=120)
st.sidebar.title("SentinelAI")
st.sidebar.write("Analyzes password strength, checks known breach exposure, "
                  "and explains the result in plain language.")

password = st.text_input("Enter a password to analyze", type="password")

if st.button("Analyze Password"):
    if not password:
        st.warning("Please enter a password first.")
    else:
        with st.spinner("Analyzing..."):
            strength = check_password_strength(password)
            breach = check_breach_database(password)

        st.markdown("## Strength Analysis")
        col1, col2, col3 = st.columns(3)
        col1.metric("Score", f"{strength['score']}/100")
        col2.metric("Entropy", f"{strength['entropy']} bits")
        col3.metric("Category", strength["category"].title())

        chart_df = pd.DataFrame({
            "Metric": ["Score", "Entropy (bits, /128)"],
            "Value": [strength["score"], min(100, round(strength["entropy"] / 128 * 100))]
        })
        chart = alt.Chart(chart_df).mark_bar().encode(
            x="Metric", y="Value", tooltip=["Metric", "Value"]
        )
        st.altair_chart(chart, use_container_width=True)

        if strength["issues"]:
            st.markdown("**Issues detected:**")
            for issue in strength["issues"]:
                st.write(f"- {issue}")
        else:
            st.success("No rule-based issues detected.")

        st.markdown("## Breach Check")
        if not breach["checked"]:
            st.error(f"Breach check failed: {breach.get('error')}")
        elif breach["breached"]:
            st.error(f"This password was found in {breach['count']:,} known breach records.")
        else:
            st.success("Not found in known breach records.")

        st.markdown("## AI Explanation")
        with st.spinner("Generating explanation..."):
            explanation = explain_with_agent(password, strength, breach)
        st.info(explanation)

        st.markdown("## Suggested Alternatives")
        c1, c2 = st.columns(2)
        c1.code(generate_strong_password("passphrase"), language=None)
        c2.code(generate_strong_password("random"), language=None)

footer = """
<style>
.footer {
    position: fixed; left: 0; bottom: 0; width: 100%;
    background-color: transparent; color: #888888;
    text-align: center; padding: 10px; font-size: 14px;
}
</style>
<div class="footer">
    <p>SentinelAI — Password & Security Advisor (GenAI + Agentic AI)</p>
</div>
"""
st.markdown(footer, unsafe_allow_html=True)
