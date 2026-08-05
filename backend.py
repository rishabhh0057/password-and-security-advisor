# backend.py
# Backend logic for the Password & Security Advisor.
# Same pattern as file_loader.py / basic_eda.py in the AI EDA Agent notebook:
# plain functions, imported by app.py, no extra framework beyond what the
# course notebooks already use (langchain, langchain_community,
# langchain-google-genai, langchain-groq, requests, faiss-cpu,
# sentence-transformers).

import re
import math
import hashlib
import secrets
import string
import requests

from langchain_google_genai import ChatGoogleGenerativeAI
from langchain_groq import ChatGroq
from langchain.agents import create_agent
from langchain_community.vectorstores import FAISS
from langchain_community.embeddings import HuggingFaceEmbeddings
from langchain_text_splitters import RecursiveCharacterTextSplitter


# ============ Tool 1: Rule-based password strength ============

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
    """Rule-based, deterministic strength check. Returns score, entropy,
    category, and a list of specific issues. No LLM involved."""
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


# ============ Tool 2: Breach checker (Have I Been Pwned) ============

def check_breach_database(password: str) -> dict:
    """HIBP k-anonymity check. Only the first 5 characters of the SHA-1
    hash are sent over the network — the real password never leaves
    this machine."""
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


# ============ Tool 3: Mini RAG - security knowledge base ============

SECURITY_KNOWLEDGE_TEXT = """
NIST GUIDELINES: Length matters more than complexity. Encourage passphrases
of 15+ characters over short complex strings. Do not force periodic
rotation without evidence of compromise - forced rotation leads to
predictable incremented passwords like Password1, Password2. Screen new
passwords against known breached password lists. Encourage MFA (TOTP
authenticator apps or hardware keys) since passwords alone are a weak
boundary. Avoid password hints and knowledge-based security questions since
they are guessable via social engineering.

ATTACK PATTERNS: Dictionary attacks try common words and previously leaked
passwords (e.g. rockyou.txt, 14 million real leaked passwords). Brute-force
attacks try every combination - short passwords under 8 characters can be
cracked in minutes on modern GPUs regardless of symbols used. Credential
stuffing reuses a password leaked from one site against other sites, which
is why unique passwords per account matter. Predictable substitutions like
a-to-@ or o-to-0 or appending 123 or an exclamation mark are well known to
cracking tools and add little real security. Keyboard-walk patterns like
qwerty or asdfgh are tried very early in cracking attempts.

PASSPHRASE CONSTRUCTION: A passphrase of 5-6 random unrelated words drawn
from a large wordlist can exceed 60 bits of entropy while staying easy to
memorize. Avoid quotes, song lyrics, or famous phrases since these appear
in dictionary-attack wordlists built from pop culture. Each word must be
randomly selected and unrelated to the others, not a meaningful sentence.
Entropy under 28 bits is very weak, 36-59 bits is reasonable for low-value
accounts, 60-127 bits is strong for most accounts, and 128+ bits suits a
password manager master password.
"""

_retriever = None  # built once, lazily, on first use


def _get_retriever():
    global _retriever
    if _retriever is None:
        splitter = RecursiveCharacterTextSplitter(chunk_size=350, chunk_overlap=50)
        docs = splitter.create_documents([SECURITY_KNOWLEDGE_TEXT])
        embeddings = HuggingFaceEmbeddings(model_name="sentence-transformers/all-MiniLM-L6-v2")
        vector_store = FAISS.from_documents(docs, embeddings)
        _retriever = vector_store.as_retriever(search_kwargs={"k": 3})
    return _retriever


def retrieve_security_guidance(query: str) -> str:
    """Retrieve relevant security guidance (NIST rules, attack patterns,
    passphrase construction) for a topic, so advice is grounded instead
    of relying on the LLM's general knowledge."""
    retriever = _get_retriever()
    results = retriever.invoke(query)
    if not results:
        return "No relevant guidance found."
    return "\n---\n".join(d.page_content for d in results)


# ============ Tool 4: Strong password / passphrase generator ============

_WORDLIST = ["orbit", "maple", "quartz", "ember", "velvet", "cobalt",
             "harbor", "falcon", "lantern", "granite", "willow", "copper",
             "marble", "thicket", "ripple", "canyon", "ash", "drift"]


def generate_strong_password(style: str = "passphrase") -> str:
    """Cryptographically secure generation via Python's `secrets` module —
    not LLM-derived, so the entropy claim is always real."""
    if style == "random":
        alphabet = string.ascii_letters + string.digits + "!@#$%^&*"
        return ''.join(secrets.choice(alphabet) for _ in range(16))
    words = [secrets.choice(_WORDLIST) for _ in range(5)]
    return "-".join(words) + str(secrets.randbelow(90) + 10)


# ============ LLM + Agent creation ============

def load_llm(provider: str = "google", api_key: str = "", model: str = ""):
    """provider: 'google' or 'groq'. Pass your key in — never hardcode it
    here, same note as in the notebook."""
    if provider == "groq":
        return ChatGroq(model=model or "llama-3.3-70b-versatile", api_key=api_key)
    return ChatGoogleGenerativeAI(model=model or "gemini-2.0-flash", google_api_key=api_key)


SYSTEM_NOTE = (
    "You are SentinelAI, a security advisor. Never invent a strength score "
    "or breach status yourself - always call the analysis tools and report "
    "their real output. Ground explanations using retrieve_security_guidance. "
    "Never ask the user to repeat their password back unnecessarily."
)

_agent = None  # built once per process


def get_agent(llm=None, api_key: str = "", provider: str = "google"):
    """Builds (once) and returns the agent with all four tools attached,
    same create_agent pattern as the class notebooks."""
    global _agent
    if _agent is not None:
        return _agent

    if llm is None:
        llm = load_llm(provider=provider, api_key=api_key)

    tools = [check_password_strength, check_breach_database,
             retrieve_security_guidance, generate_strong_password]

    _agent = create_agent(model=llm, tools=tools)
    return _agent


# ============ Report function (what app.py calls) ============

def generate_security_report(password: str, api_key: str = "", provider: str = "google") -> str:
    """Runs the full advisor pipeline for one password and returns a
    plain-language report string. This is the single function app.py needs
    to call — same pattern as `perform_eda_func` in the EDA agent notebook."""
    agent = get_agent(api_key=api_key, provider=provider)
    prompt = (
        f"{SYSTEM_NOTE}\n\nGive a full security report for this password: "
        f"{password}. Include: 1) strength summary 2) breach status "
        f"3) the single biggest weakness 4) one stronger alternative."
    )
    response = agent.invoke({"messages": [{"role": "user", "content": prompt}]})
    return response["messages"][-1].content


if __name__ == "__main__":
    # quick manual test of the non-LLM tools (safe to run without an API key)
    print(check_password_strength("Password123!"))
    print(check_breach_database("password123"))
    print(generate_strong_password("passphrase"))
