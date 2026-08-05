"""
Password Security Advisor - Core Backend Logic
Analyzes password strength, checks breach databases, and generates secure passwords.
"""

import re
import math
import hashlib
import secrets
import string
import requests

COMMON_PASSWORDS = {
    "123456", "password", "123456789", "12345678", "12345", "qwerty",
    "abc123", "password1", "111111", "123123", "letmein", "welcome",
    "admin", "iloveyou", "monkey", "dragon", "football", "baseball",
    "trustno1", "sunshine", "master", "shadow", "superman", "michael",
    "1234567890", "1234567", "000000", "qazwsx", "passw0rd", "hello",
    "freedom", "whatever", "qwerty123", "zaq1zaq1", "starwars",
}

SEQUENCES = ["abcdefghijklmnopqrstuvwxyz", "0123456789", "qwertyuiop"]


def calculate_entropy(password: str) -> float:
    """Estimate password entropy in bits based on character pool size and length."""
    pool_size = 0
    if re.search(r'[a-z]', password):
        pool_size += 26
    if re.search(r'[A-Z]', password):
        pool_size += 26
    if re.search(r'[0-9]', password):
        pool_size += 10
    if re.search(r'[^a-zA-Z0-9]', password):
        pool_size += 32

    if pool_size == 0 or len(password) == 0:
        return 0.0

    return round(len(password) * math.log2(pool_size), 2)


def estimate_crack_time(entropy_bits: float) -> str:
    """Rough offline brute-force estimate assuming 10 billion guesses/sec."""
    guesses_per_second = 10_000_000_000
    if entropy_bits <= 0:
        return "Instantly"

    total_combinations = 2 ** entropy_bits
    seconds = total_combinations / guesses_per_second / 2  # average-case guess

    if seconds < 1:
        return "Instantly"
    if seconds < 60:
        return f"{seconds:.0f} seconds"
    if seconds < 3600:
        return f"{seconds / 60:.0f} minutes"
    if seconds < 86400:
        return f"{seconds / 3600:.0f} hours"
    if seconds < 31536000:
        return f"{seconds / 86400:.0f} days"
    if seconds < 3153600000:
        return f"{seconds / 31536000:.1f} years"
    return "Centuries"


def check_common_password(password: str) -> bool:
    return password.lower() in COMMON_PASSWORDS


def check_patterns(password: str) -> list:
    """Detect repeated characters and sequential runs like 'abc' / '123'."""
    issues = []

    if re.search(r'(.)\1{2,}', password):
        issues.append("Contains repeated characters (e.g. 'aaa')")

    lowered = password.lower()
    for seq in SEQUENCES:
        for i in range(len(seq) - 2):
            chunk = seq[i:i + 3]
            if chunk in lowered or chunk[::-1] in lowered:
                issues.append("Contains a sequential pattern (e.g. 'abc', '123')")
                break

    return list(dict.fromkeys(issues))  # de-duplicate, keep order


def check_pwned(password: str) -> dict:
    """
    Check the password against the HaveIBeenPwned breach database using
    k-anonymity: only the first 5 chars of the SHA-1 hash are ever sent,
    the real password never leaves this function.
    """
    try:
        sha1 = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
        prefix, suffix = sha1[:5], sha1[5:]
        response = requests.get(
            f"https://api.pwnedpasswords.com/range/{prefix}", timeout=5
        )
        if response.status_code == 200:
            for line in response.text.splitlines():
                h, count = line.split(":")
                if h == suffix:
                    return {"pwned": True, "count": int(count)}
            return {"pwned": False, "count": 0}
        return {"pwned": None, "count": 0, "error": "Breach API unavailable"}
    except requests.RequestException:
        return {"pwned": None, "count": 0, "error": "Could not reach breach database"}


def analyze_password(password: str, check_breach: bool = True) -> dict:
    """Run the full analysis pipeline and return a structured report."""
    if not password:
        return {"error": "No password provided"}

    feedback = []
    score = 0

    length = len(password)
    if length >= 16:
        score += 30
    elif length >= 12:
        score += 22
    elif length >= 8:
        score += 12
        feedback.append("Consider using at least 12-16 characters for better security")
    else:
        feedback.append("Password is too short - use at least 8 characters")

    has_lower = bool(re.search(r'[a-z]', password))
    has_upper = bool(re.search(r'[A-Z]', password))
    has_digit = bool(re.search(r'[0-9]', password))
    has_special = bool(re.search(r'[^a-zA-Z0-9]', password))

    score += sum([has_lower, has_upper, has_digit, has_special]) * 10

    if not has_upper:
        feedback.append("Add uppercase letters (A-Z)")
    if not has_lower:
        feedback.append("Add lowercase letters (a-z)")
    if not has_digit:
        feedback.append("Add numbers (0-9)")
    if not has_special:
        feedback.append("Add special characters (!@#$%^&* etc.)")

    is_common = check_common_password(password)
    if is_common:
        score = max(0, score - 40)
        feedback.append("This is one of the most commonly used passwords - avoid it")

    pattern_issues = check_patterns(password)
    if pattern_issues:
        score = max(0, score - 15 * len(pattern_issues))
        feedback.extend(pattern_issues)

    entropy = calculate_entropy(password)
    score += min(20, entropy / 5)
    score = min(100, round(score))

    breach_info = {"pwned": None, "count": 0}
    if check_breach:
        breach_info = check_pwned(password)
        if breach_info.get("pwned"):
            score = max(0, score - 30)
            feedback.append(
                f"This password has appeared in {breach_info['count']:,} known "
                f"data breaches - change it immediately"
            )

    score = int(score)
    if score >= 80:
        strength = "Very Strong"
    elif score >= 60:
        strength = "Strong"
    elif score >= 40:
        strength = "Moderate"
    elif score >= 20:
        strength = "Weak"
    else:
        strength = "Very Weak"

    if not feedback:
        feedback.append("Great job! This password follows strong security practices.")

    return {
        "score": score,
        "strength": strength,
        "entropy_bits": entropy,
        "crack_time_estimate": estimate_crack_time(entropy),
        "length": length,
        "has_uppercase": has_upper,
        "has_lowercase": has_lower,
        "has_digit": has_digit,
        "has_special": has_special,
        "is_common_password": is_common,
        "breach_info": breach_info,
        "feedback": feedback,
    }


def generate_strong_password(length: int = 16) -> str:
    """Generate a cryptographically secure random password."""
    length = max(8, min(length, 64))
    special = "!@#$%^&*()-_=+"
    alphabet = string.ascii_letters + string.digits + special

    while True:
        pwd = "".join(secrets.choice(alphabet) for _ in range(length))
        if (
            any(c.islower() for c in pwd)
            and any(c.isupper() for c in pwd)
            and any(c.isdigit() for c in pwd)
            and any(c in special for c in pwd)
        ):
            return pwd
