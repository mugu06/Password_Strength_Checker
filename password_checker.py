import re
import hashlib
import requests
import time
import os

# -------------------------------
# Load common patterns from file
# -------------------------------
def load_common_patterns(filename="common_patterns.txt"): # User can use some other common pattern form online
    # Build path relative to script directory
    script_dir = os.path.dirname(__file__)
    file_path = os.path.join(script_dir, filename)

    try:
        with open(file_path, "r", encoding="utf-8") as f:
            patterns = [line.strip().lower() for line in f if line.strip()]
        return patterns
    except FileNotFoundError:
        print(f"⚠️ File {filename} not found in {script_dir}.")
        return []
    

# -------------------------------
# Password Strength Checker
# -------------------------------
def check_strength(password: str, patterns_file="common_patterns.txt") -> dict:
    score = 0
    feedback = []

    # Load common patterns
    common_patterns = load_common_patterns(patterns_file)

    # Length check
    if len(password) >= 12:
        score += 2
    else:
        feedback.append("Password too short (min 12 chars).")

    # Character variety
    if re.search(r"[A-Z]", password): score += 2
    else: feedback.append("Add uppercase letters.")
    if re.search(r"[a-z]", password): score += 2
    else: feedback.append("Add lowercase letters.")
    if re.search(r"[0-9]", password): score += 2
    else: feedback.append("Add numbers.")
    if re.search(r"[^A-Za-z0-9]", password): score += 2
    else: feedback.append("Add special symbols.")

    # Check against common patterns file
    if any(p in password.lower() for p in common_patterns):
        feedback.append("Avoid common patterns or words.")
        score -= 2

    # Normalize score
    score = max(0, min(score, 10))

    return {"score": score, "feedback": feedback}

# -------------------------------
# Breach Alert (HIBP API)
# -------------------------------
def check_breach(password: str, delay: float = 2.0) -> dict:
    """
    Check if a password has been breached using HIBP API.
    Includes a delay to respect rate limits.
    """
    sha1pwd = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix, suffix = sha1pwd[:5], sha1pwd[5:]

    url = f"https://api.pwnedpasswords.com/range/{prefix}"
    try:
        print("wait for the result:")
        response = requests.get(url, timeout=2)

        # Respect API rate limits: wait before next call
        time.sleep(delay)

        if response.status_code != 200:
            return {"error": f"API request failed ({response.status_code})."}

        hashes = (line.split(":") for line in response.text.splitlines())
        for h, count in hashes:
            if h == suffix:
                return {"breached": True, "count": int(count)}

        return {"breached": False}

    except requests.exceptions.RequestException as e:
        return {"error": f"Request error: {e}"}


# -------------------------------
# Main Function
# -------------------------------
if __name__ == "__main__":
    pwd = input("Enter a password to check: ")

    strength = check_strength(pwd)
    breach = check_breach(pwd)
    
    print("\n--- Password Report ---")
    print(f"Strength Score: {strength['score']} / 10")
    if strength['feedback']:
        print("Suggestions:")
        for f in strength['feedback']:
            print(f"- {f}")
            
    print("\n--- Breach Data Result ---")
    if "error" in breach:
        print("Breach check error:", breach["error"])
    elif breach["breached"]:
        print(f"⚠️ This password has been seen {breach['count']} times in breaches!")
    else:
        print("✅ This password has not been found in known breaches.")
        