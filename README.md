# Password_Strength_Checker
A Python tool that checks password strength, detects common weak patterns, and verifies if the password has been exposed in breaches using the HIBP API.

---

###  Refined Description
This Python program performs **three layers of password security checks**:

1. **Strength Check**  
   - Evaluates length, character variety (uppercase, lowercase, numbers, symbols).  
   - Flags weak patterns like `12345`, `qwerty`, `password`, etc.  

2. **Breach Check (HIBP API)**  
   - Uses the Have I Been Pwned API to see if the password’s SHA‑1 hash appears in known breach databases.  
   - Reports how many times the password has been exposed.  

3. **Weak Password List Check**  
   - Compares against a custom list of common weak passwords.  
   - Warns if the password matches one of them.  

---
“This project is currently licensed under MIT. Future versions may be relicensed.”
