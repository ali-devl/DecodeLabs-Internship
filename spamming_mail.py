from urllib.parse import urlparse

SUSPICIOUS_KEYWORDS = [
    "urgent", "action required", "account suspended", "unauthorized login", 
    "verify your identity", "restricted", "security alert", "click below"
]

def analyze_message(email_body, visible_url=None, actual_destination=None):
    print("\nAnalyzing Message for Phishing Identifiers")
    red_flags = 0

    found_keywords = [kw for kw in SUSPICIOUS_KEYWORDS if kw in email_body.lower()]
    if found_keywords:
        print(f"RED FLAG: High-urgency keywords found: {found_keywords}")
        red_flags += 1

    if "dear customer" in email_body.lower() or "dear user" in email_body.lower():
        print("RED FLAG: Generic greeting used ('Dear Customer/User').")
        red_flags += 1

    if visible_url and actual_destination:
        if visible_url != actual_destination:
            print(f"CRITICAL RED FLAG: Visible link text ('{visible_url}') does not match actual destination ('{actual_destination}').")
            red_flags += 1
            analyze_url(actual_destination)
    elif actual_destination:
        analyze_url(actual_destination)

   
    if red_flags >= 2:
        print(f"RESULT: HIGHLY SUSPICIOUS. Message exhibits {red_flags} major phishing red flags. DO NOT TRUST.")
    elif red_flags == 1:
        print("RESULT: POTENTIAL RISK. At least one red flag was triggered.")
    else:
        print("RESULT: Clean text scan.")


def analyze_url(url_string):
    if not url_string.startswith(('http://', 'https://')):
        url_string = 'http://' + url_string
        
    try:
        parsed = urlparse(url_string)
        domain = parsed.netloc.lower()
    except Exception:
        print("Could not parse URL.")
        return

    print(f"\nAnalyzing URL: {url_string}")

    
    try:
        domain.encode('ascii')
    except UnicodeEncodeError:
        print("RED FLAG (Homoglyph Attack): The domain contains non-standard international characters meant to look like real text.")
        punycode = domain.encode('idna').decode('ascii')
        print(f"   Actual system translation: {punycode}")

    clean_domain = domain.replace("www.", "")
    domain_parts = clean_domain.split('.')
    core_name = domain_parts[0] if domain_parts else clean_domain

    
    security_terms = ["security", "login", "verify", "update", "support", "alert", "account"]
    found_terms = [term for term in security_terms if term in clean_domain]
    if found_terms:
        print(f"RED FLAG: Domain contains generic security/login terms: {found_terms}")

    
    replacements = {"0": "o", "1": "l", "vv": "w"}
    detected_swaps = []
    
    for fake in replacements.keys():
        if fake in core_name:
            detected_swaps.append(fake)
            
    if detected_swaps:
        print(f"RED FLAG (Typosquatting Trick): Domain uses suspicious lookalike characters {detected_swaps} (like 0 for o, or 1 for l).")


if __name__ == "__main__":
    print("Phishing Analyzer Console Tool")
    user_email = input("Enter the email body text: ")
    user_visible_url = input("Enter the visible URL text (or leave blank if none): ").strip() or None
    user_actual_url = input("Enter the actual destination URL: ")

    analyze_message(
        email_body=user_email,
        visible_url=user_visible_url,
        actual_destination=user_actual_url
    )