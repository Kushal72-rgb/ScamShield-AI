"""Synthetic Evaluation Dataset for ScamShield AI.

NOTE: This is an internal synthetic evaluation dataset created for controlled benchmarking.
It does NOT contain private user data, real victim details, genuine OTPs, or active bank credentials.
All phone numbers, names, and scenarios are fictionalized.
"""

# 30 Synthetic Message Evaluation Cases (15 Fraudulent, 15 Legitimate)
MESSAGE_DATASET = [
    # --- 15 Clearly Fraudulent / Scam Messages ---
    {
        "id": "M01",
        "category": "bank_scam",
        "expected_label": "SCAM",
        "expected_risk": "HIGH",
        "text": "Chase Alert: Unusual debit card activity detected. $942.10 at Apple Store. If not you, verify immediately: http://chase-security-verify.net/auth or card will be permanently blocked."
    },
    {
        "id": "M02",
        "category": "upi_fraud",
        "expected_label": "SCAM",
        "expected_risk": "HIGH",
        "text": "Dear customer, your electricity bill is unpaid. Power will be disconnected tonight at 9:30 PM. Pay now via UPI to 9876543210@paytm and share screenshot to avoid disconnection."
    },
    {
        "id": "M03",
        "category": "fake_job",
        "expected_label": "SCAM",
        "expected_risk": "HIGH",
        "text": "Congratulations! You are shortlisted for Part-Time Data Entry / YouTube Video Reviewer. Earn $300-$500/day. Complete your registration fee of $35 via CashApp to receive work kit."
    },
    {
        "id": "M04",
        "category": "lottery_fraud",
        "expected_label": "SCAM",
        "expected_risk": "HIGH",
        "text": "FINAL NOTICE: Your mobile number has won 1st prize in the Samsung Mega UK Lottery ($850,000). To release your prize check, email your passport copy and wire $150 processing fee to our claims manager."
    },
    {
        "id": "M05",
        "category": "delivery_scam",
        "expected_label": "SCAM",
        "expected_risk": "HIGH",
        "text": "USPS Tracking: Package #US940523849 cannot be delivered due to missing street address. Update address and pay $1.85 redelivery fee within 12 hours: http://usps-redelivery-portal.cc"
    },
    {
        "id": "M06",
        "category": "gov_impersonation",
        "expected_label": "SCAM",
        "expected_risk": "HIGH",
        "text": "INTERNAL REVENUE SERVICE NOTICE: An arrest warrant has been filed under your SSN for tax fraud. Call the Federal Investigation Bureau immediately at 800-555-0199 to settle penalties."
    },
    {
        "id": "M07",
        "category": "distress_scam",
        "expected_label": "SCAM",
        "expected_risk": "HIGH",
        "text": "Hi Dad, I broke my phone and lost my wallet at the airport. I'm messaging from a friend's WhatsApp. Can you please send $650 via Zelle to this number right away? I'm stranded and my flight is boarding soon."
    },
    {
        "id": "M08",
        "category": "credential_phishing",
        "expected_label": "SCAM",
        "expected_risk": "HIGH",
        "text": "Microsoft 365 Security: Your email account password expires today. Keep your current password and prevent email deactivation by logging in at: http://office365-password-portal.com"
    },
    {
        "id": "M09",
        "category": "tech_support_scam",
        "expected_label": "SCAM",
        "expected_risk": "HIGH",
        "text": "WARNING: Windows Defender detected Trojan Spyware (0x80070422) on your computer. Your financial files are compromised. Do not restart. Call Microsoft certified support at 1-888-555-0144 immediately."
    },
    {
        "id": "M10",
        "category": "bank_scam",
        "expected_label": "SCAM",
        "expected_risk": "HIGH",
        "text": "Wells Fargo: A transfer of $1,200.00 was requested. If this wasn't you, reply STOP and immediately share the 6-digit one-time passcode sent to your mobile to reverse the transaction."
    },
    {
        "id": "M11",
        "category": "upi_fraud",
        "expected_label": "SCAM",
        "expected_risk": "HIGH",
        "text": "Google Pay Bonus: You have received a cashback reward of Rs 2,999. Click the link, enter your UPI PIN on the payment screen to deposit money into your bank account immediately: http://gpay-cashback-claim.xyz"
    },
    {
        "id": "M12",
        "category": "delivery_scam",
        "expected_label": "SCAM",
        "expected_risk": "HIGH",
        "text": "FedEx Delivery Update: Your shipment #FX-883921 is held at customs warehouse due to unpaid duty tax ($2.40). Pay now to resume shipping: http://fedex-customs-clearance.cc"
    },
    {
        "id": "M13",
        "category": "crypto_fraud",
        "expected_label": "SCAM",
        "expected_risk": "HIGH",
        "text": "VIP Crypto Signals: Join our exclusive Binance arbitrage pool. Guaranteed 15% daily return with zero risk. Send minimum 0.05 BTC to wallet bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh to activate trading bot."
    },
    {
        "id": "M14",
        "category": "romance_fraud",
        "expected_label": "SCAM",
        "expected_risk": "HIGH",
        "text": "Dearest, I have been deployed overseas on a peacekeeping mission and cannot access my account. The military courier is holding my trunk of gold bullion. Can you wire $800 to the customs agent to clear it?"
    },
    {
        "id": "M15",
        "category": "tech_support_scam",
        "expected_label": "SCAM",
        "expected_risk": "HIGH",
        "text": "Geek Squad Renewal: We have auto-renewed your 3-year Total Tech protection plan for $499.99 from your registered credit card. If you did not authorize this charge, call our billing cancellation department at 888-555-0182."
    },

    # --- 15 Clearly Legitimate Messages ---
    {
        "id": "M16",
        "category": "normal_family",
        "expected_label": "LEGITIMATE",
        "expected_risk": "LOW",
        "text": "Hey dad, dinner was great tonight! Let me know if you want me to bring over the lawnmower on Saturday morning."
    },
    {
        "id": "M17",
        "category": "normal_work",
        "expected_label": "LEGITIMATE",
        "expected_risk": "LOW",
        "text": "Hi Team, please find the quarterly performance slides attached for tomorrow's 10 AM sync. Let me know if you have any questions before then."
    },
    {
        "id": "M18",
        "category": "normal_transaction",
        "expected_label": "LEGITIMATE",
        "expected_risk": "LOW",
        "text": "Your Starbucks order #492 is ready for pickup at the counter. Thank you for using mobile ordering!"
    },
    {
        "id": "M19",
        "category": "normal_appointment",
        "expected_label": "LEGITIMATE",
        "expected_risk": "LOW",
        "text": "Reminder: Your dental appointment with Dr. Henderson is scheduled for Tuesday, Oct 14 at 2:00 PM. Reply 1 to confirm or call 555-0123 to reschedule."
    },
    {
        "id": "M20",
        "category": "normal_delivery",
        "expected_label": "LEGITIMATE",
        "expected_risk": "LOW",
        "text": "Amazon: Your package with the wireless mouse has been delivered to your front porch. View order details in your Amazon app."
    },
    {
        "id": "M21",
        "category": "normal_service",
        "expected_label": "LEGITIMATE",
        "expected_risk": "LOW",
        "text": "Your monthly Spotify Premium subscription has renewed successfully for $11.99. View your receipt anytime in your account settings."
    },
    {
        "id": "M22",
        "category": "normal_work",
        "expected_label": "LEGITIMATE",
        "expected_risk": "LOW",
        "text": "Thanks for sending over the drafts, Karen. I reviewed section 3 and left a few comments on Google Docs. Overall looks solid."
    },
    {
        "id": "M23",
        "category": "normal_family",
        "expected_label": "LEGITIMATE",
        "expected_risk": "LOW",
        "text": "Grandma says thank you so much for the birthday flowers! She absolutely loved the yellow tulips."
    },
    {
        "id": "M24",
        "category": "normal_transaction",
        "expected_label": "LEGITIMATE",
        "expected_risk": "LOW",
        "text": "Your Uber ride with driver Marcus has completed. Your total receipt of $16.42 has been charged to your card ending in 4120."
    },
    {
        "id": "M25",
        "category": "normal_education",
        "expected_label": "LEGITIMATE",
        "expected_risk": "LOW",
        "text": "Campus alert: The main university library will observe reduced hours during midterm break, closing at 6:00 PM on Friday."
    },
    {
        "id": "M26",
        "category": "normal_social",
        "expected_label": "LEGITIMATE",
        "expected_risk": "LOW",
        "text": "Are you free for coffee around 3 PM today? Let me know if that works or if tomorrow is better for you!"
    },
    {
        "id": "M27",
        "category": "normal_utility",
        "expected_label": "LEGITIMATE",
        "expected_risk": "LOW",
        "text": "Your monthly water utility bill of $42.50 is now available online. Automatic payment will be processed on Oct 25."
    },
    {
        "id": "M28",
        "category": "normal_flight",
        "expected_label": "LEGITIMATE",
        "expected_risk": "LOW",
        "text": "United Airlines: Flight UA 442 to Chicago O'Hare is on time. Gate departure is B12. Boarding begins at 4:15 PM."
    },
    {
        "id": "M29",
        "category": "normal_restaurant",
        "expected_label": "LEGITIMATE",
        "expected_risk": "LOW",
        "text": "Your reservation at Trattoria Bella for a party of 4 on Friday at 7:30 PM is confirmed. See you soon!"
    },
    {
        "id": "M30",
        "category": "normal_personal",
        "expected_label": "LEGITIMATE",
        "expected_risk": "LOW",
        "text": "Just landed safely in Seattle! Grabbing my luggage now and heading to the hotel. Will call you once I check in."
    },
]

# 20 Synthetic URL Evaluation Cases (10 Suspicious, 10 Legitimate)
URL_DATASET = [
    # --- 10 Suspicious URL Examples ---
    {
        "id": "U01",
        "url": "http://paypal-security-update.com",
        "expected_label": "SUSPICIOUS",
        "category": "phishing_brand_impersonation",
        "reason": "Insecure HTTP, excessive hyphens, impersonation of PayPal with security keywords"
    },
    {
        "id": "U02",
        "url": "http://chase-security-verify.net",
        "expected_label": "SUSPICIOUS",
        "category": "phishing_brand_impersonation",
        "reason": "Insecure HTTP, excessive hyphens, impersonation of Chase Bank"
    },
    {
        "id": "U03",
        "url": "http://192.168.1.150/bank/login.php",
        "expected_label": "SUSPICIOUS",
        "category": "raw_ip_phishing",
        "reason": "Uses raw IP address instead of registered domain name over HTTP"
    },
    {
        "id": "U04",
        "url": "https://usps-redelivery-portal.cc",
        "expected_label": "SUSPICIOUS",
        "category": "delivery_smishing_tld",
        "reason": "Suspicious TLD .cc, excessive hyphens, USPS brand impersonation"
    },
    {
        "id": "U05",
        "url": "http://apple-id-verify-alert.com",
        "expected_label": "SUSPICIOUS",
        "category": "credential_phishing",
        "reason": "Insecure HTTP, excessive hyphens, Apple brand impersonation"
    },
    {
        "id": "U06",
        "url": "http://netflix-billing-update.xyz",
        "expected_label": "SUSPICIOUS",
        "category": "phishing_tld",
        "reason": "Insecure HTTP, suspicious TLD .xyz, Netflix impersonation"
    },
    {
        "id": "U07",
        "url": "https://wellsfargo-auth-portal.com",
        "expected_label": "SUSPICIOUS",
        "category": "bank_phishing",
        "reason": "Excessive hyphens, Wells Fargo brand impersonation paired with auth keywords"
    },
    {
        "id": "U08",
        "url": "http://amazon-account-support.click",
        "expected_label": "SUSPICIOUS",
        "category": "ecommerce_phishing_tld",
        "reason": "Insecure HTTP, suspicious TLD .click, Amazon brand mimicry"
    },
    {
        "id": "U09",
        "url": "http://irs-tax-refund-portal.net",
        "expected_label": "SUSPICIOUS",
        "category": "gov_impersonation",
        "reason": "Insecure HTTP, IRS impersonation on commercial .net domain"
    },
    {
        "id": "U10",
        "url": "https://google.com@phishingserver.top/login",
        "expected_label": "SUSPICIOUS",
        "category": "deceptive_url_structure",
        "reason": "Contains deceptive @ character concealing destination host and suspicious TLD .top"
    },

    # --- 10 Legitimate URL Examples ---
    {
        "id": "U11",
        "url": "https://www.google.com",
        "expected_label": "LEGITIMATE",
        "category": "legitimate_search",
        "reason": "Official trusted domain with secure HTTPS"
    },
    {
        "id": "U12",
        "url": "https://www.paypal.com",
        "expected_label": "LEGITIMATE",
        "category": "legitimate_financial",
        "reason": "Official PayPal domain with secure HTTPS"
    },
    {
        "id": "U13",
        "url": "https://www.chase.com",
        "expected_label": "LEGITIMATE",
        "category": "legitimate_bank",
        "reason": "Official Chase Bank domain with secure HTTPS"
    },
    {
        "id": "U14",
        "url": "https://www.amazon.com",
        "expected_label": "LEGITIMATE",
        "category": "legitimate_ecommerce",
        "reason": "Official Amazon domain with secure HTTPS"
    },
    {
        "id": "U15",
        "url": "https://www.apple.com",
        "expected_label": "LEGITIMATE",
        "category": "legitimate_tech",
        "reason": "Official Apple domain with secure HTTPS"
    },
    {
        "id": "U16",
        "url": "https://www.microsoft.com",
        "expected_label": "LEGITIMATE",
        "category": "legitimate_tech",
        "reason": "Official Microsoft domain with secure HTTPS"
    },
    {
        "id": "U17",
        "url": "https://www.github.com",
        "expected_label": "LEGITIMATE",
        "category": "legitimate_developer",
        "reason": "Official GitHub domain with secure HTTPS"
    },
    {
        "id": "U18",
        "url": "https://www.wikipedia.org",
        "expected_label": "LEGITIMATE",
        "category": "legitimate_reference",
        "reason": "Official Wikipedia domain with secure HTTPS"
    },
    {
        "id": "U19",
        "url": "https://www.usps.com",
        "expected_label": "LEGITIMATE",
        "category": "legitimate_postal",
        "reason": "Official USPS government domain with secure HTTPS"
    },
    {
        "id": "U20",
        "url": "https://www.netflix.com",
        "expected_label": "LEGITIMATE",
        "category": "legitimate_streaming",
        "reason": "Official Netflix domain with secure HTTPS"
    },

    # --- 10 Additional Adversarial / Zero-Day / Obfuscated URLs (Robustness Expansion) ---
    {
        "id": "U21",
        "url": "https://bit.ly/3xVerifyAccount",
        "expected_label": "SUSPICIOUS",
        "category": "shortened_url_concealment",
        "reason": "URL shortener disguising destination host to evade structural inspection"
    },
    {
        "id": "U22",
        "url": "http://0x7f000001/bank/auth.php",
        "expected_label": "SUSPICIOUS",
        "category": "obfuscated_hex_ip",
        "reason": "Hexadecimal encoded IP address host format concealing loopback/internal target"
    },
    {
        "id": "U23",
        "url": "http://2130706433/login",
        "expected_label": "SUSPICIOUS",
        "category": "obfuscated_dword_ip",
        "reason": "Dword/integer representation of IP address to evade hostname reputation"
    },
    {
        "id": "U24",
        "url": "http://0177.0.0.1/verify",
        "expected_label": "SUSPICIOUS",
        "category": "obfuscated_octal_ip",
        "reason": "Octal-encoded IPv4 component bypassing simplistic regex filters"
    },
    {
        "id": "U25",
        "url": "https://xn--pypal-4ve.com/signin",
        "expected_label": "SUSPICIOUS",
        "category": "punycode_idn_homograph",
        "reason": "Punycode (xn--) internationalized domain mimicking PayPal brand with visually identical glyphs"
    },
    {
        "id": "U26",
        "url": "https://paypa1-security.com/account",
        "expected_label": "SUSPICIOUS",
        "category": "typosquatting_leetspeak",
        "reason": "Leetspeak numeral '1' replacing 'l' to impersonate PayPal domain"
    },
    {
        "id": "U27",
        "url": "https://bank-verification.duckdns.org/login",
        "expected_label": "SUSPICIOUS",
        "category": "dynamic_dns_staging",
        "reason": "Free disposable dynamic DNS domain (duckdns.org) staged with financial verification lure"
    },
    {
        "id": "U28",
        "url": "https://urgent-payroll-update.ngrok-free.app/signin",
        "expected_label": "SUSPICIOUS",
        "category": "tunneling_service_abuse",
        "reason": "Developer tunneling endpoint (ngrok-free.app) abused as ephemeral phishing drop"
    },
    {
        "id": "U29",
        "url": "http://secure-update-portal.com:8080/auth",
        "expected_label": "SUSPICIOUS",
        "category": "non_standard_port_evasion",
        "reason": "Phishing kit hosted on non-standard HTTP port 8080 over unencrypted protocol"
    },
    {
        "id": "U30",
        "url": "http://shipping-documents-download.org/invoice_details.pdf.exe",
        "expected_label": "SUSPICIOUS",
        "category": "executable_malware_payload",
        "reason": "Double-extension link delivering malicious executable (.pdf.exe) payload"
    },

    # --- 10 Additional Diverse Legitimate URLs (Baseline Calibration) ---
    {
        "id": "U31",
        "url": "https://docs.google.com/document/d/1abc123/edit",
        "expected_label": "LEGITIMATE",
        "category": "legitimate_cloud_docs",
        "reason": "Official Google Docs collaboration endpoint without suspicious parameters"
    },
    {
        "id": "U32",
        "url": "https://auth.github.com",
        "expected_label": "LEGITIMATE",
        "category": "legitimate_subdomain",
        "reason": "Official GitHub authentication subdomain on legitimate base domain"
    },
    {
        "id": "U33",
        "url": "https://www.irs.gov/refunds",
        "expected_label": "LEGITIMATE",
        "category": "legitimate_government",
        "reason": "Authentic U.S. Internal Revenue Service .gov website"
    },
    {
        "id": "U34",
        "url": "https://secure.chase.com/statement",
        "expected_label": "LEGITIMATE",
        "category": "legitimate_bank_portal",
        "reason": "Legitimate Chase Bank secure portal with matching base domain"
    },
    {
        "id": "U35",
        "url": "https://developer.apple.com/documentation",
        "expected_label": "LEGITIMATE",
        "category": "legitimate_tech_developer",
        "reason": "Official Apple developer documentation portal"
    },
    {
        "id": "U36",
        "url": "https://cdn.jsdelivr.net/npm/bootstrap@5.3.0",
        "expected_label": "LEGITIMATE",
        "category": "legitimate_cdn",
        "reason": "Public open-source content delivery network host"
    },
    {
        "id": "U37",
        "url": "https://login.microsoftonline.com",
        "expected_label": "LEGITIMATE",
        "category": "legitimate_identity_provider",
        "reason": "Official Microsoft Entra / 365 identity provider domain"
    },
    {
        "id": "U38",
        "url": "https://gitlab.com/projects",
        "expected_label": "LEGITIMATE",
        "category": "legitimate_developer",
        "reason": "Official GitLab version control platform"
    },
    {
        "id": "U39",
        "url": "https://accounts.google.com/signin",
        "expected_label": "LEGITIMATE",
        "category": "legitimate_auth",
        "reason": "Official Google accounts login portal"
    },
    {
        "id": "U40",
        "url": "https://www.who.int/health-topics",
        "expected_label": "LEGITIMATE",
        "category": "legitimate_international_org",
        "reason": "Official World Health Organization international institution domain"
    },
]

# 10 Synthetic Evaluation Cases for Degraded Mode / API Failure Resilience
DEGRADED_MODE_DATASET = [
    {
        "id": "D01",
        "category": "bank_scam",
        "expected_label": "SCAM",
        "expected_risk": "HIGH",
        "text": "Wells Fargo Alert: Unusual debit card activity. Account suspended. Reply immediately with your 6-digit OTP to unblock.",
    },
    {
        "id": "D02",
        "category": "upi_fraud",
        "expected_label": "SCAM",
        "expected_risk": "HIGH",
        "text": "Electricity bill unpaid! Power will be disconnected tonight at 9:30 PM. Pay now via UPI to 9876543210@paytm.",
    },
    {
        "id": "D03",
        "category": "delivery_smishing",
        "expected_label": "SCAM",
        "expected_risk": "HIGH",
        "text": "USPS: Package cannot be delivered due to missing street address. Update details and pay redelivery fee now.",
    },
    {
        "id": "D04",
        "category": "fake_job",
        "expected_label": "SCAM",
        "expected_risk": "HIGH",
        "text": "Shortlisted for part-time data entry! Earn $300-$500/day. Send $35 registration fee via CashApp to get started.",
    },
    {
        "id": "D05",
        "category": "tech_support",
        "expected_label": "SCAM",
        "expected_risk": "HIGH",
        "text": "Windows Defender detected trojan spyware (0x80070422). Financial files are compromised. Call Microsoft certified support at 1-888-555-0144.",
    },
    {
        "id": "D06",
        "category": "normal_family",
        "expected_label": "LEGITIMATE",
        "expected_risk": "LOW",
        "text": "Hey dad, dinner was great tonight! Let me know if you want me to bring over the lawnmower on Saturday morning.",
    },
    {
        "id": "D07",
        "category": "normal_work",
        "expected_label": "LEGITIMATE",
        "expected_risk": "LOW",
        "text": "Hi Team, please find the quarterly performance slides attached for tomorrow's 10 AM sync. Let me know if you have any questions.",
    },
    {
        "id": "D08",
        "category": "normal_appointment",
        "expected_label": "LEGITIMATE",
        "expected_risk": "LOW",
        "text": "Reminder: Your dental appointment with Dr. Henderson is scheduled for Tuesday at 2:00 PM.",
    },
    {
        "id": "D09",
        "category": "normal_transaction",
        "expected_label": "LEGITIMATE",
        "expected_risk": "LOW",
        "text": "Your Starbucks order #492 is ready for pickup at the counter. Thank you for using mobile ordering!",
    },
    {
        "id": "D10",
        "category": "normal_delivery",
        "expected_label": "LEGITIMATE",
        "expected_risk": "LOW",
        "text": "Amazon: Your package with the wireless mouse has been delivered to your front porch.",
    },
]

# Multi-Turn Conversation Thread Dataset
CONVERSATION_DATASET = [
    {
        "id": "C01",
        "name": "Pig Butchering / Crypto Grooming Thread",
        "expected_label": "SCAM",
        "expected_risk": "HIGH",
        "messages": [
            {"sender": "Stranger", "message": "Hi Anna! Are we still meeting for lunch today?"},
            {"sender": "You", "message": "Sorry, you have the wrong number."},
            {"sender": "Stranger", "message": "Oh I'm so sorry! You seem like such a polite person though. I'm Lisa from Singapore."},
            {"sender": "Stranger", "message": "I do crypto arbitrage trading. Made 25% today! Deposit $500 now at https://fake-crypto-yield.com before bonus closes!"},
        ]
    },
    {
        "id": "C02",
        "name": "Urgent Arrest Extortion Thread",
        "expected_label": "SCAM",
        "expected_risk": "HIGH",
        "messages": [
            {"sender": "Officer Davis", "message": "This is Officer Davis from the Federal Bureau. There is an active arrest warrant under your SSN."},
            {"sender": "You", "message": "What? For what?"},
            {"sender": "Officer Davis", "message": "Tax fraud penalty of $2,400. Settle immediately via prepaid wire transfer or police will be dispatched to your residence in 30 minutes."},
        ]
    },
    {
        "id": "C03",
        "name": "Legitimate Social Planning Thread",
        "expected_label": "LEGITIMATE",
        "expected_risk": "LOW",
        "messages": [
            {"sender": "Alex", "message": "Hey! Are you still up for hiking this Saturday?"},
            {"sender": "You", "message": "Yes! Which trail are we doing?"},
            {"sender": "Alex", "message": "Mount Si! Let's meet at the trailhead parking lot at 8 AM. I'll bring snacks."},
        ]
    },
    {
        "id": "C04",
        "name": "Legitimate Work Collaboration Thread",
        "expected_label": "LEGITIMATE",
        "expected_risk": "LOW",
        "messages": [
            {"sender": "Manager", "message": "Did you push the bugfix branch to GitHub?"},
            {"sender": "You", "message": "Yes, PR #42 is open for review."},
            {"sender": "Manager", "message": "Awesome, reviewing now and merging before the sprint cut."},
        ]
    },
]

# Multi-Attack Evaluation Dataset (10 Synthetic Cases)
# Evaluates multi-attack detection coverage, individual technique identification, and benign calibration.
MULTI_ATTACK_DATASET = [
    {
        "id": "MA01",
        "name": "Bank Phishing + OTP Theft + Malicious Link + Urgency",
        "text": "Chase Alert: Unusual card activity of $840 detected. Enter your one-time passcode (OTP) at http://chase-security-verify.net/auth immediately to unfreeze your card before it is permanently blocked.",
        "expected_risk": "HIGH",
        "expected_attack_types": [
            "Bank Impersonation",
            "OTP Theft",
            "Malicious Link",
            "Credential Phishing",
            "Urgency/Threat Manipulation"
        ],
    },
    {
        "id": "MA02",
        "name": "Executable Download + Threat Urgency + Malicious Link",
        "text": "FINAL WARNING: Your payroll invoice details must be reviewed immediately within 2 hours: http://shipping-documents-download.org/invoice_details.pdf.exe or legal action follows today!",
        "expected_risk": "HIGH",
        "expected_attack_types": [
            "Malicious Download",
            "Urgency/Threat Manipulation",
            "Malicious Link"
        ],
    },
    {
        "id": "MA03",
        "name": "Typosquatting + Bank Impersonation + OTP Theft",
        "text": "PayPal Security: Suspicious login attempt from unknown device. Enter your verification OTP at https://paypa1-security.com/account to secure your login credentials.",
        "expected_risk": "HIGH",
        "expected_attack_types": [
            "Bank Impersonation",
            "Typosquatting",
            "OTP Theft",
            "Credential Phishing",
            "Malicious Link"
        ],
    },
    {
        "id": "MA04",
        "name": "Delivery Smishing + Shortened URL + Payment Extortion",
        "text": "USPS Notification: Package #9405 cannot be delivered due to missing address. Pay $1.85 redelivery fee within 24 hours at https://bit.ly/3xVerifyAccount or parcel is returned.",
        "expected_risk": "HIGH",
        "expected_attack_types": [
            "Delivery Scam",
            "Suspicious Shortened URL",
            "Malicious Link",
            "UPI/Payment Fraud",
            "Urgency/Threat Manipulation"
        ],
    },
    {
        "id": "MA05",
        "name": "IRS Tax Fraud + Arrest Coercion + Payment Demand",
        "text": "INTERNAL REVENUE SERVICE NOTICE: Federal tax fraud arrest warrant issued under your SSN. Settle $1,500 immediately via wire transfer or federal marshals will execute arrest within 2 hours.",
        "expected_risk": "HIGH",
        "expected_attack_types": [
            "Government Impersonation",
            "UPI/Payment Fraud",
            "Urgency/Threat Manipulation",
            "Social Engineering"
        ],
    },
    {
        "id": "MA06",
        "name": "Tech Support Scam + Artificial Renewal Threat",
        "text": "Microsoft Defender Alert: Trojan spyware detected (Error 0x800). Your financial files are compromised. Auto-renewed for $499. Call Microsoft certified support immediately at 1-800-555-0199.",
        "expected_risk": "HIGH",
        "expected_attack_types": [
            "Tech Support Scam",
            "Urgency/Threat Manipulation",
            "Social Engineering"
        ],
    },
    {
        "id": "MA07",
        "name": "Fake Job Scam + Advance Registration Fee Demand",
        "text": "Congratulations! You are shortlisted for part-time remote data entry. Earn $300-$500 daily. Pay $35 registration fee via CashApp to receive equipment and begin.",
        "expected_risk": "HIGH",
        "expected_attack_types": [
            "Fake Job Scam",
            "UPI/Payment Fraud"
        ],
    },
    {
        "id": "MA08",
        "name": "Romance Crypto Investment Grooming + Payment Demand",
        "text": "Oh I'm so sorry, wrong number! You seem so kind though. I trade automated crypto trading bots with 25% daily ROI. Send $500 via wire transfer to join our VIP pool today!",
        "expected_risk": "HIGH",
        "expected_attack_types": [
            "Investment/Crypto Scam",
            "Social Engineering",
            "Trust/Grooming Manipulation",
            "UPI/Payment Fraud"
        ],
    },
    {
        "id": "MA09",
        "name": "Obfuscated IP URL + Credential Phishing",
        "text": "System Administrator: Your email account password expires today. Enter credentials at http://0x7f000001/bank/auth.php to retain access.",
        "expected_risk": "HIGH",
        "expected_attack_types": [
            "URL Obfuscation",
            "Malicious Link",
            "Credential Phishing",
            "Password/Account Credential Theft"
        ],
    },
    {
        "id": "MA10",
        "name": "Legitimate Routine Workplace Communication",
        "text": "Hi team, the quarterly performance slides are attached for our project sync meeting scheduled for 3 PM today. Please review beforehand.",
        "expected_risk": "LOW",
        "expected_attack_types": [],
    },
]

