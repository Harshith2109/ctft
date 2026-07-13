# Sample Emails for Phishing Detection Testing

This file contains sample emails to test the Explainable AI Phishing Detection system. Copy and paste the blocks below into the text area of the application to test different detection features.

---

## 1. Verified Brand & DKIM (Legitimate Email)
* **Features tested**: Verified Brand override (forces classification to **Safe**), DKIM verification status (`signed-by`), and clean URLs.

```text
From: security@paypal.com
Signed-by: paypal.com
Subject: Your monthly PayPal account statement is ready

Dear Customer,

Your monthly account statement for June 2026 is now available. You can view your transactions by logging securely into your account on our website.

For security reasons, please always ensure you are on https://www.paypal.com before entering your password.

Thank you,
PayPal Security Team
```

---

## 2. Lookalike Domain Spoofing & High-Risk Attachment (Phishing)
* **Features tested**: Domain spoofing check (`paypa1` vs `paypal`), high-risk attachment analysis (`.exe`), and suspicious term rules (`verify`, `update card`, `urgent`).

```text
From: support@paypa1-update.com
Attachment: security_update.exe
Subject: URGENT: Update your account details

Dear user,

We detected suspicious login attempts on your account. To prevent suspension, you must verify your identity immediately. 

Please download and run the attached security updater to update card details and restore your account.

Regards,
Customer Support
```

---

## 3. Suspicious Link & IP-Based URL (Phishing)
* **Features tested**: IP address detection in URLs, long URL flag, and ML/Rules-based classification (high risk score due to keywords like `click here`, `claim`, `winner`, `free`).

```text
From: rewards@gift-winner-centre.org
Subject: You are a winner! Claim your free gift card now

Congratulations! 

Your email has been selected as the grand prize winner of our promotional draw. To claim your free $1000 gift card, click here to access the claim form:

http://192.168.99.12/claims/verify/secure/auth/session/token/a89f92ba3c8d19a2e3427fcd?id=9928371

This offer is available for a limited time only, so act now!
```

---

## 4. Lookalike Brand Domain & DKIM Misalignment (Suspicious/Phishing)
* **Features tested**: Brand misuse (`nettflix.com` domain check), DKIM mismatch (signed by an unrelated domain `external-mail.org`), and risk keywords (`account suspended`, `update card`).

```text
From: billing@nettflix.com
Signed-by: external-mail.org
Subject: Netflix Account Suspended: Action Required

Dear Member,

Your Netflix subscription could not be renewed due to a payment failure. Your account is temporarily suspended. 

To resolve this and continue streaming, please click the link below to verify your billing information and update card records.

http://nettflix-billing-portal.com/update

Netflix Support
```

---

## 5. Standard Low-Risk Transactional (Safe Email)
* **Features tested**: Normal layout, no spoofed domains, no attachments, and typical conversational/transactional text that should be classified as **Safe**.

```text
From: manager@localbusiness.com
Subject: Schedule for tomorrow's project sync

Hi Team,

Just a quick reminder that our weekly project sync is scheduled for tomorrow at 10:00 AM. 

We will review the current phase milestones, assign tasks for the next sprint, and address any blockers. Please update your status sheets before the meeting.

See you tomorrow,
Project Manager
```
