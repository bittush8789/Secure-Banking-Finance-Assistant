# Standard Operating Procedure: Card Payment Disputes and Fraud Claims

**Procedure Code:** SOP-OPS-CARD-001  
**Version:** 3.2  
**Effective Date:** 2024-01-01  
**Regulatory Reference:** Regulation E (12 CFR Part 1005) & Card Scheme Operating Rules  

---

## 1. Scope and Objective
This procedure establishes the required steps for handling cardholder claims regarding unauthorized debit or credit card transactions, billing errors, counterfeit fraud, and lost/stolen payment cards.

## 2. Customer Intake and Identity Verification
1. Verify the customer identity using standard out-of-band multi-factor authentication (MFA) or branch biometric protocols.
2. Record the date, time, and specific transaction identifiers (ARN, POS merchant identifier, transaction amount).
3. Confirm whether the cardholder currently possesses the physical card.
4. If physical loss or theft is indicated, immediately restrict the card status to **Hotlist/Stolen** in the card management platform.

## 3. Timeline Requirements
- **Notification Period:** Cardholder must report unauthorized charges within 60 calendar days of transmittal of the periodic statement showing the unauthorized debit.
- **Investigation Window:** The bank must complete its initial investigation within 10 business days of notification.
- **Provisional Credit:** If the bank cannot complete the investigation within 10 business days, provisional credit for the disputed amount (minus applicable statutory liability of up to $50) must be credited to the customer account while the investigation continues (up to 45 or 90 calendar days for international/point-of-sale transactions).

## 4. Operational Actions
1. **Initiate Chargeback:** Dispatch dispute to the card network (Visa/Mastercard) citing appropriate reason code (e.g., Reason Code 10.4: Other Fraud in Card-Absent Environment).
2. **Card Reissuance:** Issue a newly generated PAN with randomized expiration and CVV2. Ensure the compromised token is decoupled from digital wallet bindings (Apple Pay/Google Wallet).
3. **Written Communication:** Send a formal Notice of Provisional Credit or Dispute Outcome letter to the customer's verified mailing address within 3 business days of decision.

## 5. Security & Prohibitions
- Operational personnel must **never** ask the customer for their 4-digit PIN, card CVV, or online banking password.
- Representatives must **not** state that a chargeback is guaranteed or that merchant liability has been established prior to scheme arbitration.
