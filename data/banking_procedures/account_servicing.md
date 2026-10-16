# Standard Operating Procedure: Retail Account Servicing and Address Management

**Procedure Code:** SOP-OPS-SRV-004  
**Version:** 4.0  
**Effective Date:** 2024-03-01  
**Regulatory Reference:** Gramm-Leach-Bliley Act (GLBA) & Red Flags Rule (16 CFR Part 681)  

---

## 1. Scope
Applies to customer-initiated modifications of contact details, postal addresses, statement delivery preferences, and authorized signatory mandates.

## 2. Red Flags Rule and High-Risk Activity Safeguards
Address changes represent a primary vector for identity theft and account takeover (ATO). The following controls are mandatory:
1. **Out-of-Band Notification:** Whenever a primary mailing address is changed, an automated notification must be sent to the **prior** address on file and the verified email/SMS.
2. **Post-Change Lockout Period:** For 30 calendar days following an address modification:
   - Replacement debit/credit cards cannot be dispatched to the new address without secondary in-person branch verification or biometric video verification.
   - Large outbound wire requests (> $10,000) trigger enhanced manual review.

## 3. Paper Statement Suppression and Rerouting
1. **Online Delivery Preference:** Verify whether the customer selected 'Paperless / Electronic Only'. If paperless is active, confirm that physical mail suppression is flagged across all core ledger sub-systems.
2. **Mail Return Handling:** If physical statements are returned as 'Undeliverable / Return to Sender', place an administrative postal hold on the account and trigger an online banking prompt upon next customer login.
3. **Branch Verification:** If a customer states that statements are still reaching an old address after an online update:
   - Verify the address status in the Central Customer Information File (CIF).
   - Manually clear any cached mailing routing tables in the statement printing spooler.
   - Issue written confirmation of corrected mailing parameters via encrypted portal message.

## 4. Privacy and Confidentiality
- Never disclose full previous address details or personal identifiers over an unauthenticated channel.
- Ensure all change requests are archived with full audit logging including operator ID, channel, and IP address.
