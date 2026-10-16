# Standard Operating Procedure: Merchant Refunds and Credit Adjustments

**Procedure Code:** SOP-OPS-REF-003  
**Version:** 1.8  
**Effective Date:** 2024-02-01  
**Regulatory Reference:** CFPB Bulletin 2022-06 & Merchant Payment Rules  

---

## 1. Overview
This procedure details customer inquiries concerning delayed or missing merchant refunds across debit card purchases, ACH direct credits, and wire returns.

## 2. Standard Settlement Timelines
Merchant refunds are processed through independent clearing networks with specific SLA windows:
- **Debit Card POS / E-Commerce Refunds:** 3 to 7 business days from merchant transaction submission date.
- **ACH Direct Merchant Credits:** 2 to 5 business days from ODFI entry date.
- **International Inward Wire Transfers:** 5 to 10 business days subject to correspondent banking sanctions screening.

## 3. Handling Delayed Refund Inquiries
When a customer indicates that a merchant refund has not posted after the standard timeline:
1. **Require Proof of Refund:** Obtain a merchant credit voucher, cancellation receipt, or ARN from the customer.
2. **Search Unmatched Holding Queue:** Cross-check the bank's Automated Clearing House (ACH) exception file and card clearing holding pool for unmatched customer account references.
3. **Escalate to Clearing Operations:** If the refund receipt exceeds 15 business days without ledger posting, file an inward payment tracing request via the Clearing Operations desk.

## 4. Disputed Merchant Refund Requests
If the merchant refuses to issue a promised refund or fails to respond:
- Evaluate eligibility for card chargeback under condition **Credit Not Processed** (Mastercard Code 4853 / Visa Condition 13.6).
- Customer must provide evidence of attempting to resolve the matter directly with the merchant and cancellation documentation.

## 5. Explicit Limitations
- The bank does not advance funds or provide immediate goodwill credits for merchant refund delays unless mandated under an active formal chargeback arbitration.
- Employees must never guarantee that a credit will post on an exact date when clearing network delays are outside the bank's immediate control.
