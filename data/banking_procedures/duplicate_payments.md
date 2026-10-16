# Standard Operating Procedure: Duplicate Debit and Payment Error Resolution

**Procedure Code:** SOP-OPS-DUP-002  
**Version:** 2.4  
**Effective Date:** 2024-01-15  
**Regulatory Reference:** NACHA Operating Rules & Electronic Fund Transfer Act (EFTA)  

---

## 1. Scope
This document governs complaints regarding duplicate debits originating from automated clearing house (ACH) batches, merchant POS terminal duplicate batches, recurring bill pay debits, or internal ledger re-entries.

## 2. Intake Criteria and Verification
When a customer reports a duplicate transaction:
1. **Compare Transaction Fields:** Compare the settlement timestamp, merchant reference, trace number, terminal ID, and exact amount down to the cent.
2. **Distinguish Pending vs. Settled:**
   - **Pending Authorization:** If one or both items are in pending authorization status, explain to the customer that merchant batch holds typically expire within 72 hours. Do not initiate an ACH return on a pending pre-authorization.
   - **Both Settled:** If both transactions have posted as final settled entries, an operational duplicate case must be registered immediately.

## 3. Resolution Pathways
### A. ACH Duplicate Entries
- If the originating depository financial institution (ODFI) transmitted duplicate entries, file an ACH Return using reason code **R05** (Unauthorized Debit to Consumer Account Using Corporate SEC Code) or **R10** (Customer Advises Unauthorized).
- ACH return must be submitted within 2 banking days for immediate same-day credit or within 60 calendar days under NACHA consumer rules.

### B. Merchant POS Duplication
- Submit an electronic chargeback under scheme reason code 4834 / 82 (Duplicate Processing).
- Document the two matching Acquirer Reference Numbers (ARNs).

## 4. Fee Waivers and Operational Remediation
- If the duplicate entry resulted in non-sufficient funds (NSF) or overdraft fees, the representative must submit an automated fee reversal request.
- Fee reversal must post within 24 business hours.
- Notify the customer via secure message or SMS of the pending fee adjustment.

## 5. Employee Constraints
- Do not promise an instantaneous funds credit without verification of the settlement batch status.
- Never manually alter ledger balances outside the authorized exception adjustment workflow.
