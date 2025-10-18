# Secure Google Cloud API Connection Design

## Overview
This design document outlines a secure approach for connecting to Google Cloud APIs (e.g., Firestore) in a personal project like the BAS System. It focuses on learning and demonstrating authentication security best practices, using service accounts with simplifications for hands-on implementation. The goal is to provide a secure, educational setup without overhauling the existing auth architecture—think of this as an enhancement layer for API interactions.

This is tailored for a solo developer project: easy to set up, test, and document in a GitHub repo or blog post. It builds on existing code (e.g., your database audit store) while introducing concepts like least privilege and secret management.

## Key Design Decisions
These decisions are derived from security best practices (e.g., Google's IAM guidelines, OWASP, and zero-trust principles), scoped for personal learning. Each includes rationale and trade-offs.

1. **Use Google Cloud Service Accounts for API Authentication**  
   - **Statement**: Adopt service accounts as the primary method for app-to-API auth.  
   - **Rationale**: Service accounts provide a managed identity for applications, avoiding the risks of using personal user credentials. This demonstrates secure programmatic access in a cloud environment.  
   - **Trade-offs**: Adds setup time (creating the account in Google Cloud Console) but improves security and is easier to manage than manual API keys. In a personal project, it's low-cost and scalable for demos. Alternative: Sticking with user auth tokens would be simpler but less secure for unattended apps.

2. **Categorize Permissions with Basic RBAC Roles**  
   - **Statement**: Group permissions into basic roles like "read-telemetry" or "write-config."  
   - **Rationale**: Enables least privilege by assigning only necessary access, making it easy to demo and audit in a personal project.  
   - **Trade-offs**: Slightly more complex IAM setup vs. flat permissions, but reduces risks like unauthorized data access. Great for learning RBAC without needing advanced tools like ABAC.

3. **Apply Least Privilege to Service Account Roles**  
   - **Statement**: Grant minimal permissions to each role, e.g., read-only for telemetry queries.  
   - **Rationale**: Minimizes damage from compromises; a core security concept to showcase in demos.  
   - **Trade-offs**: Requires careful planning to avoid under-provisioning (e.g., API failures), but it's straightforward to test and adjust in a personal codebase.

4. **Implement Google Secret Manager for Key Rotation and Storage**  
   - **Statement**: Use GSM for simple operations like storing and retrieving service account keys.  
   - **Rationale**: Teaches cloud-native secret management with built-in rotation, more secure than local .env files.  
   - **Trade-offs**: Introduces a Google Cloud dependency and small costs (~$0.06 per secret/month), but simplifies demos compared to manual rotation. Avoids advanced features like replication for ease.

5. **Use Existing DB Audit Log Store for API Logging**  
   - **Statement**: Log API accesses to your codebase's existing audit store (e.g., Firestore collection).  
   - **Rationale**: Integrates seamlessly with current architecture, enabling easy anomaly detection for learning monitoring basics.  
   - **Trade-offs**: Could increase DB usage/costs if logs are verbose, but simple filtering mitigates this. Better than new logging infra for a personal project.

6. **Use Short-Lived Tokens for API Calls**  
   - **Statement**: Generate temporary tokens for each API interaction.  
   - **Rationale**: Limits impact if tokens are stolen; aligns with zero-trust for educational demos.  
   - **Trade-offs**: Adds token refresh logic but enhances security without much overhead.

7. **Avoid Embedding Credentials; Document in README**  
   - **Statement**: Store creds externally and explain setup in project docs.  
   - **Rationale**: Prevents accidental exposure in code/repos; emphasizes best practices for sharing knowledge.  
   - **Trade-offs**: Relies on proper env setup, but it's simple and promotes good habits.

8. **Implement OAuth as Alternative for Hybrid Auth**  
   - **Statement**: Add OAuth flows as a fallback to service accounts.  
   - **Rationale**: Provides flexibility for non-IAM scenarios, demonstrating hybrid auth in demos.  
   - **Trade-offs**: More code to maintain, but reduces dependency risks and enriches learning.

## Architecture Impact
This isn't a full auth system overhaul—it's an additive layer for API connections. It integrates with your existing codebase (e.g., Firestore client) without breaking current flows. For example:
- Existing auth (e.g., user logins) remains unchanged.
- New: Wrap API calls with service account auth, logging to your audit store.

**High-Level Flow**:
1. App fetches secret from GSM.
2. Generates short-lived token via service account.
3. Makes API call with token.
4. Logs access to DB audit store.
5. Fallback to OAuth if needed.

## Top-5 Risks and Mitigations
1. **Key Compromise from GSM Misconfiguration**: Mitigate with IAM controls and test rotations.  
2. **Overly Broad Permissions**: Test roles and document in README.  
3. **Misconfiguration in Experiments**: Add unit tests for auth flows.  
4. **DB Audit Overload**: Implement log filtering/sampling.  
5. **IAM Dependency**: Implement OAuth for hybrid flexibility.

## Implementation Notes
- **Tools**: Use `google-cloud-secret-manager` and `google-auth` Python libraries.
- **Demo Ideas**: Include a Jupyter notebook showing setup, a test script for auth flows, and a blog section explaining trade-offs.
- **Learning Focus**: This design lets you demonstrate concepts like least privilege and secret management in a real project.

For more details, see the DDR table in the project docs.
