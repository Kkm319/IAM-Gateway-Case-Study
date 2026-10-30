from gateway import CredentialIssuer, ToolExecutionGateway
import jwt
import json

issuer = CredentialIssuer("task_profiles.json")
gateway = ToolExecutionGateway(issuer)

print("\n==================================================")
print("   ENTERPRISE IAM UPGRADE DEMONSTRATION")
print("==================================================\n")

print("--- 1. CRYPTOGRAPHIC JWT GENERATION ---")
cred_admin = issuer.issue_credential("agent_01", "user_samridhi", "task_1", "email_report")
print("Raw Token String (What the network sees):")
print(f"\033[92m{cred_admin.token_string}\033[0m\n")
print("Decoded Payload (What the Gateway verifies):")
decoded = jwt.decode(cred_admin.token_string, options={"verify_signature": False})
print(json.dumps(decoded, indent=2))
print(f"Signature Valid: {cred_admin.is_valid_signature}\n")

print("--- 2. DYNAMIC ATTRIBUTE-BASED ACCESS CONTROL (ABAC) ---")
print("\nTest A: Admin user attempting to send an approved email...")
req_admin = {
    "agent_id": "agent_01", "user_id": "user_samridhi", "task_id": "task_1",
    "resource": "email", "operation": "send",
    "arguments": {"recipient": "manager@company.com"}, "approval_given": True
}
print(gateway.execute_tool_call(cred_admin, req_admin))

print("\nTest B: Viewer attempting an email operation...")
cred_viewer = issuer.issue_credential("agent_02", "user_guest", "task_2", "email_report")
req_viewer = {
    "agent_id": "agent_02", "user_id": "user_guest", "task_id": "task_2",
    "resource": "email", "operation": "send",
    "arguments": {"recipient": "manager@company.com"}, "approval_given": True
}
print(gateway.execute_tool_call(cred_viewer, req_viewer))
