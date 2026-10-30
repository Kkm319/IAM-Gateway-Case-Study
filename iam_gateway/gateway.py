import time
import json
import uuid
import logging
import jwt
from typing import Dict, Any

logging.basicConfig(level=logging.INFO, format="%(asctime)s - [%(levelname)s] - %(message)s")

# Demo-only signing key. Replace with a managed secret before any deployment.
SECRET_KEY = "super_secret_enterprise_key_for_research"

USER_DIRECTORY = {
    "user_samridhi": {"role": "admin", "department": "cybersecurity"},
    "user_guest": {"role": "viewer", "department": "general"}
}

ROLE_PERMISSIONS = {
    "admin": ["document:read", "email:send", "file_store:read", "file_store:delete", "*:*"],
    "viewer": ["document:read"]
}

class ABACEngine:
    @staticmethod
    def get_user_entitlements(user_id: str) -> list:
        user = USER_DIRECTORY.get(user_id, {})
        role = user.get("role", "guest")
        return ROLE_PERMISSIONS.get(role, [])

class TaskCredential:
    def __init__(self, token_string: str, profile: dict, violation_count: int = 0, is_revoked: bool = False):
        self.token_string = token_string
        try:
            decoded = jwt.decode(token_string, SECRET_KEY, algorithms=["HS256"])
            self.token_id = decoded["token_id"]
            self.agent_id = decoded["agent_id"]
            self.user_id = decoded["user_id"]
            self.task_id = decoded["task_id"]
            self.profile_name = decoded["profile_name"]
            self.expires_at = decoded["exp"]
            self.issued_at = decoded["iat"]
            self.is_valid_signature = True
        except jwt.InvalidTokenError:
            self.token_id = None
            self.agent_id = None
            self.user_id = None
            self.task_id = None
            self.profile_name = None
            self.expires_at = 0
            self.issued_at = 0
            self.is_valid_signature = False
        self.profile = profile
        self.violation_count = violation_count
        self.is_revoked = is_revoked

    def is_valid(self) -> bool:
        return self.is_valid_signature and not self.is_revoked and time.time() < self.expires_at

class CredentialIssuer:
    def __init__(self, profiles_path: str):
        with open(profiles_path, "r", encoding="utf-8") as f:
            self.profiles = json.load(f)

    def issue_credential(self, agent_id: str, user_id: str, task_id: str, profile_name: str) -> TaskCredential:
        if profile_name not in self.profiles:
            raise ValueError(f"Unknown task profile: {profile_name}")
        now = int(time.time())
        profile = self.profiles[profile_name]
        payload = {
            "token_id": str(uuid.uuid4()),
            "agent_id": agent_id,
            "user_id": user_id,
            "task_id": task_id,
            "profile_name": profile_name,
            "iat": now,
            "exp": now + int(profile["ttl_seconds"])
        }
        token_string = jwt.encode(payload, SECRET_KEY, algorithm="HS256")
        return TaskCredential(token_string, profile)

class ToolExecutionGateway:
    def __init__(self, issuer: CredentialIssuer):
        self.issuer = issuer
        self.audit_log = []

    def execute_tool_call(self, credential: TaskCredential, request: Dict[str, Any], user_entitlements: list = None) -> Dict[str, Any]:
        started = time.perf_counter()
        reason = "ALLOWED"
        allowed = True

        if not credential.is_valid():
            allowed, reason = False, "INVALID_OR_EXPIRED_CREDENTIAL"
        elif request.get("agent_id") != credential.agent_id or request.get("user_id") != credential.user_id or request.get("task_id") != credential.task_id:
            allowed, reason = False, "IDENTITY_OR_TASK_BINDING_MISMATCH"
        else:
            entitlements = user_entitlements if user_entitlements is not None else ABACEngine.get_user_entitlements(credential.user_id)
            permission = f"{request.get('resource')}:{request.get('operation')}"
            if permission not in entitlements and "*:*" not in entitlements:
                allowed, reason = False, "USER_NOT_ENTITLED"
            profile = credential.profile
            permitted = any(
                (item["resource"] == request.get("resource") or item["resource"] == "*")
                and (item["operation"] == request.get("operation") or item["operation"] == "*")
                for item in profile.get("allowed_operations", [])
            )
            if allowed and not permitted:
                allowed, reason = False, "OUTSIDE_TASK_SCOPE"
            if allowed:
                for key, allowed_values in profile.get("argument_constraints", {}).items():
                    if key in request.get("arguments", {}) and request["arguments"][key] not in allowed_values:
                        allowed, reason = False, f"ARGUMENT_CONSTRAINT_FAILED:{key}"
                        break
            if allowed and permission in profile.get("requires_approval", []) and not request.get("approval_given", False):
                allowed, reason = False, "APPROVAL_REQUIRED"

        if not allowed:
            credential.violation_count += 1
            if credential.violation_count >= int(credential.profile.get("max_violations", 3)):
                credential.is_revoked = True
                reason += "; CREDENTIAL_REVOKED"

        latency_ms = (time.perf_counter() - started) * 1000
        outcome = {
            "status": "ALLOW" if allowed else "DENY",
            "reason": reason,
            "latency_ms": round(latency_ms, 4)
        }
        self.audit_log.append({
            "timestamp": time.time(),
            "token_id": credential.token_id,
            "agent_id": credential.agent_id,
            "user_id": credential.user_id,
            "task_id": credential.task_id,
            "resource": request.get("resource"),
            "operation": request.get("operation"),
            **outcome
        })
        logging.info("Authorization decision: %s (%s)", outcome["status"], reason)
        return outcome
