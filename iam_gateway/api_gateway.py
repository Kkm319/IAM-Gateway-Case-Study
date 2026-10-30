from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import Dict, Any
from gateway import CredentialIssuer, ToolExecutionGateway
import time

app = FastAPI(title="Task-Scoped Credential Gateway - Max Edition")
issuer = CredentialIssuer("task_profiles.json")
gateway = ToolExecutionGateway(issuer)

active_credentials = {}
user_entitlements = ["document:read", "email:send", "file_store:read", "file_store:delete", "*:*"]

class TaskRequest(BaseModel):
    agent_id: str
    user_id: str
    task_id: str
    profile_name: str

class DelegateRequest(BaseModel):
    parent_token_id: str
    sub_agent_id: str
    task_id: str
    profile_name: str

class ToolCallRequest(BaseModel):
    token_id: str
    agent_id: str
    user_id: str
    task_id: str
    resource: str
    operation: str
    arguments: Dict[str, Any] = {}
    approval_given: bool = False

@app.post("/issue_token")
def issue_token(req: TaskRequest):
    try:
        cred = issuer.issue_credential(req.agent_id, req.user_id, req.task_id, req.profile_name)
        active_credentials[cred.token_id] = cred
        return {"status": "SUCCESS", "token_id": cred.token_id, "expires_at": cred.expires_at}
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.post("/delegate_token")
def delegate_token(req: DelegateRequest):
    parent = active_credentials.get(req.parent_token_id)
    if not parent or not parent.is_valid():
        raise HTTPException(status_code=401, detail="Parent credential is invalid or expired")
    try:
        child = issuer.issue_credential(req.sub_agent_id, parent.user_id, req.task_id, req.profile_name)
        active_credentials[child.token_id] = child
        return {"status": "SUCCESS", "token_id": child.token_id, "expires_at": child.expires_at}
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.post("/execute_tool")
def execute_tool(req: ToolCallRequest):
    cred = active_credentials.get(req.token_id)
    if not cred:
        raise HTTPException(status_code=401, detail="Unknown credential")
    request = req.model_dump(exclude={"token_id"})
    result = gateway.execute_tool_call(cred, request, user_entitlements)
    return result

@app.get("/audit")
def get_audit_log():
    return {"events": gateway.audit_log}
