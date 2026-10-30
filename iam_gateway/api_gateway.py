from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import Dict, Any, Optional
from gateway import CredentialIssuer, ToolExecutionGateway, TaskCredential
import time

app = FastAPI(title="Task-Scoped Credential Gateway - Max Edition")
issuer = CredentialIssuer("task_profiles.json")
gateway = ToolExecutionGateway(issuer)

active_credentials = {}
# Broad user entitlements mimicking Setup B from the paper
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
    # Fulfills Multi-Agent Delegation Chains (Future Scope)
    parent = active_credentials.get(req.parent_token_id)
    if not parent or not parent.is_valid():
        raise HTTPException(status_code=401, detail="Invalid Parent Token")
    try:
        # Issue a fresh, short-lived token for the sub-agent
        child_cred = issuer.issue_credential(req.sub_agent_id, parent.user_id, req.task_id, req.profile_name)
        active_credentials[child_cred.token_id] = child_cred
        return {"status": "SUCCESS", "delegated_token_id": child_cred.token_id}
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.post("/execute_tool")
def execute_tool(req: ToolCallRequest):
    cred = active_credentials.get(req.token_id)
    if not cred:
        raise HTTPException(status_code=401, detail="Credential not found or revoked")
    
    request_data = req.dict(exclude={"token_id"})
    result = gateway.execute_tool_call(cred, request_data, user_entitlements)
    return result

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8000)
