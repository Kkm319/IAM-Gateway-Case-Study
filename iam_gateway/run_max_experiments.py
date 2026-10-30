import requests
import base64

BASE_URL = "http://127.0.0.1:8000"

def run_network_experiments():
    print("=== RUNNING ADVANCED NETWORK EVALUATIONS ===")

    print("\n--- Running Scenario T7: Misuse Within Granted Permission ---")
    res = requests.post(f"{BASE_URL}/issue_token", json={
        "agent_id": "agent_01", "user_id": "user_samridhi", "task_id": "task_202", "profile_name": "email_report"
    })
    res.raise_for_status()
    token_t7 = res.json()["token_id"]
    stolen_data = base64.b64encode(b"CONFIDENTIAL_RECORDS").decode("utf-8")
    tool_req_t7 = {
        "token_id": token_t7, "agent_id": "agent_01", "user_id": "user_samridhi",
        "task_id": "task_202", "resource": "email", "operation": "send",
        "arguments": {"recipient": "manager@company.com", "body": f"Hidden payload: {stolen_data}"},
        "approval_given": True
    }
    outcome_t7 = requests.post(f"{BASE_URL}/execute_tool", json=tool_req_t7)
    outcome_t7.raise_for_status()
    print(f"Outcome: {outcome_t7.json()['status']} (illustrates the documented residual risk)")

    print("\n--- Running Scenario T8: Misconfigured Policy (Wildcard) ---")
    res = requests.post(f"{BASE_URL}/issue_token", json={
        "agent_id": "agent_01", "user_id": "user_samridhi", "task_id": "task_203", "profile_name": "wildcard_admin_t8"
    })
    res.raise_for_status()
    token_t8 = res.json()["token_id"]
    req_t8 = {
        "token_id": token_t8, "agent_id": "agent_01", "user_id": "user_samridhi",
        "task_id": "task_203", "resource": "file_store", "operation": "delete",
        "arguments": {"path": "/archive/important_record.txt"}, "approval_given": False
    }
    result = requests.post(f"{BASE_URL}/execute_tool", json=req_t8)
    result.raise_for_status()
    print(f"Outcome: {result.json()['status']} (demonstrates broad-profile residual risk)")

if __name__ == "__main__":
    run_network_experiments()
