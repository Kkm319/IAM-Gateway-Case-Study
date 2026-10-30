class AgentSimulator:
    def __init__(self, agent_id: str, user_id: str, task_id: str):
        self.agent_id = agent_id
        self.user_id = user_id
        self.task_id = task_id

    def propose_legitimate_read(self, doc_name: str) -> dict:
        return {"agent_id": self.agent_id, "user_id": self.user_id, "task_id": self.task_id, "resource": "document", "operation": "read", "arguments": {"doc_id": doc_name}}

    def propose_injected_exfiltration(self, recipient: str, data: str) -> dict:
        return {"agent_id": self.agent_id, "user_id": self.user_id, "task_id": self.task_id, "resource": "email", "operation": "send", "arguments": {"recipient": recipient, "body": data}}

    def propose_injected_unrelated_read(self, file_path: str) -> dict:
        return {"agent_id": self.agent_id, "user_id": self.user_id, "task_id": self.task_id, "resource": "file_store", "operation": "read", "arguments": {"path": file_path}}
