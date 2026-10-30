# Identity-Aware Task-Scoped Credential Gateway

A research-based prototype exploring how task-scoped credentials and policy enforcement can limit the impact of indirect prompt injection in tool-using AI agents.

This repository accompanies the research article **“Identity-Aware Task-Scoped Credentials for Limiting Indirect Prompt-Injection Damage in Tool-Using AI Agents.”**

## Project overview

Tool-using AI agents can process untrusted documents, emails and web content while holding credentials that allow them to interact with external tools. Indirect prompt injection may manipulate an agent into proposing an action the user did not request.

This prototype places an authorization gateway between an agent and its tools. It issues task-specific credentials and checks proposed tool calls against task profiles and user entitlements.

## Repository structure

| File | Purpose |
|---|---|
| `iam_gateway/gateway.py` | Credential issuance, JWT validation, ABAC checks, authorization decisions, violation counting and audit logging |
| `iam_gateway/api_gateway.py` | FastAPI endpoints for issuing credentials, delegating credentials and submitting tool calls |
| `iam_gateway/task_profiles.json` | Task profiles, permitted operations, argument constraints, approval requirements and credential lifetimes |
| `iam_gateway/agent_simulator.py` | Generates legitimate and injection-style tool-call requests |
| `iam_gateway/evaluation.py` | Runs local scenarios and prints prototype evaluation outputs |
| `iam_gateway/demo_enterprise.py` | Demonstrates JWT issuance and role-based authorization outcomes |
| `iam_gateway/run_max_experiments.py` | Sends API-based tests for residual-risk scenarios and credential delegation |

## Prototype workflow

1. A task is started with an agent ID, user ID, task ID and named task profile.
2. The issuer creates an HS256-signed JWT containing agent, user, task, profile and validity information.
3. A proposed tool call is submitted with its resource, operation and arguments.
4. The gateway checks credential validity, identity binding, user entitlements, task scope, argument constraints and required approval.
5. The gateway allows or denies the request and records a decision with a reason code and authorization latency.
6. Repeated denied requests increment a violation counter; reaching the profile threshold revokes the credential in the running process.

## Requirements

Python 3.10 or later is recommended.

Install dependencies:

```bash
pip install fastapi uvicorn PyJWT requests
```

## Run the demonstrations

Run commands from the repository root.

### Local scenario evaluation

```bash
cd iam_gateway
python evaluation.py
```

### JWT and ABAC demonstration

```bash
cd iam_gateway
python demo_enterprise.py
```

### Start the API gateway

In one terminal:

```bash
cd iam_gateway
uvicorn api_gateway:app --reload
```

API base URL: `http://127.0.0.1:8000`

Interactive API documentation: `http://127.0.0.1:8000/docs`

### Run API-based experiments

With the API server running, open a second terminal:

```bash
cd iam_gateway
python run_max_experiments.py
```

## API endpoints

| Method | Endpoint | Purpose |
|---|---|---|
| POST | `/issue_token` | Issue a credential for a selected task profile |
| POST | `/execute_tool` | Submit a tool call for authorization |
| POST | `/delegate_token` | Demonstrate issuing a credential for a sub-agent |

## Research evaluation context

The research article proposes comparisons between unrestricted access, static least privilege and the task-scoped gateway. It identifies legitimate tasks, injected email exfiltration, unrelated file reads, protected-record modification/deletion, credential replay, misuse within granted permissions and wildcard policy misconfiguration.

The supplied scripts exercise a subset of these concepts. Their printed values are prototype outputs, not a complete controlled experimental evaluation or statistically validated results.

## Limitations and security notes

- `gateway.py` currently contains a hardcoded JWT signing key. Replace it with a securely managed environment secret before any deployment. Do not use the demo key in production.
- User identities and role entitlements are simulated in code.
- Credentials and revocation state in the API example are held in process memory, not a persistent credential store.
- The delegation endpoint issues a credential, but does not fully enforce parent-child scope intersection or a complete multi-agent delegation policy.
- Tool operations are simulated authorization decisions; the prototype does not connect to production document, email or file systems.
- The gateway can constrain whether a tool call is authorized, but it cannot reliably determine whether the contents of an otherwise permitted action are malicious.
- The wildcard task profile deliberately demonstrates how an over-broad policy can undermine least privilege.

The accompanying paper presents a broader proposed architecture and evaluation plan. This repository should be understood as an academic prototype, not as evidence that every proposed component or experiment has been fully implemented.

## Academic context

Identity and Access Management (CSF20190), MIT World Peace University, Pune, 2026–27.
