# Cursor Tabs Setup — Application + Network Layers (BAS Project)

## 📘 Overview

This guide explains how to set up **AI-assisted feature development tabs in Cursor** for the **Application and Network layers** of your Building Automation System (BAS) controller project. It defines the tabs, their models, usage rules, and example prompts.

---

## 🧭 What, Why, and How

### **What**

A structured, multi-tab AI workflow in Cursor that separates **design**, **critique**, **implementation planning**, **coding**, and **triage**.

### **Why**

* Keeps development **organized and efficient**.
* Reduces **token usage and context drift**.
* Enforces safety, non-blocking behavior, and reliability in the **Application + Network layers**.
* Simplifies handoffs between stages (Design → Implement → Test → Audit).

### **How (Simple Explanation)**

1. Each stage uses a **dedicated tab** pinned to a specific AI model.
2. Each tab has a **short rules message** to keep responses consistent.
3. You pass only a **small handoff block** (summary, decisions, risks, patch plan) between tabs.
4. The AI helps you refine design, plan code changes, generate patches, test, and audit safely.

---

## 🧩 Tabs and Models

| Tab Name                               | Model                     | Purpose                                                                           | Typical Output                      |
| -------------------------------------- | ------------------------- | --------------------------------------------------------------------------------- | ----------------------------------- |
| **Design (Grok-4)**                    | grok-4                    | Create a concise **Design Decision Record (DDR)** with invariants and tradeoffs.  | 8-row decision table + 200w summary |
| **Critique (Grok-4 Fast Reasoning)**   | grok-4-fast-reasoning     | Challenge the DDR—find blind spots, risks, or counterexamples.                    | 5–12 bullet critique list           |
| **Impl Plan (Grok-4)**                 | grok-4                    | Convert DDR into a structured **Patch Plan** (files, signatures, tests, budgets). | Table of ≤12 rows                   |
| **Implement (Grok Code Fast)**         | grok-code-fast-1          | Write or modify code via unified diffs from the Patch Plan.                       | Git-style patches + test checklist  |
| **Triage (Grok-4 Fast Non-Reasoning)** | grok-4-fast-non-reasoning | Parse test or runtime logs into concise TODO lists.                               | Fixlist ≤10 items                   |
| **Sweep (Grok-4)** *(optional)*        | grok-4                    | Audit changed App/Net files for regressions or blocking code.                     | Targeted report                     |

---

## 📋 Tab Rules and Prompts

### **1. Design (grok-4)**

**Rules:**

* Output strictly formatted **DDR table** (≤8 rows).
* Each row = `ID | statement (≤20w) | rationale (≤25w) | status | invariant? (Y/N)`.
* Include a 200w summary and Top-5 risk list.
* Never include implementation details.

**Example prompt:**

> Draft a Design Decision Record for the new HTTP authentication system. Include invariants for clockless HMAC auth, non-blocking I/O, and retry logic.

---

### **2. Critique (grok-4-fast-reasoning)**

**Rules:**

* Only review the **decision table and risks**.
* Produce ≤12 bullet points (risks, blind spots, counterexamples).
* No re-writing or re-designing.

**Example prompt:**

> Review this DDR and list edge cases that could break auth or cause network lockups. Keep your response to 10 concise bullets.

---

### **3. Implementation Plan (grok-4)**

**Rules:**

* Convert DDR into a **Patch Plan** (≤12 rows).
* Each row = `file | op | functions/APIs | tests | perf/mem budget | risk`.
* Include no prose or speculative design.

**Example prompt:**

> Create a Patch Plan to implement the approved DDR for non-blocking SSE and auth token verification.

---

### **4. Implement (grok-code-fast-1)**

**Rules:**

* Generate **unified git patches** only (one per logical change).
* Include short checklist: `pytest → mpremote deploy → device smoke`.
* Never regenerate whole files unless explicitly asked.

**Example prompt:**

> Apply Patch Plan row #3 (network/sse.py). Implement non-blocking SSE with 20s heartbeat and jittered reconnects. Output a unified diff.

---

### **5. Triage (grok-4-fast-non-reasoning)**

**Rules:**

* Input = test or device logs.
* Output = actionable TODO/fixlist (≤10 items).

**Example prompt:**

> Parse this pytest output. Summarize root causes and list fixes ranked by impact.

---

### **6. Sweep (grok-4)** *(Optional)*

**Rules:**

* Audit only changed `application/`, `network/`, or `services/` directories.
* Search for blocking I/O, missing timeouts, unbounded buffers, or auth bypass.
* Output a brief audit summary with file paths.

**Example prompt:**

> Audit all changed files for blocking socket calls and missing timeout handling. Return a short table of issues found.

---

## 🔁 Daily Flow Checklist

1. **Design →** Draft DDR (Sonnet)
2. **Critique →** Review DDR (Grok)
3. **Impl Plan →** Build Patch Plan (Sonnet)
4. **Critique (optional) →** Validate Patch Plan (Grok)
5. **Implement →** Write code diffs (GPT-5)
6. **Triage →** Parse test/device logs (Haiku)
7. **Sweep (optional) →** Audit changed modules (Supernova)

**Repeat** for each new feature or enhancement.

---

## 📦 Handoff Block (copy between tabs)

```
[Summary ≤120w]
[Decisions ≤8 rows: ID | statement | rationale | status | invariant?]
[Top-5 Risks (one-liners)]
[Patch Plan excerpt ≤12 rows or 'pending']
```

---

## 💡 Tips for Low Context & Small Diffs

* Always hand off **summaries**, not full docs.
* Keep **DDR and Patch Plan tables small**.
* For each change, create **one unified diff**.
* Scope audits/sweeps to **changed files only**.
* If responses grow long, remind the model: *"Keep context <400 tokens."*

---

## ✅ Example Invariants for Application + Network Layers

* Non-blocking socket ops (timeouts ≤100ms)
* SSE heartbeat every 20s; jittered reconnect 250–4000ms
* Token auth via HMAC (no clock dependence)
* Telemetry stream uses NDJSON; heapΔ ≤3KB per tick
* API handlers complete ≤150ms p95 latency

---

**End of File**
