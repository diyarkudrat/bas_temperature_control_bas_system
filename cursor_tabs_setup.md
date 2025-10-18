# Cursor Tabs Setup — Application + Network Layers (BAS Project)

## 📘 Overview

This guide explains how to set up **AI-assisted feature development tabs in Cursor** for the **Application and Network layers** of your Building Automation System (BAS) controller project. It defines the tabs, their models, usage rules, and example prompts. This whole setup is a fun experiment idea when developing with Cursor—adapt or simplify it to match your team’s style.

Note: In this guide, “tabs” refers to Cursor chat windows/threads.

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

## ℹ️ About `.cursorrules`

**What it is**

-.cursorrules is a small, repo-local rules file (in the project root) that Cursor reads to steer AI responses for this project.

**Purpose**

- Keep outputs consistent, small, and deterministic across tabs
- Encode the 6‑tab workflow, roles, models, and allowed formats
- Provide a shared handoff block and guardrails (e.g., no code in Design)

**How Cursor uses it**

- When you work in a tab or chat window, Cursor pairs your prompt with these rules to shape the answer: output size limits, table formats, and the exact handoff data to pass between tabs.

**Quick walkthrough of sections**

- **Refine Mode**: If a message starts with “REFINE:” or asks about the DDR, temporarily switch to conversational design clarification (no size limits), then return to the standard DDR format when asked.
- **Tab 1 — Design (Grok‑4)**: Produce a DDR table (≤8 rows). Row format: `ID | statement | rationale | status | invariant?`. Include ≤200‑word summary and Top‑5 risks. No implementation or code.
- **Tab 2 — Critique (Grok‑4 Fast Reasoning)**: Review only the DDR table and risks; output 5–12 concise bullets highlighting risks/blind spots. No re‑designing.
- **Tab 3 — Implementation Plan (Grok‑4)**: Convert DDR into a Patch Plan table (≤12 rows): `file | op | functions/APIs | tests | perf/mem budget | risk`. No prose.
- **Tab 4 — Implement (Grok Code Fast)**: Output unified diffs only, one per logical change, with brief explanation and a small test checklist. Don’t regenerate whole files; include line numbers.
- **Tab 5 — Triage (Grok‑4 Fast Non‑Reasoning)**: Parse test/device logs into an actionable TODO/fixlist (≤10 items) plus a short root‑cause summary.
- **Tab 6 — Sweep (Grok‑4)**: Audit only changed `application/`, `network/`, or `services/` files; return a brief summary and an issues table (file, line, type, severity).
- **Handoff Format**: A compact block passed between tabs: short summary, decisions table, Top‑5 risks, and a Patch Plan excerpt.
- **Tab Workflow**: The standard path: Design → Critique → Impl Plan → (Critique) → Implement → Triage → (Sweep).


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

For exact per‑tab rules, output budgets, and example prompt formats, see `.cursorrules` in the project root. That file is the canonical source; use the table above for quick reference.

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