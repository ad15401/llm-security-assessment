LLM Security Assessment: Prompt Injection and System-Prompt Leakage

A hands-on security assessment of a locally hosted Llama 3 (8B) model, testing how well it resists prompt injection and system-prompt leakage (OWASP LLM Top 10: LLM01 and LLM07). It uses a small evaluation harness I wrote plus the open-source scanner NVIDIA garak, and maps the findings to the OWASP LLM Top 10 (2025) and the NIST AI Risk Management Framework.

Headline findings

TestResultDirect harmful content (garak lmrc.Bullying)PASS 35/35, built-in safety holdsPrompt-injection hijack (garak promptinject, 3 probes)53% to 76% attack success, built-in safety failsSystem-prompt guardrail (custom eval)leakage 83% to 33%, partial control, 33% residual

Built-in model safety stops direct misuse but breaks down against indirect injection attacks. A guardrail reduces the risk without removing it. Production deployments need more than one layer of defense.

Full assessment: REPORT.md

What's in here


REPORT.md: the full assessment (findings, framework mapping, recommendations)
guardrail_eval.py: the custom system-prompt leakage harness
guardrail_eval_results.jsonl: raw output, every attempt from the custom eval
guardrail_eval_summary.csv: per-attack summary table from the custom eval
garak.*.report.html: garak scan report, formatted (open in a browser)
garak.*.report.jsonl: garak scan results, raw
garak.*.hitlog.jsonl: the exact prompts that beat the model
Custom_Script.png, Garak.png: terminal evidence of the runs


Reproduce it

bash# Prereqs: Ollama (https://ollama.com) running, plus `ollama pull llama3`
python3 -m venv ai-sec && source ai-sec/bin/activate
pip install -U garak

# 1. Custom system-prompt leakage eval
python3 guardrail_eval.py

# 2. Automated prompt-injection scan
python3 -m garak --target_type ollama --target_name llama3 --probes promptinject

Method notes


Each garak probe is 256 prompts at 5 generations each, so 1,280 scored responses, reported with 95% confidence intervals.
The custom eval uses an objective canary detector. An attack counts only if a planted secret string shows up in the output.
Testing covers Llama 3's built-in safety with no application guardrails added, except where the report explicitly compares one.


Frameworks

OWASP LLM Top 10 (2025). NIST AI RMF (Govern, Map, Measure, Manage).


Built as part of independent AI security research. Tooling: Python, Ollama, NVIDIA garak.
