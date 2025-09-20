import json
from openai import OpenAI
from dotenv import load_dotenv

load_dotenv(override=True)

def make_llm_prompt(finding, project_context=""):
    return f"""
You are a security assistant helping developers fix vulnerabilities in their project.

Project Context:
{project_context}

Vulnerability Details:
- CVE: {finding['cve']}
- Package: {finding['pkg']} (Installed: {finding['installed']} → Fixed: {finding['fixed']})
- Severity: {finding['severity']}
- CVSS Score: {finding.get('cvss')}
- KEV Known Exploited: {finding.get('kev')}

Task:
1. Assign a priority (Critical, High, Medium, Ignore).
2. Explain in plain language why this matters.
3. Suggest the best recommended fix (upgrade, config, or mitigation).

Respond in JSON:
{{
  "priority": "...",
  "explanation": "...",
  "recommended_fix": "..."
}}
"""

client = OpenAI()

def analyze_with_llm(finding, project_context=""):

    prompt = make_llm_prompt(finding, project_context)
    # print(f"Making call with ", finding, project_context, prompt)
    response = client.chat.completions.create(
        model="gpt-4o-mini",  # or "gpt-4o" if you want stronger reasoning
        messages=[{"role": "user", "content": prompt}],
        temperature=0.2,
        response_format={"type": "json_object"}
    )
    raw = response.choices[0].message.content or ""
    # print(f"LLM raw content: {raw!r}")
    # Parse the JSON output
    try:
        result = json.loads(response.choices[0].message.content)
    except Exception as e:
        print("Failed to parse LLM response", e)
        result = {"priority": "Unknown", "explanation": "Parse error", "recommended_fix": "Check manually"}

    return result

