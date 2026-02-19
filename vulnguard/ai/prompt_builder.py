def build_prompts(finding, code_snippet):
    system_prompt = """
You are a senior application security expert specializing in OWASP Top 10 vulnerabilities.

Analyze the provided code snippet and determine:

1. Is this vulnerability exploitable?
2. What is the realistic risk level?
3. Why is it vulnerable or safe?
4. Provide a secure fix recommendation.
5. Provide a confidence level (High/Medium/Low).

Respond ONLY in valid JSON format:

{
  "risk_level": "",
  "is_exploitable": true/false,
  "reasoning": "",
  "secure_fix": "",
  "confidence": ""
}
"""

    user_prompt = f"""
Rule ID: {finding['rule_id']}
Rule Name: {finding['name']}
OWASP Category: {finding['owasp']}
Severity (Static): {finding['severity']}
File: {finding['file']}
Line: {finding['line']}

Code Snippet:
----------------
{code_snippet}
----------------
"""

    return system_prompt.strip(), user_prompt.strip()

