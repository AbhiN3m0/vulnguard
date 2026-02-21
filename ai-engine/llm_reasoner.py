import sys
import json
import requests

OLLAMA_URL = "http://localhost:11434/api/generate"
MODEL = "mistral"

def call_ollama(prompt):
    try:
        response = requests.post(
            OLLAMA_URL,
            json={
                "model": MODEL,
                "prompt": prompt,
                "stream": False
            }
        )
        return response.json().get("response", "").strip()
    except Exception as e:
        return f"LLM Error: {str(e)}"

def build_prompt(vuln):
    return f"""
You are a senior penetration tester.

Analyze this vulnerability:

Type: {vuln.get('type')}
CWE: {vuln.get('cwe')}
OWASP: {vuln.get('owasp')}
Severity: {vuln.get('severity')}
Confidence: {vuln.get('confidence')}
CVSS: {vuln.get('cvss_score')}

Explain:
1. Why it is exploitable
2. Example payload attacker might use
3. Real-world impact
4. Recommended fix

Keep answer concise and technical.
"""

def main():
    input_data = sys.stdin.read()

    if not input_data.strip():
        print("[]")
        return

    findings = json.loads(input_data)
    enhanced = []

    for vuln in findings:
        prompt = build_prompt(vuln)
        reasoning = call_ollama(prompt)

        vuln["exploit_reasoning"] = reasoning
        enhanced.append(vuln)

    print(json.dumps(enhanced, indent=2))

if __name__ == "__main__":
    main()
