from vulnguard.ai.engine import AIEngine
from vulnguard.ai.prompt_builder import build_prompts


def enrich_findings(findings, file_loader, provider="local"):
    engine = AIEngine(provider=provider)

    enriched = []

    for finding in findings:
        try:
            code_snippet = file_loader(
                finding["file"],
                finding["line"],
                context=5
            )

            system_prompt, user_prompt = build_prompts(
                finding,
                code_snippet
            )

            ai_result = engine.analyze(system_prompt, user_prompt)

            finding["ai"] = ai_result

        except Exception as e:
            finding["ai"] = {
                "risk_level": "UNKNOWN",
                "is_exploitable": False,
                "reasoning": f"AI enrichment failed: {str(e)}",
                "secure_fix": "Manual review required.",
                "confidence": "Low"
            }

        enriched.append(finding)

    return enriched

