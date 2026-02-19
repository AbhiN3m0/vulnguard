import os
import json
from openai import OpenAI


class OpenAIProvider:
    def __init__(self):
        api_key = os.getenv("VULNGUARD_OPENAI_KEY")
        if not api_key:
            raise ValueError(
                "VULNGUARD_OPENAI_KEY environment variable not set."
            )

        self.client = OpenAI(api_key=api_key)
        self.model = "gpt-4o-mini"  # Fast + good reasoning

    def analyze(self, system_prompt, user_prompt):
        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt},
                ],
                temperature=0.2,
            )

            content = response.choices[0].message.content

            return json.loads(content)

        except Exception as e:
            return {
                "risk_level": "UNKNOWN",
                "is_exploitable": False,
                "reasoning": f"AI analysis failed: {str(e)}",
                "secure_fix": "Manual review required.",
                "confidence": "Low"
            }

