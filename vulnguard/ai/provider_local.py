
import json
import re
import ollama


class LocalAIProvider:
    """
    Local AI provider using Ollama.
    Designed for development and offline testing.
    """

    def __init__(self, model="llama3"):
        self.model = model

    def _extract_json(self, text):
        """
        Extract the first JSON object found in the model response.
        Handles cases where the model wraps JSON in text or markdown.
        """
        try:
            # Remove markdown code fences if present
            text = re.sub(r"```json", "", text)
            text = re.sub(r"```", "", text)

            # Extract first JSON object
            match = re.search(r"\{.*\}", text, re.DOTALL)
            if match:
                return match.group(0)

            return None

        except Exception:
            return None

    def analyze(self, system_prompt, user_prompt):
        try:
            response = ollama.chat(
                model=self.model,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt},
                ],
                options={
                    "temperature": 0.2,
                },
            )

            content = response["message"]["content"]

            json_text = self._extract_json(content)

            if not json_text:
                raise ValueError("No valid JSON object found in response")

            parsed = json.loads(json_text)

            # Validate expected fields
            required_keys = [
                "risk_level",
                "is_exploitable",
                "reasoning",
                "secure_fix",
                "confidence",
            ]

            for key in required_keys:
                if key not in parsed:
                    raise ValueError(f"Missing key in AI response: {key}")

            return parsed

        except Exception as e:
            return {
                "risk_level": "UNKNOWN",
                "is_exploitable": False,
                "reasoning": f"Local AI failed: {str(e)}",
                "secure_fix": "Manual review required.",
                "confidence": "Low",
            }

