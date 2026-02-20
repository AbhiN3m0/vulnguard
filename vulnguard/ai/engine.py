from vulnguard.ai.provider_openai import OpenAIProvider
from vulnguard.ai.provider_local import LocalAIProvider


class AIEngine:
    def __init__(self, provider="local"):
        if provider == "openai":
            self.provider = OpenAIProvider()
        elif provider == "local":
            self.provider = LocalAIProvider()
        else:
            raise ValueError(f"Unknown AI provider: {provider}")

    def analyze(self, system_prompt, user_prompt):
        return self.provider.analyze(system_prompt, user_prompt)

