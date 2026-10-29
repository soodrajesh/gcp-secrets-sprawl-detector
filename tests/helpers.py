import json

from sprawl.llm import LLM, LLMResult

# Synthetic, clearly fake credentials in the real formats. None of these is a live secret.
AWS = "AKIA" + "QWERTYUIOPASDFGH"
GH = "ghp_" + "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8"
DB_PASS = "S3cr3tPassw0rd!x9"
DB = f"postgres://app:{DB_PASS}@10.0.0.5:5432/db"
STRIPE = "sk_live_" + "4eC39HqLyjWDarjtT1zdp7dc"
SA_KEY_ID = "0123456789abcdef0123456789abcdef01234567"
SA_EMAIL = "deployer@demo-proj.iam.gserviceaccount.com"
SA_JSON = json.dumps(
    {
        "type": "service_account",
        "project_id": "demo-proj",
        "private_key_id": SA_KEY_ID,
        "private_key": "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASC\n-----END PRIVATE KEY-----\n",
        "client_email": SA_EMAIL,
        "client_id": "1234",
    }
)
ALL_SECRET_VALUES = [AWS, GH, DB_PASS, STRIPE, SA_KEY_ID, "MIIEvQIBADANBgkqhkiG9w0BAQEFAASC"]


class ScriptedLLM(LLM):
    name, model = "scripted", "scripted-1"

    def __init__(self, reply=None, *, raises=None):
        self.reply, self.raises, self.calls, self.seen = reply, raises, 0, []

    async def complete_json(self, system, user, max_tokens=1200):
        self.calls += 1
        self.seen.append(user)
        if self.raises:
            raise self.raises
        r = self.reply(json.loads(user)) if callable(self.reply) else self.reply
        return LLMResult(r if isinstance(r, str) else json.dumps(r), 50, 20, 0.0005)
