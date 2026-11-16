from anthropic import Anthropic

client = Anthropic()


def triage(user):
    prompt = f"Customer {user.email} with passport {user.passport_number} wrote in"
    return client.messages.create(model="claude-haiku-5-5", max_tokens=300,
                                  messages=[{"role": "user", "content": prompt}])
