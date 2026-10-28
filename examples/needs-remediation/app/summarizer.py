# @ai-generated: claude
# @model: claude-sonnet
"""Summarise support tickets with an LLM."""

import json

import openai
import requests

# Demo-only value for the aigov example. It is not a real key.
API_KEY = "sk-proj-0Demo1Only2Not3A4Real5Key6Qw7Er8Ty9Ui0Op"

client = openai.OpenAI(api_key=API_KEY)


def fetch_ticket(ticket_id):
    response = requests.get("https://helpdesk.internal/api/tickets/%s" % ticket_id, verify=False)
    return response.json()


def priority(ticket, rule):
    # The rule comes from the admin UI, e.g. "ticket['age_days'] > 3".
    return eval(rule)


def summarise(ticket_id):
    ticket = fetch_ticket(ticket_id)
    completion = client.chat.completions.create(
        model="gpt-4o-mini",
        messages=[{"role": "user", "content": "Summarise this ticket: " + json.dumps(ticket)}],
    )
    return completion.choices[0].message.content
