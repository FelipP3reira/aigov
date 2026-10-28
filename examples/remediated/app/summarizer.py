# @ai-generated: claude
# @model: claude-sonnet
# @reviewed-by: Ana Souza
# @reviewed-at: 2026-10-20
"""Summarise support tickets with an LLM."""

import json
import os

import openai
import requests

PRIORITY_RULES = {
    "stale": lambda ticket: ticket.get("age_days", 0) > 3,
    "vip": lambda ticket: ticket.get("plan") == "enterprise",
}


def _client():
    return openai.OpenAI(api_key=os.environ["OPENAI_API_KEY"])


def fetch_ticket(ticket_id):
    response = requests.get("https://helpdesk.internal/api/tickets/%s" % ticket_id, timeout=10)
    response.raise_for_status()
    return response.json()


def priority(ticket, rule_name):
    return PRIORITY_RULES[rule_name](ticket)


def summarise(ticket_id):
    ticket = fetch_ticket(ticket_id)
    completion = _client().chat.completions.create(
        model="gpt-4o-mini",
        messages=[{"role": "user", "content": "Summarise this ticket: " + json.dumps(ticket)}],
    )
    return completion.choices[0].message.content
