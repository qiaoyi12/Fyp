"""
Agent + orchestration for the read-only SOC Assistant chatbot.

Scope, deliberately: this agent only ever reads a single ticket's data
(via chatbot_tools.get_ticket_context) and answers one free-text question
about it - explaining the incident, suggesting investigation/remediation
steps, or naming the assigned analyst. It is given NO tools, so unlike a
tool-calling agent it has no mechanism to write to the database even if
asked to - same reasoning as assignment_agent.py's redesign (see that
module's docstring), just applied here to make this agent structurally
incapable of taking any action, rather than merely told not to.

Call answer_ticket_question(alert_id, question, user_id, role) from the
chatbot API route.
"""

import json

from agents import Agent, Runner
from agenticAI.chatbot_tools import get_ticket_context

INSTRUCTIONS = """
You are the SOC Assistant, a read-only helper embedded in a single
incident's ticket detail page.

You will be given TICKET_CONTEXT (a JSON object describing exactly one
alert/ticket) and a QUESTION from a SOC user about that ticket.

Rules:
1. Answer ONLY using the fields in TICKET_CONTEXT. Never invent, assume,
   or guess a specific fact about this ticket (e.g. an IP address, a
   status, an assigned analyst, or an evidence value) that isn't present
   in TICKET_CONTEXT.
2. If a field needed to answer is null, missing, or empty, say plainly
   that this information is not available for this ticket - do not fill
   the gap with a plausible-sounding value.
3. You MAY give general SOC investigation and remediation guidance based
   on the ticket's attack_type and severity, drawing on general
   cybersecurity best practice - that is expected and encouraged. Just
   don't present a general recommendation as if it were a ticket-specific
   fact you read from the data.
4. If asked who is assigned, answer directly from assigned_to (or say the
   ticket is unassigned if it's null).
5. Keep answers concise and practical for a SOC analyst reading on a
   ticket page. Use short paragraphs, or a short bulleted list for steps.
6. You cannot change anything - you have no ability to update tickets,
   assignments, statuses, or any other record. If asked to make a change,
   explain that you can only provide information, not take action.
"""

chatbot_agent = Agent(
    name="SOCAssistant",
    instructions=INSTRUCTIONS,
)


def answer_ticket_question(alert_id: int, question: str, user_id: int, role: str) -> dict:
    """
    Returns one of:
      {"success": True, "answer": str}
      {"success": False, "error": str, "status": int}
    Never raises - LLM/API errors are caught and turned into a
    success=False result so the caller can always return a clean
    response to the browser.
    """
    if not question or not question.strip():
        return {"success": False, "error": "Please enter a question.", "status": 400}

    context = get_ticket_context(alert_id, user_id, role)
    if context is None:
        return {
            "success": False,
            "error": "Ticket not found or you do not have access to it.",
            "status": 404,
        }

    prompt = (
        f"TICKET_CONTEXT = {json.dumps(context)}\n\n"
        f"QUESTION: {question.strip()}"
    )

    try:
        result = Runner.run_sync(chatbot_agent, prompt)
        answer = (result.final_output or "").strip()
    except Exception:
        return {
            "success": False,
            "error": "The SOC Assistant is temporarily unavailable. Please try again shortly.",
            "status": 502,
        }

    if not answer:
        return {
            "success": False,
            "error": "The SOC Assistant did not return a response. Please try again.",
            "status": 502,
        }

    return {"success": True, "answer": answer}
