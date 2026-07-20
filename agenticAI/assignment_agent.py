"""
Agent definition + orchestration entrypoint for automatic ticket assignment.

Redesigned after testing revealed the LLM tool-calling loop wasn't reliably
calling assign_ticket for every planned item (some tickets were silently
skipped). Now: the agent's ONLY job is generating reason text for the whole
batch in a single call (no tools, structured JSON output). Our own code then
loops over every planned assignment and calls assign_ticket() directly -
so every planned assignment is now GUARANTEED to execute, regardless of
what the LLM does.

Call run_assignment_for_batch(analysis_id) right after run_analysis() commits
its Alert rows in data_service.py.
"""

import json

from agents import Agent, Runner
from agenticAI.assignment_tools import assign_ticket, get_unassigned_tickets, get_staff_list
from agenticAI.distribution_plan import build_distribution_plan

INSTRUCTIONS = """
You are a SOC (Security Operations Center) ticket assignment explainer.

You will be given a JSON list called ASSIGNMENTS. Each item has:
ticket_id, staff_id, staff_name, attack_type, severity.

For EVERY item, write a short (1 sentence) human-readable reason explaining
the assignment. Since specialization matching is not yet implemented, base
each reason on the fact this is standard round-robin workload distribution
for this upload batch, and mention the attack_type and severity.

Respond with ONLY a JSON array, nothing else - no markdown, no preamble.
Each element must be: {"ticket_id": <int>, "reason": "<your explanation>"}
You must include exactly one element for every ticket_id in ASSIGNMENTS,
in any order.
"""

assignment_agent = Agent(
    name="TicketAssignmentExplainer",
    instructions=INSTRUCTIONS,
)


def _get_reasons(assignments: list) -> dict:
    """
    Ask the agent for reason text for the whole batch in one call.
    Returns {ticket_id: reason}. Falls back to a generic reason for any
    ticket_id the model didn't return or if parsing fails entirely -
    this function NEVER prevents an assignment from happening, it only
    supplies the explanation text.
    """
    fallback = {
        a["ticket_id"]: (
            f"Standard round-robin workload distribution for this batch; "
            f"{a.get('attack_type')}, {a.get('severity')} severity."
        )
        for a in assignments
    }

    prompt = f"ASSIGNMENTS = {assignments}"
    try:
        result = Runner.run_sync(assignment_agent, prompt)
        raw = result.final_output.strip()
        # strip accidental markdown fences if the model adds them anyway
        if raw.startswith("```"):
            raw = raw.strip("`")
            raw = raw.split("\n", 1)[1] if "\n" in raw else raw
        parsed = json.loads(raw)
        reasons = {item["ticket_id"]: item["reason"] for item in parsed}
    except Exception:
        return fallback

    # fill in any ticket_id the model missed with the fallback reason
    for ticket_id, reason in fallback.items():
        reasons.setdefault(ticket_id, reason)
    return reasons


def run_assignment_for_batch(analysis_id: int) -> dict:
    """
    Main entrypoint - call this from data_service.run_analysis(), right after
    db.session.commit() for the Alert rows, passing the new analysis_id.

    Runs at most ONCE per analysis_id, ever - guards against being triggered
    twice for the same batch (e.g. if the same analysis gets assigned to a
    second manager later, which would otherwise re-fire this and hand out
    more than the intended 5-per-analyst cap on top of the first run).
    """
    from backend.src.database.models import Alert  # pylint: disable=import-outside-toplevel

    already_ran = Alert.query.filter_by(
        analysis_id=analysis_id, assignment_source='agent'
    ).first() is not None
    if already_ran:
        return {
            "assigned_count": 0,
            "unassigned_ticket_ids": [],
            "agent_summary": "Agent has already run for this analysis batch; skipping to avoid double-assignment.",
        }

    tickets = get_unassigned_tickets(analysis_id)
    staff = get_staff_list()

    if not staff:
        return {
            "assigned_count": 0,
            "unassigned_ticket_ids": [t["ticket_id"] for t in tickets],
            "agent_summary": "No active analysts available; all tickets left unassigned.",
        }

    assignments, unassigned = build_distribution_plan(tickets, staff)

    if not assignments:
        return {
            "assigned_count": 0,
            "unassigned_ticket_ids": [t["ticket_id"] for t in unassigned],
            "agent_summary": "No tickets to assign in this batch.",
        }

    reasons = _get_reasons(assignments)

    # guaranteed execution: plain Python loop, not an LLM tool-calling loop
    assigned_count = 0
    for a in assignments:
        outcome = assign_ticket(
            ticket_id=a["ticket_id"],
            staff_id=a["staff_id"],
            reason=reasons.get(a["ticket_id"], "Standard round-robin workload distribution for this batch."),
        )
        if outcome["success"]:
            assigned_count += 1

    return {
        "assigned_count": assigned_count,
        "unassigned_ticket_ids": [t["ticket_id"] for t in unassigned],
        "agent_summary": f"Assigned {assigned_count} of {len(assignments)} planned tickets across {len(staff)} analyst(s).",
    }
