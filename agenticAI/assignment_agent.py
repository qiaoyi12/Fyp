"""
Agent definition + orchestration entrypoint for automatic ticket assignment.

REDESIGNED (v3): the agent now decides WHO gets WHICH ticket, not just the
explanation text. Code's role shifted from "decide" to "referee": the
agent's proposed plan is validated against hard constraints (no invented
IDs, no ticket assigned twice, no staff over the 5-ticket cap) before it's
used. If validation fails for any reason, code falls back to the fully
deterministic rule-based logic in distribution_plan.py - so correctness
is still guaranteed no matter what the LLM returns, but the agent's
judgment genuinely determines the outcome whenever it's valid.

History: v1 let the LLM both decide AND execute via tool calls in a loop -
testing showed it didn't reliably complete every call. v2 moved the
decision into deterministic code and used the LLM only for explanation
text. v3 (this version) hands the decision back to the agent, but with a
validation/fallback safety net instead of no safety net at all.

Call run_assignment_for_batch(analysis_id) right after run_analysis() commits
its Alert rows in data_service.py.
"""

import json

from agents import Agent, Runner
from agenticAI.assignment_tools import assign_ticket, get_unassigned_tickets, get_staff_list
from agenticAI.distribution_plan import build_distribution_plan, validate_agent_plan, TICKETS_PER_STAFF

INSTRUCTIONS = f"""
You are a SOC (Security Operations Center) ticket assignment agent.

You will be given TICKETS (a list of {{ticket_id, attack_type, severity}})
and STAFF (a list of {{staff_id, name, level}}, level is "junior" or "senior").

Decide which analyst should handle each ticket. Guidelines:
- Each analyst can take at most {TICKETS_PER_STAFF} tickets total.
- Prefer routing high-severity tickets to senior analysts first; only
  route a high-severity ticket to a junior once every senior is at
  capacity. Other severities can go to anyone with remaining capacity.
- You do not have to assign every ticket - if total staff capacity is
  less than the number of tickets, leave the excess out of your response
  entirely (do not invent extra capacity).
- Never assign a ticket_id or staff_id that wasn't given to you.
- Never give one analyst more than their capacity.
- Never assign the same ticket to more than one analyst.

Respond with ONLY a JSON array, nothing else - no markdown, no preamble.
Each element must be:
{{"ticket_id": <int>, "staff_id": <int>, "reason": "<short 1-sentence human-readable explanation>"}}
Include one element per ticket you decide to assign. Omit tickets you
choose not to assign (they'll be handled separately).
"""

assignment_agent = Agent(
    name="TicketAssignmentAgent",
    instructions=INSTRUCTIONS,
)


def _get_agent_plan(tickets: list, staff: list):
    """
    Ask the agent to decide the full assignment plan in one call.
    Returns the parsed list of {ticket_id, staff_id, reason} dicts,
    or None if the call/parse failed entirely - caller treats None as
    "fall back to deterministic logic".
    """
    prompt = f"TICKETS = {tickets}\nSTAFF = {staff}"
    try:
        result = Runner.run_sync(assignment_agent, prompt)
        raw = result.final_output.strip()
        if raw.startswith("```"):
            raw = raw.strip("`")
            raw = raw.split("\n", 1)[1] if "\n" in raw else raw
        parsed = json.loads(raw)
        if not isinstance(parsed, list):
            return None
        return parsed
    except Exception:
        return None


def run_assignment_for_batch(analysis_id: int) -> dict:
    """
    Main entrypoint - call this from data_service.run_analysis(), right after
    db.session.commit() for the Alert rows, passing the new analysis_id.

    Runs at most ONCE per analysis_id, ever - see module docstring history.
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
            "decision_source": "none",
        }

    tickets = get_unassigned_tickets(analysis_id)
    staff = get_staff_list()

    if not staff:
        return {
            "assigned_count": 0,
            "unassigned_ticket_ids": [t["ticket_id"] for t in tickets],
            "agent_summary": "No active analysts available; all tickets left unassigned.",
            "decision_source": "none",
        }

    if not tickets:
        return {
            "assigned_count": 0,
            "unassigned_ticket_ids": [],
            "agent_summary": "No tickets to assign in this batch.",
            "decision_source": "none",
        }

    decision_source = "agent"
    proposed = _get_agent_plan(tickets, staff)

    if proposed is not None:
        is_valid, error = validate_agent_plan(proposed, tickets, staff)
    else:
        is_valid, error = False, "Agent call or JSON parsing failed."

    if is_valid:
        assignments = proposed
        assigned_ids = {a["ticket_id"] for a in assignments}
        unassigned = [t for t in tickets if t["ticket_id"] not in assigned_ids]
    else:
        # fallback: deterministic, guaranteed-correct logic
        decision_source = f"fallback ({error})"
        assignments, unassigned = build_distribution_plan(tickets, staff)

    # guaranteed execution: plain Python loop, not an LLM tool-calling loop,
    # regardless of whether the plan came from the agent or the fallback
    assigned_count = 0
    for a in assignments:
        outcome = assign_ticket(
            ticket_id=a["ticket_id"],
            staff_id=a["staff_id"],
            reason=a.get("reason", "Assigned by the ticket assignment agent."),
        )
        if outcome["success"]:
            assigned_count += 1

    return {
        "assigned_count": assigned_count,
        "unassigned_ticket_ids": [t["ticket_id"] for t in unassigned],
        "agent_summary": (
            f"Assigned {assigned_count} of {len(assignments)} planned tickets across "
            f"{len(staff)} analyst(s). Decision source: {decision_source}."
        ),
        "decision_source": decision_source,
    }