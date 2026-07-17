"""
Agent definition + orchestration entrypoint for automatic ticket assignment.

Call run_assignment_for_batch(analysis_id) right after run_analysis() commits
its Alert rows in data_service.py. See INTEGRATION.md for the exact hook point.
"""

from agents import Agent, Runner
from agenticAI.assignment_tools import assign_ticket, get_unassigned_tickets, get_staff_list
from agenticAI.distribution_plan import build_distribution_plan

INSTRUCTIONS = """
You are a SOC (Security Operations Center) ticket assignment agent.

You will be given a JSON list called ASSIGNMENTS. Each item already specifies
which ticket_id goes to which staff_id (this distribution has already been
decided by the system - do not change who gets which ticket).

For every item in ASSIGNMENTS, call the assign_ticket tool with:
  - ticket_id: from the item
  - staff_id: from the item
  - reason: a short (1 sentence) human-readable explanation for the assignment.
    Since specialization matching is not yet implemented, base the reason on
    the fact this is standard round-robin workload distribution for this
    upload batch, and mention the attack_type and severity if present.

Call assign_ticket once per item, in order. After all calls are done,
reply with a brief summary: how many tickets were assigned and to how many staff.
"""

assignment_agent = Agent(
    name="TicketAssignmentAgent",
    instructions=INSTRUCTIONS,
    tools=[assign_ticket],
)


def run_assignment_for_batch(analysis_id: int) -> dict:
    """
    Main entrypoint - call this from data_service.run_analysis(), right after
    db.session.commit() for the Alert rows, passing the new analysis_id.
    """
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

    prompt = f"ASSIGNMENTS = {assignments}"
    result = Runner.run_sync(assignment_agent, prompt)

    return {
        "assigned_count": len(assignments),
        "unassigned_ticket_ids": [t["ticket_id"] for t in unassigned],
        "agent_summary": result.final_output,
    }
