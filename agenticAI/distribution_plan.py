"""
Deterministic pre-computation of the assignment plan.

We do NOT trust the LLM to count precisely, enforce a hard cap, or match
severity to seniority. This function decides *how many* tickets each staff
member gets (capped at 5) and *who* gets the high-severity ones:

- high-severity tickets are routed to senior analysts first; only once
  every senior is at capacity do they overflow to junior analysts.
- all other tickets (medium/normal severity) fill whatever capacity is
  left, in staff-list order, regardless of level.
- anything beyond total staff capacity is left unassigned for the
  manager to handle.

The agent's job (see assignment_agent.py) is only to decide the reasoning/
explanation and to actually call the assign_ticket tool per pair - the
*capacity and routing* rules themselves live here in plain Python so they
can never drift.
"""

from typing import List, Dict, Tuple

TICKETS_PER_STAFF = 5
HIGH_SEVERITY = "high"


def build_distribution_plan(
    tickets: List[Dict],
    staff: List[Dict],
) -> Tuple[List[Dict], List[Dict]]:
    """
    Args:
        tickets: list of {"ticket_id": ..., "attack_type": ..., "severity": ...}
        staff: list of {"staff_id": ..., "name": ..., "level": "junior"|"senior"}

    Returns:
        (assignments, unassigned)
        assignments: list of {"ticket_id", "staff_id", "staff_name", "staff_level",
            "attack_type", "severity"}
        unassigned: list of leftover ticket dicts (over capacity, manager handles manually)
    """
    remaining_capacity = {s["staff_id"]: TICKETS_PER_STAFF for s in staff}
    assignments = []

    def assign_block(ticket_queue: List[Dict], staff_order: List[Dict]) -> None:
        for staff_member in staff_order:
            capacity = remaining_capacity[staff_member["staff_id"]]
            while capacity > 0 and ticket_queue:
                ticket = ticket_queue.pop(0)
                assignments.append({
                    "ticket_id": ticket["ticket_id"],
                    "staff_id": staff_member["staff_id"],
                    "staff_name": staff_member["name"],
                    "staff_level": staff_member.get("level", "junior"),
                    "attack_type": ticket.get("attack_type"),
                    "severity": ticket.get("severity"),
                })
                remaining_capacity[staff_member["staff_id"]] -= 1
                capacity -= 1

    high_severity_tickets = [t for t in tickets if t.get("severity") == HIGH_SEVERITY]
    other_tickets = [t for t in tickets if t.get("severity") != HIGH_SEVERITY]

    seniors = [s for s in staff if s.get("level") == "senior"]
    juniors = [s for s in staff if s.get("level") != "senior"]

    # high severity: senior-preferred, overflow to junior once seniors are full
    assign_block(high_severity_tickets, seniors)
    assign_block(high_severity_tickets, juniors)

    # everything else: fill whatever capacity is left, in original staff order
    assign_block(other_tickets, staff)

    assigned_ids = {a["ticket_id"] for a in assignments}
    unassigned = [t for t in tickets if t["ticket_id"] not in assigned_ids]

    return assignments, unassigned
