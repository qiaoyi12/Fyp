"""
Deterministic pre-computation of the assignment plan.

We do NOT trust the LLM to count precisely or enforce a hard cap.
This function decides *how many* tickets each staff member gets (exactly 5,
first-come first-served from the batch) and which tickets are left over.

The agent's job (see assignment_agent.py) is only to decide the reasoning/
explanation and to actually call the assign_ticket tool per pair - the
*capacity* rule itself lives here in plain Python so it can never drift.
"""

from typing import List, Dict, Tuple

TICKETS_PER_STAFF = 5


def build_distribution_plan(
    tickets: List[Dict],
    staff: List[Dict],
) -> Tuple[List[Dict], List[Dict]]:
    """
    Args:
        tickets: list of {"ticket_id": ..., "attack_type": ..., "severity": ...}
        staff: list of {"staff_id": ..., "name": ...}

    Returns:
        (assignments, unassigned)
        assignments: list of {"ticket_id": ..., "staff_id": ...}
        unassigned: list of leftover ticket dicts (over capacity, manager handles manually)
    """
    capacity = len(staff) * TICKETS_PER_STAFF
    to_assign = tickets[:capacity]
    unassigned = tickets[capacity:]

    assignments = []
    for i, ticket in enumerate(to_assign):
        staff_member = staff[i // TICKETS_PER_STAFF]
        assignments.append({
            "ticket_id": ticket["ticket_id"],
            "staff_id": staff_member["staff_id"],
            "staff_name": staff_member["name"],
            "attack_type": ticket.get("attack_type"),
            "severity": ticket.get("severity"),
        })

    return assignments, unassigned
