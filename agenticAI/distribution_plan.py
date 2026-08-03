"""
Two things live here:

1. build_distribution_plan() - the FALLBACK. Deterministic, rule-based
   (severity -> seniority preference, 5-per-staff cap). Used only when
   the agent's proposed plan fails validation - a safety net, not the
   primary decision-maker anymore.

2. validate_agent_plan() - the referee. The agent now decides WHO gets
   WHAT ticket directly (see assignment_agent.py), not just the reasoning
   text. This function checks that decision against hard constraints
   that can never be allowed to break, regardless of what the LLM
   returns: no invented ticket/staff IDs, no ticket assigned twice, no
   staff member over their capacity. We do NOT re-check the *soft*
   severity/seniority preference here - that's exactly the judgment call
   we now want the agent to make. If validation fails, the caller falls
   back to build_distribution_plan() for guaranteed-correct results.
"""

from typing import List, Dict, Tuple

TICKETS_PER_STAFF = 5
HIGH_SEVERITY = "high"


def build_distribution_plan(
    tickets: List[Dict],
    staff: List[Dict],
) -> Tuple[List[Dict], List[Dict]]:
    """
    Deterministic fallback only - used when the agent's proposed plan
    fails validation. See module docstring.
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
                    "reason": (
                        f"Fallback rule-based assignment: routed to "
                        f"{staff_member['name']} ({staff_member.get('level', 'junior')} analyst) "
                        f"based on {ticket.get('severity')} severity {ticket.get('attack_type')} activity."
                    ),
                })
                remaining_capacity[staff_member["staff_id"]] -= 1
                capacity -= 1

    high_severity_tickets = [t for t in tickets if t.get("severity") == HIGH_SEVERITY]
    other_tickets = [t for t in tickets if t.get("severity") != HIGH_SEVERITY]

    seniors = [s for s in staff if s.get("level") == "senior"]
    juniors = [s for s in staff if s.get("level") != "senior"]

    assign_block(high_severity_tickets, seniors)
    assign_block(high_severity_tickets, juniors)
    assign_block(other_tickets, staff)

    assigned_ids = {a["ticket_id"] for a in assignments}
    unassigned = [t for t in tickets if t["ticket_id"] not in assigned_ids]

    return assignments, unassigned


def validate_agent_plan(
    proposed: List[Dict],
    tickets: List[Dict],
    staff: List[Dict],
) -> Tuple[bool, str]:
    """
    Checks the agent's proposed assignments against hard constraints that
    must never be violated. Returns (is_valid, reason_if_invalid).

    Deliberately does NOT check the severity/seniority preference - that
    soft judgment call now belongs to the agent. Only checks what would
    actually break the system if wrong.
    """
    valid_ticket_ids = {t["ticket_id"] for t in tickets}
    valid_staff_ids = {s["staff_id"] for s in staff}

    seen_ticket_ids = set()
    per_staff_count = {s["staff_id"]: 0 for s in staff}

    for item in proposed:
        if not isinstance(item, dict) or "ticket_id" not in item or "staff_id" not in item:
            return False, "Malformed proposal item (missing ticket_id or staff_id)."

        ticket_id = item["ticket_id"]
        staff_id = item["staff_id"]

        if ticket_id not in valid_ticket_ids:
            return False, f"Agent invented a ticket_id that doesn't exist: {ticket_id}"
        if staff_id not in valid_staff_ids:
            return False, f"Agent invented a staff_id that doesn't exist: {staff_id}"
        if ticket_id in seen_ticket_ids:
            return False, f"Ticket {ticket_id} assigned more than once."

        seen_ticket_ids.add(ticket_id)
        per_staff_count[staff_id] += 1

        if per_staff_count[staff_id] > TICKETS_PER_STAFF:
            return False, f"Staff {staff_id} exceeded the {TICKETS_PER_STAFF}-ticket cap."

    return True, ""