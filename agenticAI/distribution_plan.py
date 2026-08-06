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
    assign_block(high_severity_tickets, juniors)  # emergency overflow once seniors are full
    assign_block(other_tickets, juniors)  # medium/normal go ONLY to juniors - seniors never receive these

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

    Includes one severity/seniority constraint as a HARD check: senior
    analysts may only receive high-severity tickets. This was upgraded
    from a soft preference to a validated constraint because "seniors
    receive ONLY high severity" is a strict business rule, not a
    suggestion - and past testing showed the agent cannot be trusted to
    honour strict rules reliably on its own (see design history).
    Junior analysts may still receive high-severity overflow once every
    senior is at capacity - that direction is intentionally NOT enforced
    here, since it's the sanctioned emergency-overflow path.
    """
    valid_ticket_ids = {t["ticket_id"] for t in tickets}
    valid_staff_ids = {s["staff_id"] for s in staff}
    ticket_severity = {t["ticket_id"]: t.get("severity") for t in tickets}
    staff_level = {s["staff_id"]: s.get("level", "junior") for s in staff}

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
        if staff_level[staff_id] == "senior" and ticket_severity[ticket_id] != HIGH_SEVERITY:
            return False, (
                f"Senior analyst {staff_id} was assigned a non-high-severity ticket "
                f"({ticket_id}, severity={ticket_severity[ticket_id]}) - seniors may only receive high-severity tickets."
            )

        seen_ticket_ids.add(ticket_id)
        per_staff_count[staff_id] += 1

        if per_staff_count[staff_id] > TICKETS_PER_STAFF:
            return False, f"Staff {staff_id} exceeded the {TICKETS_PER_STAFF}-ticket cap."

    # second pass: a junior may only receive a high-severity ticket if
    # EVERY senior is already fully at capacity in this proposal. This
    # can't be checked item-by-item above since it depends on the final
    # tally across the whole plan, not just the one item being checked.
    senior_ids = {s["staff_id"] for s in staff if s.get("level") == "senior"}
    if senior_ids:
        for item in proposed:
            ticket_id = item["ticket_id"]
            staff_id = item["staff_id"]
            if staff_level[staff_id] != "senior" and ticket_severity[ticket_id] == HIGH_SEVERITY:
                if any(per_staff_count[sid] < TICKETS_PER_STAFF for sid in senior_ids):
                    return False, (
                        f"Junior {staff_id} was given a high-severity ticket ({ticket_id}) "
                        f"while a senior analyst still had free capacity - "
                        f"seniors must be fully utilised before juniors receive high-severity overflow."
                    )

    return True, ""
