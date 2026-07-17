"""
Backend functions used for automatic ticket (Alert) assignment.

get_unassigned_tickets() and get_staff_list() are plain data-fetching
functions - the distribution decision (exactly 5 per analyst) is computed
deterministically in distribution_plan.py, NOT decided by the LLM.

assign_ticket() is the one function exposed to the agent as a tool
(@function_tool) - it's the actual write action the agent performs.
"""

from datetime import datetime
from agents import function_tool

from backend.src.database.models import Alert, User
from backend.src.database.db import db


def get_unassigned_tickets(analysis_id: int):
    """
    Plain function (not an agent tool) - fetch alerts from a specific
    analysis run that have not yet been assigned to an analyst.
    """
    alerts = Alert.query.filter_by(
        analysis_id=analysis_id,
        assigned_analyst_id=None,
    ).all()

    return [
        {
            "ticket_id": a.id,
            "attack_type": a.prediction,
            "severity": a.severity,
        }
        for a in alerts
    ]


def get_staff_list():
    """
    Plain function (not an agent tool) - fetch all SOC analysts eligible
    to receive tickets. Role string confirmed as 'analyst' (lowercase).
    """
    analysts = User.query.filter_by(role='analyst').all()
    return [{"staff_id": u.id, "name": u.username} for u in analysts]


@function_tool
def assign_ticket(ticket_id: int, staff_id: int, reason: str) -> dict:
    """
    Assign a single alert/ticket to an analyst and store the
    human-readable justification for the assignment.

    Args:
        ticket_id: the Alert.id being assigned.
        staff_id: the User.id (analyst) receiving the ticket.
        reason: short natural-language explanation for the assignment.

    Returns:
        {"success": bool, "ticket_id": int, "staff_id": int}
    """
    alert = Alert.query.get(ticket_id)
    if not alert:
        return {"success": False, "ticket_id": ticket_id, "staff_id": staff_id, "error": "ticket not found"}

    alert.assigned_analyst_id = staff_id
    alert.assignment_source = 'agent'
    alert.assignment_reason = reason
    alert.assigned_at = datetime.utcnow()
    db.session.commit()

    return {"success": True, "ticket_id": ticket_id, "staff_id": staff_id}
