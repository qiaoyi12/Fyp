"""
Read-only data-fetching for the SOC Assistant chatbot.

Every function here only reads from the database - none of them write,
update, or delete anything. The chatbot must never be able to change a
ticket's assignment, status, remarks, or any other record; keeping all DB
access confined to a single plain read-only query here (no @function_tool,
no tool-calling loop) is what guarantees that structurally, regardless of
what the LLM is asked to do.
"""

from backend.src.services import data_service


def get_ticket_context(alert_id, user_id, role):
    """
    Fetch everything the chatbot is allowed to know about one ticket.

    Reuses data_service.get_alert_detail(), the same role-based access
    check the Threat Detail page itself uses, so the chatbot can never
    expose a ticket outside what this user is already allowed to view.
    Returns None if the ticket doesn't exist or isn't accessible to
    this user - the caller treats that as "not found".
    """
    result = data_service.get_alert_detail(user_id, role, alert_id)
    if not result:
        return None

    alert = result["alert"]
    detail = result["detail"]

    assigned_to = None
    if alert.assigned_analyst_id:
        analyst = alert.assigned_analyst
        assigned_to = {
            "analyst_name": analyst.username if analyst else None,
            "analyst_level": analyst.level if analyst else None,
            "assignment_source": alert.assignment_source,
            "assignment_reason": alert.assignment_reason,
            "assigned_at": alert.assigned_at.strftime('%Y-%m-%d %H:%M') if alert.assigned_at else None,
        }

    evidence = None
    if detail:
        evidence = {
            "flow_duration_ms": detail.flow_duration,
            "flow_bytes_per_s": detail.flow_bytes_s,
            "flow_packets_per_s": detail.flow_packets_s,
            "total_fwd_packets": detail.total_fwd_packets,
            "total_backward_packets": detail.total_backward_packets,
            "packet_length_mean": detail.packet_length_mean,
            "average_packet_size": detail.average_packet_size,
            "syn_flag_count": detail.syn_flag_count,
            "ack_flag_count": detail.ack_flag_count,
            "psh_flag_count": detail.psh_flag_count,
            "init_win_bytes_forward": detail.init_win_bytes_forward,
            "init_win_bytes_backward": detail.init_win_bytes_backward,
        }

    return {
        "ticket_id": alert.id,
        "attack_type": alert.prediction,
        "severity": alert.severity,
        "confidence": alert.confidence,
        "status": alert.tag,
        "source_ip": alert.source_ip,
        "destination_port": alert.dest_port,
        # No per-alert destination IP is stored anywhere in the schema.
        # Explicitly None here rather than the placeholder IP the log
        # viewer displays elsewhere, so the chatbot never states a
        # fabricated address as if it were real evidence.
        "destination_ip": None,
        "analyst_remarks": alert.remarks or None,
        "detected_at": alert.created_at.strftime('%Y-%m-%d %H:%M:%S') if alert.created_at else None,
        "model_consensus": "agree" if alert.xgb_vote == alert.rf_vote else "disagree",
        "evidence": evidence,
        "assigned_to": assigned_to,
    }
