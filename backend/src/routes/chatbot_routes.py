"""
JSON API for the SOC Assistant chatbot embedded in the Threat Detail page.

Kept in its own blueprint/file rather than pages.py so this feature stays
isolated from the existing page-rendering routes - see soc_chatbot.py and
chatbot_tools.py for the actual logic; this file only handles the HTTP
request/response and input validation.
"""

from functools import wraps
from flask import Blueprint, request, jsonify, session

from agenticAI.soc_chatbot import answer_ticket_question

chatbot_bp = Blueprint('chatbot', __name__)


def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user' not in session:
            return jsonify({'error': 'Authentication required'}), 401
        return f(*args, **kwargs)
    return decorated


@chatbot_bp.route('/chatbot/ask', methods=['POST'])
@login_required
def chatbot_ask():
    payload = request.get_json(silent=True) or {}

    raw_alert_id = payload.get('alert_id')
    question = payload.get('question', '')

    if raw_alert_id is None:
        return jsonify({'error': 'A ticket ID is required.'}), 400

    try:
        alert_id = int(raw_alert_id)
    except (TypeError, ValueError):
        return jsonify({'error': 'Invalid ticket ID.'}), 400

    if not isinstance(question, str) or not question.strip():
        return jsonify({'error': 'Please enter a question.'}), 400

    result = answer_ticket_question(
        alert_id=alert_id,
        question=question,
        user_id=session['user_id'],
        role=session['role'],
    )

    if not result['success']:
        return jsonify({'error': result['error']}), result['status']

    return jsonify({'answer': result['answer']}), 200
