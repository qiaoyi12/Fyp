from flask import Blueprint, jsonify
from threading import Thread
import time

from live_simulator import run_live

simulator_bp = Blueprint("simulator", __name__)

sim_thread = None
running = False


@simulator_bp.route("/start")
def start_simulation():
    global sim_thread, running

    if running:
        return jsonify({"status": "already running"})

    running = True

    def runner():
        run_live("mixed")  # your simulator

    sim_thread = Thread(target=runner)
    sim_thread.start()

    return jsonify({"status": "started"})


@simulator_bp.route("/stop")
def stop_simulation():
    global running
    running = False
    return jsonify({"status": "stopped"})