"""
app.py — Flask web application for the Network Control Panel.

Run on the Kali VM with root privileges (scapy + iptables need it):

    sudo python3 app.py

Then open http://127.0.0.1:5000 in the VM's browser.

Routes
  /                 login page
  /dashboard        live traffic stats + recent threat alerts
  /control          access control (white/black lists) + admin mgmt
  /api/stats        JSON polled by the dashboard for live updates
  various POST routes for start/stop capture and list/admin actions
"""

import functools
import os
import secrets

from flask import (Flask, abort, redirect, render_template, request,
                   session, url_for, jsonify, flash)

from core.sniffer import TrafficMonitor, load_config
from core.alerts import log_event, recent_events, event_counts
from core import access_control as ac
from core import admins

app = Flask(__name__)
# Fail closed: do not start an administration server with a public/static secret.
secret_key = os.environ.get("NETCONTROL_SECRET_KEY", "")
if len(secret_key) < 32:
    raise RuntimeError("NETCONTROL_SECRET_KEY must be set (at least 32 characters).")
app.secret_key = secret_key
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Strict",
    # Set to True ONLY when serving the interface through HTTPS.
    SESSION_COOKIE_SECURE=os.environ.get("NETCONTROL_HTTPS", "0") == "1",
    MAX_CONTENT_LENGTH=64 * 1024,
)

config = load_config()
monitor = TrafficMonitor(config)
admins.ensure_bootstrap_admin()


@app.context_processor
def inject_csrf():
    def csrf_token():
        if "_csrf" not in session:
            session["_csrf"] = secrets.token_urlsafe(32)
        return session["_csrf"]
    return {"csrf_token": csrf_token}


@app.before_request
def protect_post_requests():
    if request.method == "POST":
        expected = session.get("_csrf", "")
        received = request.form.get("_csrf", "")
        if not expected or not secrets.compare_digest(expected, received):
            abort(400, description="Invalid CSRF token")


# --- authentication helper ---------------------------------------------

def login_required(view):
    @functools.wraps(view)
    def wrapped(*args, **kwargs):
        if "admin" not in session:
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    return wrapped


# --- auth routes -------------------------------------------------------

@app.route("/", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        if admins.verify(username, password):
            session.clear()  # discard anonymous session state at login
            session["admin"] = username
            log_event("ADMIN", f"'{username}' logged in", "info")
            return redirect(url_for("dashboard"))
        flash("Invalid credentials")
        log_event("ADMIN", f"Failed login attempt for '{username}'", "warning")
    return render_template("login.html")


@app.route("/logout", methods=["POST"])
def logout():
    user = session.pop("admin", None)
    if user:
        log_event("ADMIN", f"'{user}' logged out", "info")
    return redirect(url_for("login"))


# --- dashboard ---------------------------------------------------------

@app.route("/dashboard")
@login_required
def dashboard():
    return render_template(
        "dashboard.html",
        admin=session["admin"],
        refresh=config["web"]["refresh_seconds"],
    )


@app.route("/api/stats")
@login_required
def api_stats():
    return jsonify(
        stats=monitor.snapshot(),
        counts=event_counts(),
        events=recent_events(30),
    )


@app.route("/capture/<action>", methods=["POST"])
@login_required
def capture(action):
    if action == "start":
        monitor.start()
    elif action == "stop":
        monitor.stop()
    return redirect(url_for("dashboard"))


# --- control panel -----------------------------------------------------

@app.route("/control")
@login_required
def control():
    whitelist, blacklist = ac.get_lists()
    return render_template(
        "control.html",
        admin=session["admin"],
        whitelist=whitelist,
        blacklist=blacklist,
        admin_list=admins.list_admins(),
        enforcement=ac.IPTABLES is not None,
    )


@app.route("/list/<which>/<action>", methods=["POST"])
@login_required
def list_action(which, action):
    ip = request.form.get("ip", "").strip()
    if not ip:
        flash("No IP provided")
        return redirect(url_for("control"))

    handlers = {
        ("blacklist", "add"): ac.add_to_blacklist,
        ("blacklist", "remove"): ac.remove_from_blacklist,
        ("whitelist", "add"): ac.add_to_whitelist,
        ("whitelist", "remove"): ac.remove_from_whitelist,
    }
    handler = handlers.get((which, action))
    if handler:
        ok, msg = handler(ip)
        flash(f"{ip}: {msg}")
    return redirect(url_for("control"))


@app.route("/admin/<action>", methods=["POST"])
@login_required
def admin_action(action):
    username = request.form.get("username", "").strip()
    if action == "add":
        password = request.form.get("password", "")
        if not username or not password:
            flash("Username and password required")
        elif len(password) < 12:
            flash("Password must contain at least 12 characters")
            return redirect(url_for("control"))
        else:
            ok, msg = admins.add_admin(username, password)
            flash(f"{username}: {msg}")
    elif action == "remove":
        ok, msg = admins.remove_admin(username, session["admin"])
        flash(f"{username}: {msg}")
    return redirect(url_for("control"))


if __name__ == "__main__":
    web = config["web"]
    # threaded=True so the sniffer thread and request handling coexist.
    app.run(host=web["host"], port=web["port"], threaded=True, debug=False)
