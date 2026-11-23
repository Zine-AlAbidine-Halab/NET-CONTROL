"""
access_control.py — manages the whitelist / blacklist and enforces
blacklist entries on the real network using iptables.

Design choice (explained in the README):
  * BLACKLIST  -> real enforcement. Adding an IP inserts an iptables
                  DROP rule so traffic to/from that host is blocked.
  * WHITELIST  -> detection filter. Whitelisted hosts are trusted and
                  never raise threat alerts.

iptables requires root. The Flask app must therefore be started with
sudo on the Kali VM. If iptables is unavailable (e.g. testing on a
non-Linux machine), enforcement is skipped but the list is still kept
so the interface stays usable for demonstration.
"""

import json
import ipaddress
import os
import shutil
import subprocess
import threading

from .alerts import log_event

CONFIG_PATH = os.path.join(os.path.dirname(__file__), "..", "config.json")
_lock = threading.Lock()

# Detect whether real enforcement is possible.
IPTABLES = shutil.which("iptables")


def _load_config():
    with open(CONFIG_PATH, "r", encoding="utf-8") as fh:
        return json.load(fh)


def _save_config(cfg):
    with open(CONFIG_PATH, "w", encoding="utf-8") as fh:
        json.dump(cfg, fh, indent=4, ensure_ascii=False)


def get_lists():
    cfg = _load_config()
    ac = cfg.get("access_control", {})
    return ac.get("whitelist", []), ac.get("blacklist", [])


def _iptables_block(ip):
    """Insert DROP rules for an IP. Returns True if enforced."""
    if not IPTABLES:
        return False
    try:
        # -C checks if the rule already exists; only add if missing.
        for direction in (["-s", ip], ["-d", ip]):
            check = subprocess.run(
                [IPTABLES, "-C", "INPUT", *direction, "-j", "DROP"],
                capture_output=True,
            )
            if check.returncode != 0:
                subprocess.run(
                    [IPTABLES, "-I", "INPUT", *direction, "-j", "DROP"],
                    check=True,
                )
        return True
    except subprocess.CalledProcessError as exc:
        log_event("ACCESS", f"iptables block failed for {ip}: {exc}", "warning")
        return False


def _iptables_unblock(ip):
    """Remove DROP rules for an IP."""
    if not IPTABLES:
        return False
    try:
        for direction in (["-s", ip], ["-d", ip]):
            # Loop in case the rule was inserted more than once.
            while subprocess.run(
                [IPTABLES, "-C", "INPUT", *direction, "-j", "DROP"],
                capture_output=True,
            ).returncode == 0:
                subprocess.run(
                    [IPTABLES, "-D", "INPUT", *direction, "-j", "DROP"],
                    check=True,
                )
        return True
    except subprocess.CalledProcessError as exc:
        log_event("ACCESS", f"iptables unblock failed for {ip}: {exc}", "warning")
        return False


def _valid_ipv4(ip):
    try:
        return isinstance(ipaddress.ip_address(ip), ipaddress.IPv4Address)
    except ValueError:
        return False


def add_to_blacklist(ip):
    if not _valid_ipv4(ip):
        return False, "Invalid IPv4 address"
    with _lock:
        cfg = _load_config()
        if ip in cfg["access_control"].get("whitelist", []):
            return False, "IP is whitelisted"
        bl = cfg["access_control"]["blacklist"]
        if ip in bl:
            return False, "IP already blacklisted"
        enforced = _iptables_block(ip)
        bl.append(ip)
        _save_config(cfg)
    note = "blocked via iptables" if enforced else "saved (iptables not active)"
    log_event("ACCESS", f"Blacklisted {ip} — {note}", "warning")
    return True, note


def remove_from_blacklist(ip):
    if not _valid_ipv4(ip):
        return False, "Invalid IPv4 address"
    with _lock:
        cfg = _load_config()
        bl = cfg["access_control"]["blacklist"]
        if ip not in bl:
            return False, "IP not in blacklist"
        _iptables_unblock(ip)
        bl.remove(ip)
        _save_config(cfg)
    log_event("ACCESS", f"Removed {ip} from blacklist", "info")
    return True, "unblocked"


def add_to_whitelist(ip):
    if not _valid_ipv4(ip):
        return False, "Invalid IPv4 address"
    with _lock:
        cfg = _load_config()
        wl = cfg["access_control"]["whitelist"]
        if ip in wl:
            return False, "IP already whitelisted"
        wl.append(ip)
        _save_config(cfg)
    log_event("ACCESS", f"Whitelisted {ip} (trusted host)", "info")
    return True, "added"


def remove_from_whitelist(ip):
    if not _valid_ipv4(ip):
        return False, "Invalid IPv4 address"
    with _lock:
        cfg = _load_config()
        wl = cfg["access_control"]["whitelist"]
        if ip not in wl:
            return False, "IP not in whitelist"
        wl.remove(ip)
        _save_config(cfg)
    log_event("ACCESS", f"Removed {ip} from whitelist", "info")
    return True, "removed"


def is_whitelisted(ip):
    wl, _ = get_lists()
    return ip in wl
