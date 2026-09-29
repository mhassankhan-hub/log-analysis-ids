import json
import logging
import requests
from typing import Dict, Any, Optional
from core.models import Alert

logger = logging.getLogger("SOCSentinel.Alerter")


class AlertDispatcher:
    """Dispatches security alerts to Console, Discord Webhooks, and Slack."""

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self.console_enabled = self.config.get("alerts", {}).get("console", {}).get("enabled", True)
        self.discord_enabled = self.config.get("alerts", {}).get("discord", {}).get("enabled", False)
        self.discord_webhook = self.config.get("alerts", {}).get("discord", {}).get("webhook_url", "")
        self.slack_enabled = self.config.get("alerts", {}).get("slack", {}).get("enabled", False)
        self.slack_webhook = self.config.get("alerts", {}).get("slack", {}).get("webhook_url", "")

    def update_config(self, alerts_config: Dict[str, Any]):
        if "console" in alerts_config:
            self.console_enabled = alerts_config["console"].get("enabled", True)
        if "discord" in alerts_config:
            self.discord_enabled = alerts_config["discord"].get("enabled", False)
            self.discord_webhook = alerts_config["discord"].get("webhook_url", "")
        if "slack" in alerts_config:
            self.slack_enabled = alerts_config["slack"].get("enabled", False)
            self.slack_webhook = alerts_config["slack"].get("webhook_url", "")

    def dispatch(self, alert: Alert):
        """Broadcast alert to all configured channels."""
        if self.console_enabled:
            self._send_console(alert)

        if self.discord_enabled and self.discord_webhook:
            self._send_discord(alert)

        if self.slack_enabled and self.slack_webhook:
            self._send_slack(alert)

    def _send_console(self, alert: Alert):
        severity_colors = {
            "CRITICAL": "\033[91;1m",  # Bright Red
            "HIGH": "\033[31m",        # Red
            "MEDIUM": "\033[33m",      # Yellow
            "LOW": "\033[36m"          # Cyan
        }
        reset = "\033[0m"
        color = severity_colors.get(alert.severity, "")

        print(f"\n{color}[!] {alert.severity} INTRUSION ALERT - {alert.rule_name}{reset}")
        print(f"    |-- Alert ID:    {alert.id}")
        print(f"    |-- MITRE ATT&CK:{alert.mitre_attack_id} ({alert.mitre_attack_technique} - {alert.mitre_attack_tactic})")
        print(f"    |-- Attacker IP: {alert.source_ip} [{alert.geo_city or 'Unknown'}, {alert.geo_country or 'Unknown'}]")
        print(f"    |-- Target User: {alert.targeted_user or 'N/A'}")
        print(f"    |-- Description: {alert.description}")
        print(f"    |-- Evidence:    {alert.event_count} correlating log events")
        print(f"    \\-- Action:      iptables -A INPUT -s {alert.source_ip} -j DROP\n")

    def _send_discord(self, alert: Alert) -> bool:
        """Sends rich Discord embed alert."""
        if not self.discord_webhook:
            return False

        colors = {
            "CRITICAL": 0xDC2626,  # Crimson
            "HIGH": 0xEA580C,      # Orange
            "MEDIUM": 0xF59E0B,    # Amber
            "LOW": 0x3B82F6        # Blue
        }

        embed = {
            "title": f"🚨 [{alert.severity}] {alert.rule_name}",
            "description": alert.description,
            "color": colors.get(alert.severity, 0xDC2626),
            "fields": [
                {"name": "Attacker IP", "value": f"`{alert.source_ip}` ({alert.geo_city or 'Unknown'}, {alert.geo_country or 'Unknown'})", "inline": True},
                {"name": "MITRE ATT&CK", "value": f"`{alert.mitre_attack_id}`: {alert.mitre_attack_technique}", "inline": True},
                {"name": "Target", "value": f"`{alert.targeted_user or 'Server'}`", "inline": True},
                {"name": "Event Count", "value": str(alert.event_count), "inline": True},
                {"name": "Firewall Mitigation", "value": f"```bash\niptables -A INPUT -s {alert.source_ip} -j DROP\n```", "inline": False}
            ],
            "footer": {
                "text": f"SOC Sentinel IDS | Alert ID: {alert.id}"
            },
            "timestamp": alert.timestamp.isoformat()
        }

        try:
            resp = requests.post(self.discord_webhook, json={"embeds": [embed]}, timeout=5)
            return resp.status_code in (200, 204)
        except Exception as e:
            logger.warning(f"Failed to post alert to Discord: {e}")
            return False

    def _send_slack(self, alert: Alert) -> bool:
        """Sends Slack incoming webhook payload."""
        if not self.slack_webhook:
            return False

        payload = {
            "text": f"*🚨 [{alert.severity}] {alert.rule_name}*\n"
                    f"*Attacker IP:* `{alert.source_ip}` ({alert.geo_country or 'Unknown'})\n"
                    f"*MITRE ATT&CK:* `{alert.mitre_attack_id}` - {alert.mitre_attack_technique}\n"
                    f"*Details:* {alert.description}\n"
                    f"*Mitigation:* `iptables -A INPUT -s {alert.source_ip} -j DROP`"
        }
        try:
            resp = requests.post(self.slack_webhook, json=payload, timeout=5)
            return resp.status_code == 200
        except Exception as e:
            logger.warning(f"Failed to post alert to Slack: {e}")
            return False

    def send_test_discord(self, webhook_url: str) -> bool:
        """Sends a verification message to ensure Discord webhook is functional."""
        payload = {
            "embeds": [{
                "title": "🛡️ SOC Sentinel - Webhook Integration Test",
                "description": "Your Discord alerting integration is working correctly! Active intrusion detection alerts will be routed here.",
                "color": 0x10B981,
                "fields": [
                    {"name": "Status", "value": "🟢 Connected & Active", "inline": True},
                    {"name": "Engine", "value": "SOC Sentinel v1.0", "inline": True}
                ],
                "footer": {"text": "SOC Sentinel Intrusion Detection System"}
            }]
        }
        try:
            resp = requests.post(webhook_url, json=payload, timeout=5)
            return resp.status_code in (200, 204)
        except Exception as e:
            logger.error(f"Discord test webhook failed: {e}")
            return False
