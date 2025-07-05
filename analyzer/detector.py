import json
import re
import time
import psycopg2
import yaml
import jsonschema
from nats.aio.client import Client as NATS
from nats.aio.errors import ErrConnectionClosed, ErrTimeout


class LogAnalyzer:
    def __init__(self, config_path="config/config.yaml"):
        self.config = self.load_config(config_path)
        self.rules = self.load_rules(self.config["rules_path"])
        self.db_conn = self.connect_to_db()
        self.nc = NATS()

    def load_config(self, path):
        with open(path, "r") as f:
            return yaml.safe_load(f)

    def load_rules(self, path):
        with open(path, "r") as f:
            rules = yaml.safe_load(f)
        self.validate_rules(rules)
        return rules

    def validate_rules(self, rules):
        schema = {
            "type": "object",
            "properties": {
                "rules": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "id": {"type": "string"},
                            "name": {"type": "string"},
                            "description": {"type": "string"},
                            "severity": {
                                "type": "string",
                                "enum": ["low", "medium", "high", "critical"],
                            },
                            "tags": {"type": "array", "items": {"type": "string"}},
                            "condition": {"type": "string"},
                            "window": {"type": "integer"},
                            "threshold": {"type": "integer"},
                            "actions": {"type": "array", "items": {"type": "string"}},
                        },
                        "required": ["id", "name", "condition"],
                    },
                }
            },
            "required": ["rules"],
        }
        jsonschema.validate(instance=rules, schema=schema)

    def connect_to_db(self):
        return psycopg2.connect(
            host=self.config["db_host"],
            port=self.config["db_port"],
            user=self.config["db_user"],
            password=self.config["db_password"],
            database=self.config["db_name"],
        )

    async def message_handler(self, msg):
        try:
            data = json.loads(msg.data.decode())
            await self.process_message(data)
        except json.JSONDecodeError:
            print("Invalid JSON message")
        except Exception as e:
            print(f"Error processing message: {e}")

    async def process_message(self, message):
        # Store in database
        self.store_message(message)

        # Apply detection rules
        alerts = self.apply_rules(message)

        # Process alerts
        for alert in alerts:
            self.store_alert(alert)
            await self.send_alert(alert)

    def store_message(self, message):
        with self.db_conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO syslog_messages (
                    timestamp, hostname, tag, message, priority, source_ip
                ) VALUES (%s, %s, %s, %s, %s, %s)
                """,
                (
                    message["timestamp"],
                    message["hostname"],
                    message["tag"],
                    message["message"],
                    message["priority"],
                    message["source_ip"],
                ),
            )
            self.db_conn.commit()

    def apply_rules(self, message):
        alerts = []
        for rule in self.rules["rules"]:
            if self.evaluate_rule(rule, message):
                alerts.append(
                    {
                        "rule_id": rule["id"],
                        "timestamp": time.time(),
                        "source_ip": message["source_ip"],
                        "hostname": message["hostname"],
                        "message": message["message"],
                        "severity": rule.get("severity", "medium"),
                        "description": rule["description"],
                    }
                )
        return alerts

    def evaluate_rule(self, rule, message):
        # Simple regex matching for demo
        if "condition" in rule:
            return re.search(rule["condition"], message["message"]) is not None

        # More complex threshold-based rules
        if "threshold" in rule and "window" in rule:
            with self.db_conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT COUNT(*) 
                    FROM syslog_messages 
                    WHERE hostname = %s 
                    AND tag = %s 
                    AND timestamp >= NOW() - INTERVAL '%s seconds'
                    """,
                    (message["hostname"], message["tag"], rule["window"]),
                )
                count = cur.fetchone()[0]
                return count >= rule["threshold"]
        return False

    def store_alert(self, alert):
        with self.db_conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO alerts (
                    rule_id, timestamp, source_ip, hostname, 
                    message, severity, description
                ) VALUES (%s, %s, %s, %s, %s, %s, %s)
                """,
                (
                    alert["rule_id"],
                    alert["timestamp"],
                    alert["source_ip"],
                    alert["hostname"],
                    alert["message"],
                    alert["severity"],
                    alert["description"],
                ),
            )
            self.db_conn.commit()

    async def send_alert(self, alert):
        # Send to notification channels
        for action in self.rules["actions"]:
            if action == "email":
                await self.send_email_alert(alert)
            elif action == "slack":
                await self.send_slack_alert(alert)

    async def send_email_alert(self, alert):
        # Implement email sending
        print(f"Sending email alert: {alert['description']}")

    async def send_slack_alert(self, alert):
        # Implement Slack webhook
        print(f"Sending Slack alert: {alert['description']}")

    async def run(self):
        await self.nc.connect(servers=[self.config["nats_url"]])
        await self.nc.subscribe("syslog.raw", cb=self.message_handler)
        print("Syslog analyzer running...")


if __name__ == "__main__":
    import asyncio

    analyzer = LogAnalyzer()
    asyncio.run(analyzer.run())
