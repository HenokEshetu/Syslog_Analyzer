import psycopg2
import time
from datetime import datetime, timedelta


class CorrelationEngine:
    def __init__(self, db_config):
        self.db_conn = psycopg2.connect(**db_config)
        self.patterns = [
            self.detect_bruteforce,
            self.detect_scan_pattern,
            self.detect_lateral_movement,
        ]

    def run(self):
        while True:
            self.analyze_recent_events()
            time.sleep(60)  # Run every minute

    def analyze_recent_events(self):
        # Get events from last 5 minutes
        cutoff = datetime.utcnow() - timedelta(minutes=5)

        with self.db_conn.cursor() as cur:
            cur.execute(
                """
                SELECT * FROM syslog_messages 
                WHERE timestamp >= %s
                ORDER BY timestamp DESC
                """,
                (cutoff,),
            )
            events = cur.fetchall()

        # Apply correlation patterns
        for pattern in self.patterns:
            pattern(events)

    def detect_bruteforce(self, events):
        # Detect multiple failed login attempts
        failed_logins = [e for e in events if "Failed password" in e[4]]

        # Group by source IP and target host
        from collections import defaultdict

        attempts = defaultdict(int)

        for event in failed_logins:
            key = (event[5], event[1])  # (source_ip, hostname)
            attempts[key] += 1

        # Generate alerts for suspicious patterns
        for (source_ip, hostname), count in attempts.items():
            if count > 10:
                print(
                    f"Brute force detected: {source_ip} -> {hostname} ({count} attempts)"
                )
                self.store_correlation_alert(
                    "BRUTE_FORCE",
                    f"Multiple failed login attempts from {source_ip} to {hostname}",
                    "high",
                    source_ip,
                )

    def detect_scan_pattern(self, events):
        # Detect port scanning patterns
        scan_events = [e for e in events if "Connection attempt" in e[4]]

        # Group by source IP
        from collections import defaultdict

        targets = defaultdict(set)

        for event in scan_events:
            source_ip = event[5]
            port_match = re.search(r"port (\d+)", event[4])
            if port_match:
                targets[source_ip].add(port_match.group(1))

        # Generate alerts for scanners
        for source_ip, ports in targets.items():
            if len(ports) > 20:
                print(f"Port scan detected: {source_ip} scanned {len(ports)} ports")
                self.store_correlation_alert(
                    "PORT_SCAN",
                    f"Port scanning activity from {source_ip}",
                    "medium",
                    source_ip,
                )

    def detect_lateral_movement(self, events):
        # Detect lateral movement patterns
        auth_events = [e for e in events if "Accepted password" in e[4]]

        # Build authentication graph
        from collections import defaultdict

        auth_map = defaultdict(set)

        for event in auth_events:
            source_ip = event[5]
            user_match = re.search(r"for (\w+) from", event[4])
            if user_match:
                user = user_match.group(1)
                auth_map[user].add(event[1])  # hostname
                auth_map[source_ip].add(user)

        # Detect unusual patterns
        for entity, accesses in auth_map.items():
            if len(accesses) > 3:
                print(
                    f"Lateral movement pattern: {entity} accessed {len(accesses)} resources"
                )
                self.store_correlation_alert(
                    "LATERAL_MOVEMENT",
                    f"Unusual access pattern for {entity}",
                    "high",
                    entity,
                )

    def store_correlation_alert(self, alert_type, description, severity, source):
        with self.db_conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO correlation_alerts (
                    alert_type, description, severity, source, timestamp
                ) VALUES (%s, %s, %s, %s, NOW())
                """,
                (alert_type, description, severity, source),
            )
            self.db_conn.commit()


if __name__ == "__main__":
    db_config = {
        "host": "postgres",
        "port": 5432,
        "user": "postgres",
        "password": "password",
        "database": "syslog",
    }
    engine = CorrelationEngine(db_config)
    engine.run()
