from flask import Flask, render_template, request, jsonify
import psycopg2
from datetime import datetime, timedelta
import humanize

app = Flask(__name__)

# Database configuration
DB_CONFIG = {
    "host": "postgres",
    "port": 5432,
    "user": "postgres",
    "password": "password",
    "database": "syslog",
}


def get_db_connection():
    return psycopg2.connect(**DB_CONFIG)


@app.route("/")
def dashboard():
    return render_template("dashboard.html")


@app.route("/logs")
def get_logs():
    conn = get_db_connection()
    cur = conn.cursor()

    # Pagination
    page = request.args.get("page", 1, type=int)
    per_page = 50
    offset = (page - 1) * per_page

    # Filters
    hostname = request.args.get("hostname")
    tag = request.args.get("tag")
    search = request.args.get("search")

    query = "SELECT * FROM syslog_messages"
    conditions = []
    params = []

    if hostname:
        conditions.append("hostname = %s")
        params.append(hostname)
    if tag:
        conditions.append("tag = %s")
        params.append(tag)
    if search:
        conditions.append("message ILIKE %s")
        params.append(f"%{search}%")

    if conditions:
        query += " WHERE " + " AND ".join(conditions)

    query += " ORDER BY timestamp DESC LIMIT %s OFFSET %s"
    params.extend([per_page, offset])

    cur.execute(query, params)
    logs = cur.fetchall()

    # Format timestamps
    formatted_logs = []
    for log in logs:
        formatted_logs.append(
            {
                "id": log[0],
                "timestamp": humanize.naturaltime(datetime.now() - log[1]),
                "hostname": log[2],
                "tag": log[3],
                "message": log[4],
                "priority": log[5],
                "source_ip": log[6],
            }
        )

    cur.close()
    conn.close()
    return jsonify(logs=formatted_logs)


@app.route("/alerts")
def get_alerts():
    conn = get_db_connection()
    cur = conn.cursor()

    # Get time filter
    time_filter = request.args.get("time", "24h")
    if time_filter == "1h":
        cutoff = datetime.utcnow() - timedelta(hours=1)
    elif time_filter == "7d":
        cutoff = datetime.utcnow() - timedelta(days=7)
    else:  # 24h
        cutoff = datetime.utcnow() - timedelta(hours=24)

    cur.execute(
        """
        SELECT a.id, a.timestamp, a.description, a.severity, 
               a.source_ip, r.name as rule_name, r.tags
        FROM alerts a
        JOIN detection_rules r ON a.rule_id = r.id
        WHERE a.timestamp >= %s
        ORDER BY a.timestamp DESC
        """,
        (cutoff,),
    )
    alerts = cur.fetchall()

    # Format alerts
    formatted_alerts = []
    for alert in alerts:
        formatted_alerts.append(
            {
                "id": alert[0],
                "timestamp": humanize.naturaltime(datetime.now() - alert[1]),
                "description": alert[2],
                "severity": alert[3],
                "source_ip": alert[4],
                "rule_name": alert[5],
                "tags": alert[6],
            }
        )

    cur.close()
    conn.close()
    return jsonify(alerts=formatted_alerts)


@app.route("/stats")
def get_stats():
    conn = get_db_connection()
    cur = conn.cursor()

    # Log volume stats
    cur.execute(
        """
        SELECT 
            COUNT(*) AS total,
            COUNT(*) FILTER (WHERE timestamp >= NOW() - INTERVAL '1 hour') AS last_hour,
            COUNT(*) FILTER (WHERE tag = 'sshd') AS ssh,
            COUNT(*) FILTER (WHERE tag = 'sudo') AS sudo,
            COUNT(*) FILTER (WHERE tag = 'firewall') AS firewall
        FROM syslog_messages
        """
    )
    log_stats = cur.fetchone()

    # Alert stats
    cur.execute(
        """
        SELECT 
            COUNT(*) AS total_alerts,
            COUNT(*) FILTER (WHERE severity = 'critical') AS critical,
            COUNT(*) FILTER (WHERE severity = 'high') AS high,
            COUNT(*) FILTER (WHERE source_ip IS NOT NULL) AS with_ip
        FROM alerts
        WHERE timestamp >= NOW() - INTERVAL '24 hours'
        """
    )
    alert_stats = cur.fetchone()

    # Top sources
    cur.execute(
        """
        SELECT source_ip, COUNT(*) 
        FROM alerts 
        WHERE timestamp >= NOW() - INTERVAL '24 hours'
        GROUP BY source_ip 
        ORDER BY COUNT(*) DESC 
        LIMIT 5
        """
    )
    top_sources = cur.fetchall()

    cur.close()
    conn.close()

    return jsonify(
        {
            "log_volume": {
                "total": log_stats[0],
                "last_hour": log_stats[1],
                "ssh": log_stats[2],
                "sudo": log_stats[3],
                "firewall": log_stats[4],
            },
            "alerts": {
                "total": alert_stats[0],
                "critical": alert_stats[1],
                "high": alert_stats[2],
                "with_ip": alert_stats[3],
                "top_sources": [
                    {"ip": ip, "count": count} for ip, count in top_sources
                ],
            },
        }
    )


@app.route("/timeline")
def get_timeline():
    conn = get_db_connection()
    cur = conn.cursor()

    # Get events for the last 24 hours grouped by hour
    cur.execute(
        """
        SELECT 
            DATE_TRUNC('hour', timestamp) AS hour,
            COUNT(*) AS log_count,
            COUNT(*) FILTER (WHERE tag = 'sshd') AS ssh_count,
            COUNT(*) FILTER (WHERE tag = 'sudo') AS sudo_count
        FROM syslog_messages
        WHERE timestamp >= NOW() - INTERVAL '24 hours'
        GROUP BY hour
        ORDER BY hour
        """
    )
    timeline = cur.fetchall()

    # Format for chart
    hours = []
    log_counts = []
    ssh_counts = []
    sudo_counts = []

    for entry in timeline:
        hours.append(entry[0].strftime("%H:%M"))
        log_counts.append(entry[1])
        ssh_counts.append(entry[2])
        sudo_counts.append(entry[3])

    cur.close()
    conn.close()

    return jsonify(
        {
            "hours": hours,
            "log_counts": log_counts,
            "ssh_counts": ssh_counts,
            "sudo_counts": sudo_counts,
        }
    )


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
