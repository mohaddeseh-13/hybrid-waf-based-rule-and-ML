"""
داشبورد مدیریتی WAF 
html dashboard
در حال حاضر جزو پروژه نیست
We use API dashboard
"""

from flask import Flask, render_template_string
import json
import os
from datetime import datetime, timedelta
from collections import defaultdict
import sys

sys.path.append(os.path.join(os.path.dirname(__file__), '../..'))
from config.waf_config import WAFConfig

app = Flask(__name__)
config = WAFConfig()


def read_logs(log_file, limit=100):
    """خواندن فایل لاگ"""
    logs = []
    try:
        with open(log_file, 'r', encoding='utf-8') as f:
            lines = f.readlines()
            for line in lines[-limit:]:
                try:
                    logs.append(json.loads(line))
                except:
                    pass
    except FileNotFoundError:
        pass
    return logs[::-1]


@app.route('/')
def dashboard():
    """صفحه اصلی داشبورد"""
    
    # خواندن لاگ‌ها
    attacks = read_logs(config.LOG_DIR + 'attack.log', 1000)
    blocked = read_logs(config.LOG_DIR + 'blocked.log', 1000)
    
    # آمار
    total_attacks = len(attacks)
    total_blocked = len(blocked)
    
    # آمار 24 ساعت اخیر
    now = datetime.now()
    last_24h = now - timedelta(hours=24)
    
    recent_attacks = [a for a in attacks 
                     if datetime.fromisoformat(a['timestamp']) > last_24h]
    
    # Top IPs
    ip_counter = defaultdict(int)
    for attack in attacks:
        ip_counter[attack['ip']] += 1
    top_ips = sorted(ip_counter.items(), key=lambda x: x[1], reverse=True)[:10]
    
    # نوع حملات
    attack_types = defaultdict(int)
    for attack in attacks:
        if 'attacks' in attack.get('details', {}):
            for att in attack['details']['attacks']:
                attack_types[att.get('attack_type', 'Unknown')] += 1
    
    html = '''
    <!DOCTYPE html>
    <html lang="fa" dir="rtl">
    <head>
        <meta charset="UTF-8">
        <title>WAF Dashboard</title>
        <meta http-equiv="refresh" content="30">
        <style>
            * { margin: 0; padding: 0; box-sizing: border-box; }
            body {
                font-family: Arial, sans-serif;
                background: #f5f5f5;
                padding: 20px;
            }
            .header {
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                color: white;
                padding: 30px;
                border-radius: 10px;
                margin-bottom: 20px;
            }
            .stats {
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
                gap: 15px;
                margin-bottom: 20px;
            }
            .stat-card {
                background: white;
                padding: 20px;
                border-radius: 10px;
                box-shadow: 0 2px 5px rgba(0,0,0,0.1);
            }
            .stat-number {
                font-size: 2.5em;
                font-weight: bold;
                color: #667eea;
            }
            .section {
                background: white;
                padding: 20px;
                border-radius: 10px;
                margin-bottom: 20px;
                box-shadow: 0 2px 5px rgba(0,0,0,0.1);
            }
            table {
                width: 100%;
                border-collapse: collapse;
            }
            th, td {
                padding: 10px;
                text-align: right;
                border-bottom: 1px solid #ddd;
            }
            th {
                background: #f8f9fa;
                font-weight: bold;
            }
            .badge {
                display: inline-block;
                padding: 3px 8px;
                border-radius: 3px;
                font-size: 0.85em;
            }
            .badge-critical { background: #dc3545; color: white; }
            .badge-high { background: #fd7e14; color: white; }
            .badge-medium { background: #ffc107; color: black; }
            .badge-low { background: #28a745; color: white; }
        </style>
    </head>
    <body>
        <div class="header">
            <h1>🛡️ WAF Dashboard</h1>
            <p>Real-time Monitoring System</p>
        </div>
        
        <div class="stats">
            <div class="stat-card">
                <div class="stat-number">{{ total_attacks }}</div>
                <div>Total Attacks</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">{{ total_blocked }}</div>
                <div>Blocked</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">{{ recent_count }}</div>
                <div>Last 24h</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">{{ block_rate }}%</div>
                <div>Block Rate</div>
            </div>
        </div>
        
        <div class="section">
            <h2>🔥 Recent Attacks</h2>
            <table>
                <thead>
                    <tr>
                        <th>Time</th>
                        <th>IP</th>
                        <th>URL</th>
                        <th>Type</th>
                        <th>Status</th>
                    </tr>
                </thead>
                <tbody>
                    {% for attack in latest_attacks[:15] %}
                    <tr>
                        <td>{{ attack.timestamp.split('T')[1][:8] }}</td>
                        <td><code>{{ attack.ip }}</code></td>
                        <td>{{ attack.url[:40] }}...</td>
                        <td>{{ attack.details.get('attacks', [{}])[0].get('attack_type', 'N/A') }}</td>
                        <td>
                            {% if attack.was_blocked %}
                            <span class="badge badge-critical">Blocked</span>
                            {% else %}
                            <span class="badge badge-medium">Logged</span>
                            {% endif %}
                        </td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
        </div>
        
        <div class="section">
            <h2>📊 Top Attacker IPs</h2>
            <table>
                <thead>
                    <tr>
                        <th>IP Address</th>
                        <th>Attack Count</th>
                    </tr>
                </thead>
                <tbody>
                    {% for ip, count in top_ips %}
                    <tr>
                        <td><code>{{ ip }}</code></td>
                        <td><strong>{{ count }}</strong></td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
        </div>
        
        <p style="text-align: center; color: #666; margin-top: 20px;">
            Auto-refresh every 30 seconds
        </p>
    </body>
    </html>
    '''
    
    block_rate = int((total_blocked / total_attacks * 100) if total_attacks > 0 else 0)
    
    return render_template_string(
        html,
        total_attacks=total_attacks,
        total_blocked=total_blocked,
        recent_count=len(recent_attacks),
        block_rate=block_rate,
        latest_attacks=attacks[:15],
        top_ips=top_ips
    )


if __name__ == '__main__':
    print(" Dashboard running on http://localhost:5000")
    app.run(host='0.0.0.0', port=5000, debug=False)