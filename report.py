import plotly.graph_objects as go
import math


# -------------------------------
# Build Graph
# -------------------------------
def build_graph(results):
    nodes, edges = [], []
    services = {r["service"]: r for r in results}

    for r in results:
        if r.get("status") == "OPEN":
            nodes.append(r["service"])

    if services.get("SMB", {}).get("accessible_shares") and services.get("SSH", {}).get("status") == "OPEN":
        edges.append(("SMB", "SSH"))

    if services.get("FTP", {}).get("classified_hits", {}).get("credentials"):
        if services.get("SMB", {}).get("status") == "OPEN":
            edges.append(("FTP", "SMB"))
        if services.get("SSH", {}).get("status") == "OPEN":
            edges.append(("FTP", "SSH"))

    return nodes, edges


# -------------------------------
# Graph HTML
# -------------------------------
def generate_graph_div(results):
    nodes, edges = build_graph(results)

    if not nodes:
        return "<p>No graph available</p>"

    angle_step = 2 * math.pi / len(nodes)
    positions = {n: (math.cos(i * angle_step), math.sin(i * angle_step)) for i, n in enumerate(nodes)}

    edge_x, edge_y = [], []
    for src, dst in edges:
        x0, y0 = positions[src]
        x1, y1 = positions[dst]
        edge_x += [x0, x1, None]
        edge_y += [y0, y1, None]

    edge_trace = go.Scatter(x=edge_x, y=edge_y, mode='lines', line=dict(width=2))

    node_x, node_y = [], []
    for n in nodes:
        x, y = positions[n]
        node_x.append(x)
        node_y.append(y)

    node_trace = go.Scatter(
        x=node_x,
        y=node_y,
        mode='markers+text',
        text=nodes,
        textposition="top center",
        marker=dict(size=18)
    )

    fig = go.Figure(data=[edge_trace, node_trace])
    fig.update_layout(margin=dict(l=20, r=20, t=40, b=20))

    return fig.to_html(full_html=False, include_plotlyjs="cdn")


# -------------------------------
# HTML Report
# -------------------------------
def generate_html_report(results, target, filename="report.html"):
    sorted_results = sorted(results, key=lambda x: x.get("score", 0), reverse=True)
    top = sorted_results[0] if sorted_results else None
    graph_html = generate_graph_div(results)

    def badge(score):
        if score >= 90:
            return '<span class="badge critical">CRITICAL</span>'
        elif score >= 70:
            return '<span class="badge high">HIGH</span>'
        elif score >= 40:
            return '<span class="badge medium">MEDIUM</span>'
        else:
            return '<span class="badge low">LOW</span>'

    html = f"""
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title>Security Report</title>

<style>
    body {{
        font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
        background: #f5f7fa;
        margin: 0;
    }}

    .container {{
        max-width: 1000px;
        margin: 40px auto;
        padding: 20px;
    }}

    h1 {{
        font-size: 28px;
        margin-bottom: 5px;
    }}

    h2 {{
        margin-top: 30px;
        border-bottom: 1px solid #e0e0e0;
        padding-bottom: 5px;
    }}

    .card {{
        background: white;
        border-radius: 10px;
        padding: 20px;
        margin-top: 20px;
        box-shadow: 0 2px 6px rgba(0,0,0,0.05);
    }}

    .badge {{
        padding: 4px 10px;
        border-radius: 6px;
        font-size: 12px;
        font-weight: bold;
    }}

    .critical {{ background: #ffe5e5; color: #c0392b; }}
    .high {{ background: #fff4e5; color: #d35400; }}
    .medium {{ background: #fffbe5; color: #b7950b; }}
    .low {{ background: #eafaf1; color: #27ae60; }}

    ul {{
        padding-left: 20px;
    }}

    li {{
        margin-bottom: 5px;
    }}

    .service-title {{
        display: flex;
        justify-content: space-between;
        align-items: center;
    }}

    .muted {{
        color: #777;
        font-size: 13px;
    }}
</style>

</head>
<body>

<div class="container">

<h1>Security Assessment Report</h1>
<div class="muted">Target: {target}</div>

<div class="card">
<h2>Executive Summary</h2>
<p>Highest Risk: <b>{top['service']}</b> {badge(top['score'])} ({top['score']}/100)</p>
</div>

<div class="card">
<h2>Attack Path Graph</h2>
{graph_html}
</div>

<h2>Service Analysis</h2>
"""

    for r in sorted_results:
        html += f"""
<div class="card">
    <div class="service-title">
        <h3>{r['service']} ({r['status']})</h3>
        {badge(r['score'])}
    </div>
    <div class="muted">Confidence: {r.get('confidence', 0)}</div>
"""

        if r.get("findings"):
            html += "<h4>Findings</h4><ul>"
            for f in r["findings"]:
                html += f"<li>{f}</li>"
            html += "</ul>"

        if r.get("impact"):
            html += "<h4>Impact</h4><ul>"
            for i in r["impact"]:
                html += f"<li>{i}</li>"
            html += "</ul>"

        if r.get("attack_path"):
            html += "<h4>Attack Path</h4><ul>"
            for step in r["attack_path"]:
                html += f"<li>{step}</li>"
            html += "</ul>"

        html += "</div>"

    html += "</div></body></html>"

    with open(filename, "w") as f:
        f.write(html)

    print(f"[+] Professional HTML report saved to {filename}")
