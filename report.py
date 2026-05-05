import os
import json
import logging

# ---------------------------------------------------------------------------
# Setup Module-Specific Logger
# ---------------------------------------------------------------------------
logger = logging.getLogger("PivotRaid.Report")

def build_attack_chain(results):
    """
    Analyzes the structural scan results to programmatically compile
    a directional attack chain of nodes and links.
    """
    nodes = [{"id": "Attacker", "type": "origin", "label": "External Threat Actor"}]
    links = []

    # Track which services are online
    services = {r["service"]: r for r in results if r.get("status") == "OPEN"}

    for name, r in services.items():
        # Add the primary service node
        nodes.append({
            "id": name,
            "type": "service",
            "label": f"{name} (Port {r['port']})",
            "verdict": r.get("verdict", "LOW").split(" ")[0].upper(),
            "score": r.get("score", 0)
        })

        # Link 1: Initial access paths
        if r.get("anonymous") or r.get("weak_creds") or r.get("vulns"):
            links.append({"source": "Attacker", "target": name, "label": "Initial Access"})

        # Link 2: Highlight critical vulnerability CVEs as sub-nodes
        for vuln in r.get("vulns", []):
            vuln_id = f"VULN_{vuln['id']}"
            nodes.append({
                "id": vuln_id,
                "type": "exploit",
                "label": f"{vuln['cve'] if vuln.get('cve') else 'Exploit'}: {vuln['title']}",
                "verdict": vuln.get("severity", "HIGH")
            })
            links.append({"source": name, "target": vuln_id, "label": "Exploited"})

    # Pivot Correlation Logic
    ftp = services.get("FTP")
    smb = services.get("SMB")

    if ftp and smb:
        # Cross-Service Path: FTP Credentials leak used to access SMB admin shares
        ftp_creds = ftp.get("classified_hits", {}).get("credentials")
        if ftp_creds:
            links.append({
                "source": "FTP",
                "target": "SMB",
                "label": "Credential Pivot"
            })
        elif ftp.get("writable"):
            links.append({
                "source": "FTP",
                "target": "SMB",
                "label": "Payload Upload Pivot"
            })

    return {"nodes": nodes, "links": links}


def generate_d3_network_js(chain_data):
    """
    Generates a native, responsive D3.js force-directed graph script.
    Provides stunning interactive visual nodes with zero bulky Python backend graph dependencies.
    """
    if not chain_data["nodes"] or len(chain_data["nodes"]) <= 1:
        return "<div class='no-graph'>No open network services detected to plot.</div>"

    # Convert the Python data structural dicts securely to JSON strings
    nodes_json = json.dumps(chain_data["nodes"])
    links_json = json.dumps(chain_data["links"])

    js_code = f"""
    <div id="attack-graph" style="width: 100%; height: 450px; background: #0b0d16; border-radius: 8px; border: 1px solid #1e2235; position: relative; overflow: hidden;"></div>
    <script src="https://d3js.org/d3.v7.min.js"></script>
    <script>
        const nodes = {nodes_json};
        const links = {links_json};

        const width = document.getElementById('attack-graph').clientWidth;
        const height = 450;

        const svg = d3.select("#attack-graph")
            .append("svg")
            .attr("width", "100%")
            .attr("height", height)
            .attr("viewBox", `0 0 ${{width}} ${{height}}`);

        // Defining Marker Arrowheads for Directional Edges
        svg.append("defs").selectAll("marker")
            .data(["arrow"])
            .enter().append("marker")
            .attr("id", d => d)
            .attr("viewBox", "0 -5 10 10")
            .attr("refX", 25)
            .attr("refY", 0)
            .attr("markerWidth", 6)
            .attr("markerHeight", 6)
            .attr("orient", "auto")
            .append("path")
            .attr("fill", "#00ffcc")
            .attr("d", "M0,-5L10,0L0,5");

        const simulation = d3.forceSimulation(nodes)
            .force("link", d3.forceLink(links).id(d => d.id).distance(120))
            .force("charge", d3.forceManyBody().strength(-300))
            .force("center", d3.forceCenter(width / 2, height / 2));

        // Draw Links
        const link = svg.append("g")
            .selectAll("line")
            .data(links)
            .enter().append("line")
            .attr("stroke", "#1e2438")
            .attr("stroke-width", 2)
            .attr("marker-end", "url(#arrow)");

        // Add link text labels
        const linkText = svg.append("g")
            .selectAll("text")
            .data(links)
            .enter().append("text")
            .attr("fill", "#5f6e85")
            .attr("font-size", "9px")
            .attr("text-anchor", "middle")
            .text(d => d.label);

        // Draw Nodes
        const node = svg.append("g")
            .selectAll("g")
            .data(nodes)
            .enter().append("g")
            .call(d3.drag()
                .on("start", dragstarted)
                .on("drag", dragged)
                .on("end", dragended));

        // Color nodes based on type/threat
        node.append("circle")
            .attr("r", d => d.type === 'origin' ? 14 : 10)
            .attr("fill", d => {{
                if (d.type === 'origin') return "#ff3366";
                if (d.type === 'exploit') return "#ff9900";
                return d.verdict === 'CRITICAL' ? '#ff3333' :
                       d.verdict === 'HIGH' ? '#ff9900' : '#00ffcc';
            }})
            .attr("stroke", "#0b0d16")
            .attr("stroke-width", 2);

        // Text Labels
        node.append("text")
            .attr("dx", 14)
            .attr("dy", ".35em")
            .attr("fill", "#e3e6eb")
            .attr("font-size", "11px")
            .attr("font-weight", d => d.type === 'origin' ? 'bold' : 'normal')
            .text(d => d.id);

        simulation.on("tick", () => {{
            link
                .attr("x1", d => d.source.x)
                .attr("y1", d => d.source.y)
                .attr("x2", d => d.target.x)
                .attr("y2", d => d.target.y);

            linkText
                .attr("x", d => (d.source.x + d.target.x) / 2)
                .attr("y", d => (d.source.y + d.target.y) / 2 - 5);

            node
                .attr("transform", d => `translate(${{d.x}}, ${{d.y}})`);
        }});

        function dragstarted(event, d) {{
            if (!event.active) simulation.alphaTarget(0.3).restart();
            d.fx = d.x;
            d.fy = d.y;
        }}

        function dragged(event, d) {{
            d.fx = event.x;
            d.fy = event.y;
        }}

        function dragended(event, d) {{
            if (!event.active) simulation.alphaTarget(0);
            d.fx = null;
            d.fy = null;
        }}
    </script>
    """
    return js_code


def generate_html_report(results, target, filename="report.html"):
    """
    Assembles results and network visualizer arrays, generating
    a stunning threat dashboard report in HTML.
    """
    logger.info(f"Generating professional security HTML report: {filename}")

    sorted_results = sorted(results, key=lambda x: x.get("score", 0), reverse=True)
    top_vulnerability = sorted_results[0] if sorted_results else None

    chain_data = build_attack_chain(results)
    interactive_graph_html = generate_d3_network_js(chain_data)

    def get_badge_class(verdict_str):
        verdict_lower = verdict_str.lower()
        if "critical" in verdict_lower:
            return "critical"
        elif "high" in verdict_lower:
            return "high"
        elif "medium" in verdict_lower:
            return "medium"
        return "low"

    def format_verdict_label(verdict_str):
        return verdict_str.split(" ")[0].upper()

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>PivotRaid - Threat Assessment Report</title>
    <style>
        :root {{
            --bg-main: #0b0d16;
            --bg-card: #121625;
            --bg-card-header: #1b2035;
            --border-color: #222943;
            --text-primary: #e3e6eb;
            --text-secondary: #8592a6;
            --accent-cyber: #00ffcc;
            --color-critical: #ff3355;
            --color-high: #ff9f1a;
            --color-medium: #ffd32a;
            --color-low: #05c46b;
        }}

        body {{
            font-family: 'Segoe UI', -apple-system, BlinkMacSystemFont, Roboto, sans-serif;
            background-color: var(--bg-main);
            color: var(--text-primary);
            margin: 0;
            padding: 0;
        }}

        .container {{
            max-width: 1100px;
            margin: 40px auto;
            padding: 0 24px;
        }}

        header {{
            border-bottom: 2px solid var(--border-color);
            padding-bottom: 20px;
            margin-bottom: 30px;
            display: flex;
            justify-content: space-between;
            align-items: flex-end;
        }}

        h1 {{
            font-size: 32px;
            font-weight: 800;
            margin: 0 0 5px 0;
            letter-spacing: -0.5px;
            background: linear-gradient(135deg, #ffffff, var(--text-secondary));
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }}

        h2 {{
            font-size: 20px;
            font-weight: 700;
            color: var(--accent-cyber);
            margin: 0 0 15px 0;
            display: flex;
            align-items: center;
            gap: 8px;
        }}

        .card {{
            background-color: var(--bg-card);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            padding: 24px;
            margin-bottom: 24px;
            box-shadow: 0 10px 30px rgba(0, 0, 0, 0.25);
        }}

        .badge {{
            padding: 4px 10px;
            border-radius: 4px;
            font-size: 11px;
            font-weight: 800;
            letter-spacing: 0.5px;
            text-transform: uppercase;
            display: inline-block;
        }}

        .badge.critical {{ background-color: rgba(255, 51, 85, 0.15); color: var(--color-critical); border: 1px solid var(--color-critical); }}
        .badge.high {{ background-color: rgba(255, 159, 26, 0.15); color: var(--color-high); border: 1px solid var(--color-high); }}
        .badge.medium {{ background-color: rgba(255, 211, 42, 0.15); color: var(--color-medium); border: 1px solid var(--color-medium); }}
        .badge.low {{ background-color: rgba(5, 196, 107, 0.15); color: var(--color-low); border: 1px solid var(--color-low); }}

        ul {{
            padding-left: 20px;
            margin: 10px 0;
        }}

        li {{
            margin-bottom: 8px;
            color: var(--text-primary);
        }}

        .service-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            border-bottom: 1px solid var(--border-color);
            padding-bottom: 12px;
            margin-bottom: 15px;
        }}

        .service-title-text {{
            font-size: 18px;
            font-weight: 700;
            margin: 0;
            color: #ffffff;
        }}

        .muted {{
            color: var(--text-secondary);
            font-size: 13px;
        }}

        .meta-grid {{
            display: flex;
            gap: 40px;
            margin-top: 15px;
        }}

        .meta-item {{
            display: flex;
            flex-direction: column;
        }}

        .meta-value {{
            font-size: 18px;
            font-weight: 700;
            color: #fff;
        }}

        .vuln-table {{
            width: 100%;
            border-collapse: collapse;
            margin-top: 15px;
        }}

        .vuln-table th {{
            background-color: var(--bg-card-header);
            color: var(--accent-cyber);
            text-align: left;
            padding: 10px 15px;
            font-size: 12px;
            text-transform: uppercase;
            font-weight: 800;
        }}

        .vuln-table td {{
            padding: 12px 15px;
            border-bottom: 1px solid var(--border-color);
            font-size: 13px;
        }}

        .vuln-table tr:hover {{
            background-color: rgba(255, 255, 255, 0.02);
        }}

        .no-graph {{
            padding: 40px;
            text-align: center;
            color: var(--text-secondary);
        }}
    </style>
</head>
<body>

<div class="container">

    <header>
        <div>
            <h1>PivotRaid Threat Assessment</h1>
            <div class="muted">Target System Core Profile: <strong>{target}</strong></div>
        </div>
        <div class="muted">Generated on 2026-05-05</div>
    </header>

    <div class="card">
        <h2>Executive Summary</h2>
        <div class="meta-grid">
            <div class="meta-item">
                <span class="muted">Target Host IP</span>
                <span class="meta-value">{target}</span>
            </div>
            <div class="meta-item">
                <span class="muted">Primary Threat Vector</span>
                <span class="meta-value" style="color: #ffffff">{top_vulnerability['service'] if top_vulnerability else 'N/A'}</span>
            </div>
            <div class="meta-item">
                <span class="muted">Highest Risk Score</span>
                <span>
                    <span class="badge {get_badge_class(top_vulnerability['verdict'] if top_vulnerability else 'LOW')}">
                        {format_verdict_label(top_vulnerability['verdict'] if top_vulnerability else 'LOW')} ({top_vulnerability['score'] if top_vulnerability else 0}/100)
                    </span>
                </span>
            </div>
        </div>
    </div>

    <div class="card">
        <h2>Interactive Threat Pathway</h2>
        {interactive_graph_html}
    </div>

    <h2>Exploitation Interface Analysis</h2>
"""

    for r in sorted_results:
        badge_class = get_badge_class(r.get("verdict", "LOW"))
        html += f"""
    <div class="card">
        <div class="service-header">
            <h3 class="service-title-text">{r['service']} on Port {r['port']} ({r['status']})</h3>
            <span class="badge {badge_class}">{format_verdict_label(r['verdict'])}</span>
        </div>
        <div class="muted" style="margin-bottom: 15px;">Confidence Score: <strong>{r.get('confidence', 0)}/100</strong></div>
"""

        # Append Exploit-DB entries if they exist
        if r.get("vulns"):
            html += """
            <h4 style="font-size: 13px; color: var(--accent-cyber); margin-top: 15px;">Discovered Vulnerability Indexes</h4>
            <table class="vuln-table">
                <thead>
                    <tr>
                        <th>CVE Identifier</th>
                        <th>Vulnerability Title</th>
                        <th>Threat Class</th>
                        <th>Exploit Payload Link</th>
                    </tr>
                </thead>
                <tbody>
            """
            for v in r["vulns"]:
                html += f"""
                    <tr>
                        <td style="font-family: monospace; font-weight: bold; color: var(--color-critical);">{v.get('cve', 'EDB-ID: ' + str(v['id']))}</td>
                        <td>{v['title']}</td>
                        <td><span class="badge {get_badge_class(v['severity'])}">{v['severity']}</span></td>
                        <td><a href="{v.get('url', '#')}" target="_blank" style="color: var(--accent-cyber); text-decoration: none;">View Exploit Details &rarr;</a></td>
                    </tr>
                """
            html += "</tbody></table>"

        if r.get("findings"):
            html += '<h4 style="font-size: 13px; color: var(--accent-cyber); margin-top: 15px;">Interface Enumeration</h4><ul>'
            for f in r["findings"]:
                html += f"<li>{f}</li>"
            html += "</ul>"

        if r.get("impact"):
            html += '<h4 style="font-size: 13px; color: var(--accent-cyber); margin-top: 15px;">Local Exposure Impact</h4><ul>'
            for i in r["impact"]:
                html += f"<li>{i}</li>"
            html += "</ul>"

        if r.get("attack_path"):
            html += '<h4 style="font-size: 13px; color: var(--accent-cyber); margin-top: 15px;">Local Attack Path Progression</h4><ol style="padding-left: 20px; line-height: 1.6;">'
            for step in r["attack_path"]:
                html += f"<li style='margin-bottom: 5px;'>{step}</li>"
            html += "</ol>"

        html += "</div>"

    html += "</div></body></html>"

    with open(filename, "w", encoding="utf-8") as f:
        f.write(html)

    print(f"[+] High-fidelity cyber threat assessment report saved to {filename}")
