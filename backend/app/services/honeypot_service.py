from app.models.schemas import GraphData, HoneypotAnalyzeResponse, HoneypotRecommendation, RiskLevel


def analyze_topology(graph: GraphData, max_suggestions: int = 5) -> HoneypotAnalyzeResponse:
    """Heuristic honeypot placement from scan graph (no ML)."""
    hosts = [n for n in graph.nodes if n.id != "scan-origin"]
    if not hosts:
        return HoneypotAnalyzeResponse(
            recommendations=[],
            summary="No discovered hosts to analyze.",
        )

    risk_rank = {RiskLevel.red: 0, RiskLevel.yellow: 1, RiskLevel.green: 2}
    hosts_sorted = sorted(
        hosts,
        key=lambda n: (
            risk_rank.get(n.risk_level, 3),
            -len(n.open_ports),
            -len(n.vulnerabilities),
        ),
    )

    recs: list[HoneypotRecommendation] = []
    for idx, node in enumerate(hosts_sorted[:max_suggestions], start=1):
        top_ports = sorted(node.open_ports)[:6]
        if not top_ports and node.services:
            top_ports = [s.port for s in node.services if s.state == "open"][:6]

        rationale_parts = [
            f"Risk level: {node.risk_level.value}.",
            f"Open ports: {len(node.open_ports)}.",
        ]
        if node.vulnerabilities:
            rationale_parts.append(f"Script findings: {len(node.vulnerabilities)}.")

        hint = (
            f"Place a medium-interaction honeypot adjacent to {node.ip}, "
            f"emulating {', '.join(str(p) for p in top_ports) or 'common services'} "
            "to catch lateral movement toward this asset."
        )

        recs.append(
            HoneypotRecommendation(
                target_node_id=node.id,
                ip=node.ip,
                priority=idx,
                rationale=" ".join(rationale_parts),
                emulate_ports=top_ports,
                placement_hint=hint,
            )
        )

    summary = (
        f"Suggested {len(recs)} placement(s), prioritizing higher-risk hosts with broader "
        "exposed surface and vulnerability script output."
    )
    return HoneypotAnalyzeResponse(recommendations=recs, summary=summary)
