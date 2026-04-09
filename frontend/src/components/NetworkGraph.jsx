import { useEffect, useMemo, useRef } from "react";
import * as d3 from "d3";

const riskToColor = {
  green: "#10b981",
  yellow: "#f59e0b",
  red: "#ef4444"
};

export function NetworkGraph({ graph, selectedNodeId, onSelectNode }) {
  const svgRef = useRef(null);
  const safeGraph = useMemo(() => graph || { nodes: [], edges: [] }, [graph]);

  useEffect(() => {
    const width = 760;
    const height = 520;
    const svg = d3.select(svgRef.current);
    svg.selectAll("*").remove();
    svg.attr("viewBox", `0 0 ${width} ${height}`);

    if (safeGraph.nodes.length === 0) {
      svg
        .append("text")
        .attr("x", width / 2)
        .attr("y", height / 2)
        .attr("text-anchor", "middle")
        .attr("fill", "#9ca3af")
        .text("Run or replay a scan to render the network graph");
      return;
    }

    const simulation = d3
      .forceSimulation(safeGraph.nodes)
      .force("link", d3.forceLink(safeGraph.edges).id((d) => d.id).distance(120))
      .force("charge", d3.forceManyBody().strength(-300))
      .force("center", d3.forceCenter(width / 2, height / 2));

    const link = svg
      .append("g")
      .attr("stroke", "#334155")
      .attr("stroke-opacity", 0.8)
      .selectAll("line")
      .data(safeGraph.edges)
      .enter()
      .append("line")
      .attr("stroke-width", 1.5);

    const node = svg
      .append("g")
      .selectAll("circle")
      .data(safeGraph.nodes)
      .enter()
      .append("circle")
      .attr("r", 16)
      .attr("fill", (d) => riskToColor[d.risk_level] || riskToColor.green)
      .attr("stroke", (d) => (d.id === selectedNodeId ? "#ffffff" : "#111827"))
      .attr("stroke-width", (d) => (d.id === selectedNodeId ? 3 : 1.5))
      .style("cursor", "pointer")
      .on("click", (_, d) => onSelectNode(d.id))
      .call(
        d3
          .drag()
          .on("start", (event, d) => {
            if (!event.active) {
              simulation.alphaTarget(0.3).restart();
            }
            d.fx = d.x;
            d.fy = d.y;
          })
          .on("drag", (event, d) => {
            d.fx = event.x;
            d.fy = event.y;
          })
          .on("end", (event, d) => {
            if (!event.active) {
              simulation.alphaTarget(0);
            }
            d.fx = null;
            d.fy = null;
          })
      );

    const labels = svg
      .append("g")
      .selectAll("text")
      .data(safeGraph.nodes)
      .enter()
      .append("text")
      .attr("font-size", 12)
      .attr("fill", "#e2e8f0")
      .attr("text-anchor", "middle")
      .text((d) => d.label);

    simulation.on("tick", () => {
      link
        .attr("x1", (d) => d.source.x)
        .attr("y1", (d) => d.source.y)
        .attr("x2", (d) => d.target.x)
        .attr("y2", (d) => d.target.y);

      node.attr("cx", (d) => d.x).attr("cy", (d) => d.y);

      labels.attr("x", (d) => d.x).attr("y", (d) => d.y - 22);
    });

    return () => simulation.stop();
  }, [safeGraph, selectedNodeId, onSelectNode]);

  return (
    <section>
      <h2>Network Graph</h2>
      <svg ref={svgRef} className="graph-canvas" />
      <div className="legend">
        <span className="risk-green">Low</span>
        <span className="risk-yellow">Medium</span>
        <span className="risk-red">High</span>
      </div>
    </section>
  );
}
