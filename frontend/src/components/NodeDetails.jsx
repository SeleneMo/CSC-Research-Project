const riskClass = {
  green: "risk-green",
  yellow: "risk-yellow",
  red: "risk-red"
};

export function NodeDetails({ node }) {
  if (!node) {
    return (
      <section>
        <h2>Node Details</h2>
        <p>Select a node to inspect services and risk.</p>
      </section>
    );
  }

  return (
    <section>
      <h2>Node Details</h2>
      <p>
        <strong>{node.label}</strong> ({node.ip})
      </p>
      <p>Status: {node.status}</p>
      <p>
        Risk: <span className={riskClass[node.risk_level] || "risk-green"}>{node.risk_level.toUpperCase()}</span>
      </p>
      <p>Open Ports: {node.open_ports.length ? node.open_ports.join(", ") : "None"}</p>

      <h3>Services</h3>
      <ul className="details-list">
        {node.services.length === 0 && <li>No discovered services.</li>}
        {node.services.map((service) => (
          <li key={`${service.protocol}-${service.port}`}>
            {service.protocol}/{service.port} - {service.service || "unknown"} ({service.state})
          </li>
        ))}
      </ul>

      <h3>Vulnerabilities</h3>
      <ul className="details-list">
        {node.vulnerabilities.length === 0 && <li>No vulnerability script hits.</li>}
        {node.vulnerabilities.map((item, index) => (
          <li key={`${item}-${index}`}>{item}</li>
        ))}
      </ul>
    </section>
  );
}
