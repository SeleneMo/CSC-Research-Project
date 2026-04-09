function formatTime(raw) {
  const date = new Date(raw);
  return `${date.toLocaleDateString()} ${date.toLocaleTimeString()}`;
}

export function ScanHistory({ scans, onReplayScan }) {
  return (
    <section>
      <h2>Scan History / Replay</h2>
      <div className="history-list">
        {scans.length === 0 && <p>No scans yet.</p>}
        {scans.map((scan) => (
          <button key={scan.scan_id} className="history-item" onClick={() => onReplayScan(scan.scan_id)}>
            <span>{formatTime(scan.timestamp)}</span>
            <span className="history-scanner">{scan.scanner || "?"}</span>
            <span>{scan.scan_type.toUpperCase()}</span>
            <span>{scan.destination}</span>
          </button>
        ))}
      </div>
    </section>
  );
}
