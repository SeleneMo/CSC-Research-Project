import { useEffect, useMemo, useState } from "react";
import { getScanPlugins } from "../services/api";

export function ScanControls({ isRunning, onRunScan, useWebSocket, onUseWebSocketChange }) {
  const [plugins, setPlugins] = useState([]);
  const [pluginsError, setPluginsError] = useState("");
  const [scanner, setScanner] = useState("nmap");
  const [target, setTarget] = useState("127.0.0.1");
  const [scanType, setScanType] = useState("vuln");
  const [source, setSource] = useState("netvision-ui");

  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const list = await getScanPlugins();
        if (cancelled) {
          return;
        }
        setPlugins(list);
        setPluginsError("");
        setScanner((prev) => {
          if (list.some((p) => p.name === prev)) {
            return prev;
          }
          return list.find((p) => p.name === "nmap")?.name ?? list[0]?.name ?? prev;
        });
      } catch (err) {
        if (!cancelled) {
          setPluginsError(err.message || "Could not load scanners from server");
        }
      }
    })();
    return () => {
      cancelled = true;
    };
  }, []);

  const activePlugin = useMemo(
    () => plugins.find((p) => p.name === scanner) ?? null,
    [plugins, scanner]
  );

  const scanTypeOptions = useMemo(() => {
    if (!activePlugin) {
      return [];
    }
    return activePlugin.supported_scan_types.map((value) => ({
      value,
      label: activePlugin.scan_type_labels?.[value] ?? value
    }));
  }, [activePlugin]);

  useEffect(() => {
    if (!activePlugin?.supported_scan_types?.length) {
      return;
    }
    if (!activePlugin.supported_scan_types.includes(scanType)) {
      setScanType(activePlugin.supported_scan_types[0]);
    }
  }, [activePlugin, scanType]);

  function submit(event) {
    event.preventDefault();
    const extraArgs =
      scanner === "nmap"
        ? ["--host-timeout", "45s", "--script-timeout", "15s"]
        : [];

    onRunScan({
      scanner,
      target,
      scan_type: scanType,
      source,
      extra_args: extraArgs,
      _transport: useWebSocket ? "ws" : "http"
    });
  }

  return (
    <section>
      <h2>Run Scan</h2>
      <p className="plugin-hint">
        Scanners are loaded from the API (<code>GET /scans/plugins</code>). Add new tools by registering
        plugins in the FastAPI app — see <code>backend/app/scanners/plugins.py</code>.
      </p>
      {pluginsError && <p className="warn-text">{pluginsError}</p>}
      <form className="form" onSubmit={submit}>
        <label>
          Scanner (plugin)
          <select
            value={scanner}
            onChange={(e) => setScanner(e.target.value)}
            disabled={isRunning || plugins.length === 0}
          >
            {plugins.length === 0 && <option value="nmap">nmap (offline)</option>}
            {plugins.map((p) => (
              <option key={p.name} value={p.name}>
                {p.name} — {p.description}
              </option>
            ))}
          </select>
        </label>

        <label>
          Target (IP, CIDR, range)
          <input value={target} onChange={(e) => setTarget(e.target.value)} required />
        </label>

        <label>
          Scan type
          <select
            value={scanType}
            onChange={(e) => setScanType(e.target.value)}
            disabled={isRunning || scanTypeOptions.length === 0}
          >
            {scanTypeOptions.map((type) => (
              <option key={type.value} value={type.value}>
                {type.label}
              </option>
            ))}
          </select>
        </label>

        <label>
          Source tag
          <input value={source} onChange={(e) => setSource(e.target.value)} />
        </label>

        <label className="checkbox-row">
          <input
            type="checkbox"
            checked={useWebSocket}
            onChange={(e) => onUseWebSocketChange(e.target.checked)}
          />
          Live progress (WebSocket) — streams tool output when supported (e.g. Nmap stderr)
        </label>

        <button type="submit" disabled={isRunning || plugins.length === 0}>
          {isRunning ? "Scanning…" : `Run scan (${scanner})`}
        </button>
      </form>
    </section>
  );
}
