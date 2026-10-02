import { useEffect, useMemo, useState } from "react";
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, AreaChart, Area, CartesianGrid, Cell } from "recharts";

const COLORS = { TCP: "#1F6F8B", UDP: "#7A5C99", HTTP: "#B7791F", TLS: "#2F855A", DNS: "#C05621", mDNS: "#8A6D3B", ARP: "#B83280", ICMP: "#4A5568", FTP: "#9B2C2C", Other: "#718096" };
const bytes = (n) => (n > 1e6 ? (n / 1e6).toFixed(1) + " MB" : n > 1e3 ? (n / 1e3).toFixed(1) + " KB" : n + " B");

export default function App() {
  const [data, setData] = useState(null);
  const [error, setError] = useState("");
  const [proto, setProto] = useState("All");
  const [query, setQuery] = useState("");

  useEffect(() => {
    fetch("/sample.json").then((r) => r.json()).then(setData).catch(() => setError("Could not load the sample data."));
  }, []);

  const onFile = (e) => {
    const file = e.target.files[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = () => {
      try {
        const json = JSON.parse(reader.result);
        if (!json.packets || !json.protocols) throw new Error();
        setData(json); setError(""); setProto("All"); setQuery("");
      } catch {
        setError("That file is not a PacketScope report. Load the capture.json made by sniffer.py.");
      }
    };
    reader.readAsText(file);
  };

  const rows = useMemo(() => {
    if (!data) return [];
    const q = query.toLowerCase();
    return data.packets.filter((p) =>
      (proto === "All" || p.proto === proto) &&
      (!q || `${p.src} ${p.dst} ${p.info}`.toLowerCase().includes(q)));
  }, [data, proto, query]);

  if (!data) return <main className="wrap"><p>{error || "Loading…"}</p></main>;
  const m = data.meta;

  return (
    <main className="wrap">
      <header className="top">
        <div>
          <h1>PacketScope</h1>
          <p className="sub">
            {m.sample ? "Showing sample data. " : ""}
            {m.packets} packets, {bytes(m.bytes)}, {m.duration}s on {m.interface}
          </p>
        </div>
        <label className="btn">
          Load capture.json
          <input type="file" accept=".json" onChange={onFile} hidden />
        </label>
      </header>
      {error && <p className="error">{error}</p>}

      <section className="findings">
        <h2>Findings</h2>
        {data.alerts.length === 0 ? (
          <p className="ok">No suspicious activity detected in this capture.</p>
        ) : (
          <ul>
            {data.alerts.map((a, i) => (
              <li key={i}><strong>{a.type}</strong><span>{a.detail}</span></li>
            ))}
          </ul>
        )}
      </section>

      <div className="grid">
        <section>
          <h2>Protocols</h2>
          <ResponsiveContainer width="100%" height={240}>
            <BarChart data={data.protocols} layout="vertical" margin={{ left: 8 }}>
              <XAxis type="number" hide />
              <YAxis type="category" dataKey="name" width={52} tickLine={false} axisLine={false} />
              <Tooltip cursor={{ fill: "#0001" }} />
              <Bar dataKey="count" radius={2}>
                {data.protocols.map((p) => <Cell key={p.name} fill={COLORS[p.name] || COLORS.Other} />)}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </section>

        <section>
          <h2>Traffic over time</h2>
          <ResponsiveContainer width="100%" height={240}>
            <AreaChart data={data.timeline}>
              <CartesianGrid stroke="#0001" vertical={false} />
              <XAxis dataKey="t" unit="s" tickLine={false} />
              <YAxis tickFormatter={bytes} width={64} tickLine={false} axisLine={false} />
              <Tooltip formatter={(v) => bytes(v)} labelFormatter={(t) => `${t}s`} />
              <Area dataKey="bytes" stroke="#0F5C6E" fill="#0F5C6E33" />
            </AreaChart>
          </ResponsiveContainer>
        </section>

        <section>
          <h2>Top talkers</h2>
          <table>
            <tbody>
              {data.talkers.map((t) => (
                <tr key={t.ip}><td className="mono">{t.ip}</td><td className="num">{bytes(t.bytes)}</td></tr>
              ))}
            </tbody>
          </table>
        </section>

        <section>
          <h2>DNS lookups</h2>
          <table>
            <tbody>
              {data.dns.length === 0 && <tr><td>No DNS queries captured.</td></tr>}
              {data.dns.map((d) => (
                <tr key={d.name}><td className="mono">{d.name}</td><td className="num">{d.count}</td></tr>
              ))}
            </tbody>
          </table>
        </section>

        <section>
          <h2>TCP flags</h2>
          <table>
            <tbody>
              {Object.entries(data.flags).map(([k, v]) => (
                <tr key={k}><td>{k}</td><td className="num">{v}</td></tr>
              ))}
            </tbody>
          </table>
        </section>
      </div>

      <section className="packets">
        <div className="bar">
          <h2>Packets</h2>
          <select value={proto} onChange={(e) => setProto(e.target.value)}>
            <option>All</option>
            {data.protocols.map((p) => <option key={p.name}>{p.name}</option>)}
          </select>
          <input placeholder="Search address or info" value={query} onChange={(e) => setQuery(e.target.value)} />
          <span className="sub">{rows.length} shown</span>
        </div>
        <div className="scroll">
          <table className="pk">
            <thead><tr><th>No.</th><th>Time</th><th>Source</th><th>Destination</th><th>Protocol</th><th>Length</th><th>Info</th></tr></thead>
            <tbody>
              {rows.map((p) => (
                <tr key={p.no}>
                  <td>{p.no}</td><td>{p.t}</td><td>{p.src}</td><td>{p.dst}</td>
                  <td><span className="tag" style={{ background: COLORS[p.proto] || COLORS.Other }}>{p.proto}</span></td>
                  <td>{p.length}</td><td>{p.info}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>
    </main>
  );
}
