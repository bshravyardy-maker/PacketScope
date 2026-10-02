"""Builds synthetic sample data so the dashboard works without a live capture."""
import json, random
random.seed(7)
protos = ["TLS"] * 46 + ["DNS"] * 14 + ["TCP"] * 14 + ["UDP"] * 10 + ["HTTP"] * 8 + ["ARP"] * 5 + ["ICMP"] * 3
hosts = ["192.168.1.12", "142.250.77.46", "104.18.32.7", "151.101.1.69", "192.168.1.1", "157.240.7.35"]
domains = ["www.google.com", "fonts.gstatic.com", "github.com", "api.netlify.com", "cdn.jsdelivr.net", "www.wikipedia.org"]
rows, tl, counts = [], {}, {}
for i in range(1, 301):
    pr = random.choice(protos)
    src, dst = random.sample(hosts, 2)
    ln = random.randint(60, 1514)
    info = {"DNS": "Query " + random.choice(domains), "ARP": f"Who has {dst}? Tell {src}",
            "ICMP": "ICMP type 8"}.get(pr, f"{random.randint(1024, 60000)} -> {random.choice([80, 443, 53])} [A]")
    rows.append({"no": i, "t": round(i * 0.1, 3), "src": src, "dst": dst, "proto": pr, "length": ln, "info": info})
    counts[pr] = counts.get(pr, 0) + 1
    tl[int(i * 0.1)] = tl.get(int(i * 0.1), 0) + ln
tk = {}
for r in rows:
    tk[r["src"]] = tk.get(r["src"], 0) + r["length"]
data = {
    "meta": {"interface": "en0", "filter": "none", "started": "sample data", "duration": 30,
             "packets": 300, "bytes": sum(r["length"] for r in rows), "sample": True},
    "protocols": [{"name": k, "count": v} for k, v in sorted(counts.items(), key=lambda x: -x[1])],
    "talkers": [{"ip": k, "bytes": v} for k, v in sorted(tk.items(), key=lambda x: -x[1])],
    "timeline": [{"t": t, "bytes": b} for t, b in sorted(tl.items())],
    "dns": [{"name": d, "count": random.randint(1, 9)} for d in domains],
    "flags": {"SYN": 22, "ACK": 190, "FIN": 14, "RST": 5, "PSH": 61},
    "alerts": [
        {"severity": "high", "type": "Possible port scan", "detail": "192.168.1.12 probed 24 ports on 192.168.1.1"},
        {"severity": "high", "type": "Cleartext credentials", "detail": "192.168.1.12 -> 151.101.1.69 sent login data without encryption"},
    ],
    "packets": rows,
}
json.dump(data, open("../dashboard/public/sample.json", "w"), indent=1)
print("wrote ../dashboard/public/sample.json")
