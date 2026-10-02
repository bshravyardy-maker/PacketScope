#!/usr/bin/env python3
"""PacketScope sniffer: capture packets, dissect them, write a JSON report + .pcap.

Usage (macOS, needs admin rights):
    sudo ./venv/bin/python sniffer.py --iface en0 --duration 30
"""
import argparse, json, time
from collections import Counter, defaultdict
from scapy.all import sniff, wrpcap, IP, IPv6, TCP, UDP, ICMP, ARP, DNS, DNSQR, Raw

CLEARTEXT_PORTS = {21, 23, 25, 80, 110, 143, 8080}
CRED_MARKERS = (b"password=", b"passwd=", b"pass ", b"authorization: basic")


def classify(p):
    if p.haslayer(UDP) and 5353 in {p[UDP].sport, p[UDP].dport}:
        return "mDNS"
    if p.haslayer(DNS):
        return "DNS"
    if p.haslayer(ARP):
        return "ARP"
    if p.haslayer(TCP):
        ports = {p[TCP].sport, p[TCP].dport}
        if ports & {80, 8080}:
            return "HTTP"
        if 443 in ports:
            return "TLS"
        if 21 in ports:
            return "FTP"
        return "TCP"
    if p.haslayer(UDP):
        return "UDP"
    if p.haslayer(ICMP):
        return "ICMP"
    return "Other"


def addresses(p):
    if IP in p:
        return p[IP].src, p[IP].dst
    if IPv6 in p:
        return p[IPv6].src, p[IPv6].dst
    if ARP in p:
        return p[ARP].psrc, p[ARP].pdst
    return "-", "-"


def info(p, proto):
    if proto in ("DNS", "mDNS") and p.haslayer(DNSQR):
        return "Query " + p[DNSQR].qname.decode(errors="ignore").rstrip(".")
    if proto == "mDNS":
        return "mDNS announcement"
    if p.haslayer(TCP):
        t = p[TCP]
        return f"{t.sport} -> {t.dport} [{t.sprintf('%flags%')}]"
    if p.haslayer(UDP):
        return f"{p[UDP].sport} -> {p[UDP].dport}"
    if p.haslayer(ARP):
        a = p[ARP]
        return f"Who has {a.pdst}? Tell {a.psrc}" if a.op == 1 else f"{a.psrc} is at {a.hwsrc}"
    if p.haslayer(ICMP):
        return f"ICMP type {p[ICMP].type}"
    return p.summary()[:60]


def analyze(packets, meta):
    t0 = float(packets[0].time) if packets else 0.0
    protocols, talkers, dns_q, flags = Counter(), Counter(), Counter(), Counter()
    timeline = defaultdict(int)
    syn_ports = defaultdict(set)
    arp_macs = defaultdict(set)
    alerts, seen_alerts, rows = [], set(), []

    def alert(sev, kind, detail):
        if (kind, detail) not in seen_alerts:
            seen_alerts.add((kind, detail))
            alerts.append({"severity": sev, "type": kind, "detail": detail})

    for i, p in enumerate(packets, 1):
        size, proto = len(p), classify(p)
        src, dst = addresses(p)
        protocols[proto] += 1
        talkers[src] += size
        timeline[int(float(p.time) - t0)] += size

        if proto == "DNS" and p.haslayer(DNSQR) and p[DNS].qr == 0:
            dns_q[p[DNSQR].qname.decode(errors="ignore").rstrip(".")] += 1

        if p.haslayer(TCP):
            f = int(p[TCP].flags)
            for bit, name in ((0x02, "SYN"), (0x10, "ACK"), (0x01, "FIN"), (0x04, "RST"), (0x08, "PSH")):
                if f & bit:
                    flags[name] += 1
            if f & 0x02 and not f & 0x10:  # SYN without ACK
                syn_ports[(src, dst)].add(p[TCP].dport)
            if p.haslayer(Raw) and {p[TCP].sport, p[TCP].dport} & CLEARTEXT_PORTS:
                if any(m in bytes(p[Raw]).lower() for m in CRED_MARKERS):
                    alert("high", "Cleartext credentials", f"{src} -> {dst} sent login data without encryption")

        if p.haslayer(ARP) and p[ARP].op == 2:
            arp_macs[p[ARP].psrc].add(p[ARP].hwsrc)

        if i <= 300:
            rows.append({"no": i, "t": round(float(p.time) - t0, 3), "src": src, "dst": dst,
                         "proto": proto, "length": size, "info": info(p, proto)})

    for (src, dst), ports in syn_ports.items():
        if len(ports) >= 15:
            alert("high", "Possible port scan", f"{src} probed {len(ports)} ports on {dst}")
    for ip, macs in arp_macs.items():
        if len(macs) > 1:
            alert("high", "Possible ARP spoofing", f"{ip} claimed by {len(macs)} different MAC addresses")

    return {
        "meta": {**meta, "packets": len(packets), "bytes": sum(len(p) for p in packets)},
        "protocols": [{"name": k, "count": v} for k, v in protocols.most_common()],
        "talkers": [{"ip": k, "bytes": v} for k, v in talkers.most_common(8)],
        "timeline": [{"t": t, "bytes": b} for t, b in sorted(timeline.items())],
        "dns": [{"name": k, "count": v} for k, v in dns_q.most_common(15)],
        "flags": dict(flags),
        "alerts": alerts,
        "packets": rows,
    }


def main():
    ap = argparse.ArgumentParser(description="PacketScope packet sniffer")
    ap.add_argument("--iface", default="en0", help="network interface (en0 is Wi-Fi on most MacBooks)")
    ap.add_argument("--duration", type=int, default=30, help="seconds to capture")
    ap.add_argument("--count", type=int, default=0, help="stop after N packets (0 = no limit)")
    ap.add_argument("--filter", default="", help="BPF filter, e.g. 'tcp port 80'")
    ap.add_argument("--out", default="capture", help="output name without extension")
    a = ap.parse_args()

    print(f"Capturing on {a.iface} for {a.duration}s ... generate some traffic (browse, ping).")
    started = time.strftime("%Y-%m-%d %H:%M:%S")
    packets = sniff(iface=a.iface, timeout=a.duration, count=a.count, filter=a.filter or None, store=True)
    if not len(packets):
        print("No packets captured. Check the interface name and that you ran with sudo.")
        return
    wrpcap(a.out + ".pcap", packets)
    report = analyze(list(packets), {"interface": a.iface, "filter": a.filter or "none",
                                     "started": started, "duration": a.duration, "sample": False})
    with open(a.out + ".json", "w") as fh:
        json.dump(report, fh, indent=1)
    print(f"Captured {len(packets)} packets. Wrote {a.out}.pcap (open in Wireshark) and {a.out}.json (load in dashboard).")
    for al in report["alerts"]:
        print(f"[{al['severity'].upper()}] {al['type']}: {al['detail']}")


if __name__ == "__main__":
    main()
