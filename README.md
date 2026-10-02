# PacketScope: Network Packet Sniffing and Analysis

Two parts:
- `sniffer/` is a Python (Scapy) tool that captures packets on your machine, dissects them (Ethernet, IP, TCP/UDP/ICMP, ARP, DNS, HTTP/TLS), detects port scans, ARP spoofing and cleartext credentials, and writes `capture.pcap` and `capture.json`.
- `dashboard/` is a React + Vite web dashboard that shows the results. It is deployed on Netlify and works with bundled sample data or any `capture.json` you load.

Netlify cannot capture packets (no raw network access), so capture runs locally and the dashboard only visualises the report.

## 1. Run the sniffer (MacBook)
```bash
cd sniffer
python3 -m venv venv
./venv/bin/pip install -r requirements.txt
sudo ./venv/bin/python sniffer.py --iface en0 --duration 30
```
While it runs, browse a few sites and run `ping google.com` to create traffic.
Find your interface with `ifconfig` (Wi-Fi is usually `en0`). Optional: `--filter "tcp port 80"`.

Outputs: `capture.pcap` (open in Wireshark to compare) and `capture.json`.

## 2. Run the dashboard
```bash
cd dashboard
npm install
npm run dev
```
Open the printed localhost link, click **Load capture.json**, and pick your file.

## 3. Demo the detections (own machine / own network only)
- Port scan: `nmap -p 1-100 <your-own-test-IP>` while the sniffer runs.
- Cleartext credentials: send a POST to a test HTTP server on your own machine.

## 4. Push to GitHub and deploy on Netlify
```bash
git init && git add . && git commit -m "PacketScope"
git branch -M main
git remote add origin https://github.com/<you>/packetscope.git
git push -u origin main
```
In Netlify: Add new site, Import from GitHub, pick the repo. `netlify.toml` already sets base `dashboard`, build `npm run build`, publish `dist`. Deploy.

## Ethics
Capture only on networks you own or have written permission to test. `.pcap` files are git-ignored because they can contain private data. Detections log who sent credentials, never the credential itself.
