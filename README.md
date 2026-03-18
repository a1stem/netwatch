# NetWatch

**Live network connection monitor for Linux with firewall integration.**

See every app connecting to the internet — what process (and its full parent chain), which interface (WiFi / Ethernet / VPN), whether the connection is encrypted, what country it's talking to, and block anything suspicious with one click via UFW.

---

## Features

- **Live connection table** — all active internet connections, refreshed every 2–30s (configurable)
- **Process ancestry tree** — shows the full parent chain so you never accidentally block a child process that belongs to a trusted app
- **Interface tagging** — WiFi, Ethernet, VPN (tun0/wg0/proton0), loopback — WiFi flagged as higher interception risk
- **TLS heuristic** — flags port-80 / plaintext connections in red; port-443 shown as encrypted
- **Package manager detection** — apt, snap, flatpak, pip, npm, cargo, etc. flagged with dedicated "Update traffic" badge; plain-HTTP update fetches fire an immediate alert
- **Repository integrity audit** — scans `/etc/apt/sources.list`, `.d/`, snap, and flatpak remotes; flags HTTP sources and missing GPG keys
- **Offline GeoIP** — country flag next to every remote IP using MaxMind GeoLite2 (no network call)
- **Reverse DNS** — async hostname resolution with LRU cache; displayed next to raw IPs
- **Connection history** — append-only SQLite log; browse by app, date, unknown-only, blocked-only
- **UFW integration** — block any connection with one click; rule applied via `pkexec ufw deny out to <ip> port <port>`
- **System tray** — lives in the notification area; alerts pop up for new unknowns and high-risk update traffic
- **Trust store** — JSON file keyed by executable path; persists across sessions

---

## Quick start

### 1. Install dependencies

```bash
sudo apt install python3-pyqt5 python3-psutil ufw
pip3 install maxminddb          # optional, for GeoIP
```

### 2. Enable UFW (if not already active)

```bash
sudo ufw enable
sudo ufw status
```

### 3. Download GeoIP database (optional but recommended)

Register free at <https://dev.maxmind.com/geoip/geolite2-free-geolocation-data>
and download `GeoLite2-Country.mmdb`. Place it at:

```
netwatch/data/GeoLite2-Country.mmdb
```

### 4. Run

```bash
cd netwatch
sudo python3 main.py
```

> **Why sudo?**  
> `psutil.net_connections()` requires root or `CAP_NET_ADMIN` to list all
> system connections. See the *Privilege model* section below for alternatives.

---

## Privilege model

Three options, from simplest to most secure:

### Option A — sudo (simplest)
```bash
sudo python3 main.py
```
Works immediately. The entire GUI runs as root.

### Option B — setcap (GUI as normal user, no password prompt)
```bash
sudo setcap cap_net_admin+eip $(which python3)
python3 main.py
```
Grants `cap_net_admin` to the Python interpreter permanently.
⚠ This applies to *all* Python scripts — use with awareness.

### Option C — split daemon (recommended for ongoing use)
Run a small privileged daemon that writes connection data to a Unix socket,
and the GUI reads from it unprivileged.

```bash
# Install and start the daemon
sudo cp daemon/netwatch.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now netwatch

# Run GUI as normal user
python3 main.py
```

### UFW rules (block button)

The block button calls `pkexec ufw ...`. To avoid a password prompt each time,
set up the PolicyKit rule:

```bash
sudo groupadd netwatch
sudo usermod -aG netwatch $USER        # log out and back in
sudo cp daemon/50-netwatch.rules /etc/polkit-1/rules.d/
sudo chmod 644 /etc/polkit-1/rules.d/50-netwatch.rules
```

---

## Repository layout

```
netwatch/
├── main.py                     Entry point
├── requirements.txt
├── daemon/
│   ├── netwatch_daemon.py      Privileged connection poller (Unix socket)
│   ├── netwatch.service        systemd unit file
│   └── 50-netwatch.rules       PolicyKit rule for passwordless ufw
├── ui/
│   ├── main_window.py          QMainWindow — wires everything together
│   ├── conn_table.py           Live connection QTableView + model
│   ├── proc_tree.py            Process ancestry QTreeWidget panel
│   ├── repo_panel.py           Repository integrity audit tab
│   ├── history_view.py         SQLite log browser tab
│   └── notif_tray.py           System tray icon + alerts
├── backend/
│   ├── poller.py               QThread — central poll cycle
│   ├── resolver.py             PID → full process parent chain
│   ├── iface_mapper.py         Local IP → interface type (WiFi/ETH/VPN)
│   ├── tls_heuristic.py        Port-based TLS/plaintext classification
│   ├── dns_lookup.py           Async reverse DNS with LRU cache
│   ├── geoip.py                Offline MaxMind country lookup
│   ├── pkg_watcher.py          Package manager detection + risk scoring
│   ├── repo_checker.py         sources.list / snap / flatpak audit
│   └── ufw.py                  subprocess wrapper for ufw rules
└── data/
    ├── trust_store.py          JSON trust/block persistence
    ├── history.py              SQLite connection log
    ├── trusted_apps.json       Persisted trust decisions
    ├── settings.json           Runtime configuration
    ├── connections.db          SQLite history (auto-created)
    └── GeoLite2-Country.mmdb   MaxMind GeoIP DB (download separately)
```

---

## Understanding the connection table

| Column | Meaning |
|---|---|
| ● | Green = trusted, amber = unknown, blue = update traffic, red = blocked |
| Application | Name of the process owning the socket |
| PID | Process ID |
| Interface | ETH / WiFi / VPN / LO — WiFi carries a tooltip warning |
| Local port | Ephemeral source port on your machine |
| Remote host | Reverse-DNS hostname (or raw IP) + remote port |
| Enc | TLS = port 443 (encrypted); HTTP = port 80 (plaintext ⚠) |
| Country | Offline GeoIP flag + country code |
| Status | Trust state + any active flags |

Click any row to populate the **Process tree** panel on the right, which shows the full ancestor chain from `systemd` down to the process owning the socket. Use this before blocking — if an unrecognised process is a child of `firefox`, blocking it may affect your browser.

---

## Repository integrity audit

Switch to the **Repo integrity** tab and click **Scan repositories**.

NetWatch reads:
- `/etc/apt/sources.list` and `/etc/apt/sources.list.d/*.list`
- Modern deb822 `.sources` files
- `snap list` output
- `flatpak remotes` output

Each source is checked for:

| Check | Safe | Risk |
|---|---|---|
| Transport | `https://` | `http://` — interceptable |
| GPG key | Present in `/etc/apt/trusted.gpg.d/` | Missing — packages unverifiable |
| Origin | Official Ubuntu/Debian/Canonical | Third-party PPA or unknown |

A source with **neither HTTPS nor a GPG key** is rated **Danger** — this is precisely the configuration that allows a man-in-the-middle to silently substitute malicious packages.

---

## Package manager alerts

When `apt`, `snap`, `flatpak`, `pip`, `npm`, or similar tools make a network
connection, NetWatch:

1. Tags the row with a blue **"Update traffic"** badge
2. Logs the remote IP, hostname, port, and interface
3. If the connection is over **plain HTTP** → fires an immediate tray notification and highlights the row red
4. If the remote hostname doesn't match the known official domain list for that package manager → fires a **"Unrecognised host"** warning

---

## Contributing

Pull requests welcome. Priority areas:
- Daemon ↔ GUI socket protocol (currently the GUI talks directly to psutil)
- IPv6 connection display improvements
- AppArmor / SELinux profile awareness
- Dark mode stylesheet

---

## Licence

MIT
