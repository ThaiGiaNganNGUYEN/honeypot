# Training honeypot

A low-interaction decoy that imitates SSH, HTTP, and FTP, writes every session to a log, and never runs what a client types. Use it to practice threat detection and log analysis on a machine you control.

The decoy listens on `127.0.0.1` only. Commands are answered from a fake Linux personality named `prod-gateway`. Downloads are not fetched, uploads are not saved, and FTP active mode is refused so the process never connects to an address a client supplies.

## What you will practice

- Giving a honeypot a personality: banners, hostname, and fake files for specific services.
- Recording logins, commands, and web probes in one event schema.
- Turning those events into a short list of things to check on the real network.

## How this maps to the usual tools

| Idea | In this project |
| --- | --- |
| Honeyd | Service personalities. SSH, HTTP, and FTP banners and the fake host are set in `config/honeypot.json`. |
| Kippo | The SSH service records the password, then presents a fake shell. Cowrie is the maintained Kippo successor; this lab reimplements that pattern in Python so it runs on Windows without an old daemon. |
| Dionaea | Dionaea stores malware samples. This lab does not. An upload is hashed in memory and discarded. |
| VirtualBox | `Vagrantfile` builds an isolated Ubuntu VM. |
| Splunk | `deploy/splunk/` plus the searches below. |
| ELK | `docker compose --profile elk up` ships the JSON log with Filebeat. |

## Safety rules

- Run it only on a computer and network you are allowed to use.
- Do not type a real password. The demo uses `training-only`.
- Leave `bind_host` at `127.0.0.1` for local work. The HTTP pages and the SSH login banner say this is a training system.
- Do not add code that shells out, fetches a URL from a command, or writes an upload to disk.

## Layout

| Path | Role |
| --- | --- |
| `config/honeypot.json` | Ports, banners, and the personality hostname |
| `honeypot/shell.py` | Fake shell and fake files |
| `honeypot/services/` | SSH, HTTP, and FTP decoys |
| `logs/events.jsonl` | One JSON event per line (created when you run) |
| `logs/events.log` | Same events, one readable line each |
| `honeypot/analyze.py` | Text report and `reports/summary.json` |
| `honeypot/dashboard.py` | Local analyst page |
| `honeypot/demo.py` | Training client. It can only connect to `127.0.0.1` |

## Event fields

Each line in `logs/events.jsonl` has `timestamp`, `session_id`, `service`, `event_type`, `category`, `src_ip`, `src_port`, `dst_port`, `username`, `password`, `command`, `path`, `status`, `indicator`, `summary`, and `message`.

Categories:

| Category | Meaning |
| --- | --- |
| `connection` | TCP open or close |
| `authentication` | A password or key was submitted |
| `recon` | Listing, banners, ordinary paths |
| `collection` | A sensitive-looking path or a file transfer |
| `egress_attempt` | A download or remote-access style command. Nothing was contacted |

Group a visit with `session_id`.

## Run it on Windows

From `Cybersecurity\honeypot`:

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe -m honeypot
```

Leave that window open. In a second window:

```powershell
cd Cybersecurity\honeypot
.\.venv\Scripts\python.exe -m honeypot.demo
.\.venv\Scripts\python.exe -m honeypot.analyze
```

Then open:

- Analyst page: http://127.0.0.1:8090
- Decoy site: http://127.0.0.1:8080

You can also watch the text log:

```powershell
Get-Content .\logs\events.log -Wait
```

A manual SSH session, using a training password:

```powershell
ssh -p 2222 -o StrictHostKeyChecking=no -o UserKnownHostsFile=NUL -o PreferredAuthentications=password -o PubkeyAuthentication=no root@127.0.0.1
```

| Port | What it is |
| --- | --- |
| 2222 | SSH decoy |
| 8080 | HTTP decoy |
| 2121 | FTP decoy |
| 8090 | Dashboard (not a lure) |

Run the tests with:

```powershell
.\.venv\Scripts\python.exe -m unittest discover -s tests -t . -v
```

## Change the personality

Edit `config/honeypot.json`, then restart.

- `ssh.hostname` is the name inside the fake shell. The real computer name does not change.
- `ssh.banner` and `http.server_header` are what scanners read first.
- `ssh.reject_first_n` rejects that many passwords from each source address before accepting one into the fake shell. Set it to `2`, connect twice, and compare `accepted` and `rejected` in the report.
- Set `ftp.enabled` to `false` and the next report only shows the services that were touched.

## Read the report

`python -m honeypot.analyze` writes `reports/report.txt` and `reports/summary.json`. The useful part is the insight list:

- Which usernames and passwords were tried, so you can check them against real accounts.
- Which paths were requested, so you can confirm the real servers do not expose them.
- Which URLs showed up in commands. The honeypot did not download them. Search DNS or proxy logs on the real network for those indicators.

## Docker

Requires Docker. Published ports stay on `127.0.0.1`.

```powershell
docker compose up --build
```

The container starts as root only long enough to make the log directory writable, then drops to the `honeypot` user when the platform allows it.

## VirtualBox

Requires VirtualBox and Vagrant. From this folder:

```powershell
vagrant up
```

The VM is host-only at `192.168.56.20`, plus localhost forwards for ports 2222, 8080, 2121, and 8090. Do not run the Windows copy at the same time, or those forwards collide. The guest firewall allows the decoy ports only from the host-only and NAT subnets. After you change the code, run `vagrant provision` to copy it into the VM. Logs on the guest are in `/var/log/honeypot`. Follow them with:

```bash
vagrant ssh -c "sudo journalctl -u honeypot -f"
```

## Splunk

1. Create an index named `honeypot`.
2. Point `deploy/splunk/inputs.conf` at `logs/events.jsonl` and install that input.
3. Install `deploy/splunk/props.conf`.

```spl
index=honeypot sourcetype=honeypot:json
| stats count by service, category

index=honeypot sourcetype=honeypot:json event_type=auth_attempt
| stats count by username, password, src_ip

index=honeypot sourcetype=honeypot:json category=egress_attempt
| stats count by indicator, command, src_ip
```

## ELK

This stack wants about 2 GB of free RAM. Kibana can take a minute to open.

```powershell
docker compose --profile elk up --build
```

Open Kibana at http://127.0.0.1:5601 and create a data view for `honeypot-*`.

```text
event_type: "auth_attempt"
category: "egress_attempt" and indicator: *
```

Filebeat reads `logs/events.jsonl`. If you only want the honeypot, skip this profile and use the dashboard.
