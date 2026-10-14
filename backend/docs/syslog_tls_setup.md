# Syslog over TLS — sender setup (task 6.2)

Configures the Kali sandbox to forward logs to the ThreatSense collector over
TLS on TCP 6514 instead of plaintext UDP 1514.

**Requirement (Proposal Section 3, Table 11, NFR-04, in part):**

> All web application, API, and external-service traffic must be encrypted using
> TLS 1.2 or higher. Syslog over TLS on TCP port 6514 must be used where
> supported. Standard Syslog ports 514 and 1514 may be used only within the
> isolated testing environment.

**Measurement (verbatim, in part):** *"verification of Syslog-over-TLS
configuration where enabled"* — this document plus the listener's start-up and
per-connection log lines are that verification.

---

## Before you start

The UDP 1514 path from Phase 5 keeps working throughout. Nothing here removes
it, and the requirement explicitly permits it inside the isolated test
environment. If TLS misbehaves, switching back is one config file away.

---

## Step 1 — Generate the collector's certificate (Mac)

```bash
cd ~/threatsense/backend
./scripts/generate_dev_cert.sh
```

Creates `certs/threatsense.crt` and `certs/threatsense.key`. The SANs include
`192.168.64.1`, the Mac's address on the UTM bridge, which is what the sender
will dial.

Confirm `certs/` is ignored by git before you commit anything:

```bash
git check-ignore -v backend/certs/threatsense.key
```

That must print a matching `.gitignore` rule. **A private key pushed to GitHub
cannot be un-published** — it stays in the history even after deletion.

## Step 2 — Start the collector (Mac)

```bash
cd ~/threatsense/backend && source .venv/bin/activate
python -m app.services.ingestion.listener
```

Expected:

```
Syslog listener starting (flush: 5s / 500 records)
  UDP  0.0.0.0:1514   testing only (NFR-04 permits 514/1514 in the isolated test environment)
  TLS  0.0.0.0:6514   RFC 5425 syslog-over-TLS (min=TLSv1_2, auth=server-only)
```

> **EVIDENCE** — screenshot this block. It states the port and the TLS floor.

If it exits with a `TLSConfigError`, the certificate is missing — go back to
step 1. The listener refuses to start rather than falling back to plaintext,
because a collector that silently downgrades would make the NFR-04 evidence
untrue.

## Step 3 — Copy the certificate to Kali

**The certificate only. Never the key.**

```bash
scp ~/threatsense/backend/certs/threatsense.crt kali@192.168.64.2:~/
```

On Kali:

```bash
sudo mkdir -p /etc/rsyslog.d/certs
sudo mv ~/threatsense.crt /etc/rsyslog.d/certs/
sudo chmod 644 /etc/rsyslog.d/certs/threatsense.crt
```

## Step 4 — Install the rsyslog TLS driver (Kali)

```bash
sudo apt update
sudo apt install -y rsyslog-gnutls
```

Without this package rsyslog silently ignores `StreamDriver="gtls"` and sends
plaintext, or refuses to start. Check it landed:

```bash
dpkg -l rsyslog-gnutls | tail -1
```

## Step 5 — Configure forwarding (Kali)

Replace the Phase 5 config:

```bash
sudo nano /etc/rsyslog.d/90-threatsense.conf
```

```rsyslog
# ThreatSense forwarding — TLS on 6514 (task 6.2, NFR-04)

# Rate limiting off: the kernel emits bursts during an nmap or hping3 run and
# rsyslog's default limiter would silently discard most of them. This is the
# setting that finally made Phase 5 work.
$SystemLogRateLimitInterval 0
$SystemLogRateLimitBurst 0

# --- TLS ---------------------------------------------------------------
# The collector's self-signed certificate. anon mode means the sender does
# not present a certificate of its own; the collector is not configured to
# ask for one (RFC 5425 s4.2.1 mutual auth is out of scope for the MVP).
global(
  DefaultNetstreamDriver="gtls"
  DefaultNetstreamDriverCAFile="/etc/rsyslog.d/certs/threatsense.crt"
)

*.* action(
  type="omfwd"
  target="192.168.64.1"
  port="6514"
  protocol="tcp"
  StreamDriver="gtls"
  StreamDriverMode="1"
  StreamDriverAuthMode="anon"
  TCP_Framing="octet-counted"
  RebindInterval="0"
)
```

Two settings that matter more than they look:

`TCP_Framing="octet-counted"` — RFC 5425 s4.3.1 mandates octet-counting for
Syslog-over-TLS. rsyslog's default over TCP is LF-delimited, which cannot
represent a message containing a newline. The collector accepts both (and
logs which it saw), but octet-counted is the correct one.

`StreamDriverAuthMode="anon"` — the sender encrypts but does not verify the
collector's identity, because a self-signed certificate has no CA to vouch
for it. Encryption in transit, no server authentication. Say so in the
write-up rather than implying otherwise.

## Step 6 — Restart and verify (Kali)

```bash
sudo rsyslogd -N1                 # config syntax check; fix any error first
sudo systemctl restart rsyslog
systemctl is-active rsyslog
```

Re-add the iptables LOG rule if the VM has rebooted — it does not persist:

```bash
sudo iptables -L OUTPUT -n -v | head -3
sudo iptables -A OUTPUT -p tcp -d 192.168.64.1 -j LOG --log-level 4
```

Scoping it with `-p tcp -d 192.168.64.1` captures attack traffic without the
background VM chatter that made an earlier nmap run classify as DDOS.

Make it survive the next reboot:

```bash
sudo apt install -y iptables-persistent
sudo netfilter-persistent save
```

## Step 7 — Prove it end to end

On Kali:

```bash
logger "ThreatSense TLS test message"
sudo nmap -sS -p 1-1000 192.168.64.1
```

On the Mac, the listener should show:

```
TLS connection from 192.168.64.2 (TLSv1.3, TLS_AES_256_GCM_SHA384)
flushed N records (batch ...)
```

> **EVIDENCE** — screenshot the `TLS connection from …` line. It names the
> negotiated protocol version, which is the direct evidence for "TLS 1.2 or
> higher".

Confirm the rows landed:

```bash
docker exec -it threatsense-db psql -U threatsense -d threatsense -P pager=off -c "SELECT COUNT(*), MAX(ingested_at) FROM network_logs WHERE ingested_at >= CURRENT_DATE;"
```

---

## If nothing arrives

Work down this list; each step rules out one layer.

**Is the collector reachable at all?**

```bash
nc -zv 192.168.64.1 6514
```

**Does the TLS handshake succeed?**

```bash
openssl s_client -connect 192.168.64.1:6514 -CAfile /etc/rsyslog.d/certs/threatsense.crt
```

Look for `Protocol : TLSv1.3` and `Verify return code: 0`. A verification
failure here means the certificate on Kali does not match the one the
collector is serving — regenerate and re-copy.

**Is rsyslog complaining?**

```bash
sudo journalctl -u rsyslog -n 40 --no-pager
```

`could not load module 'lmnsd_gtls'` means step 4 was skipped.

**Are messages arriving but being discarded?**

Check the collector's log for:

```
DROPPED n message(s) from unregistered sender(s): 192.168.64.2
```

That means `192.168.64.2` is not in `data_sources.ip_address`. The collector
resolves every message against that table and discards what it cannot match.
Before task 6.2 this happened silently — it cost two full NFR-01 runs during
6.1 before the cause was found, which is why the warning now exists.

```bash
docker exec -it threatsense-db psql -U threatsense -d threatsense -c "SELECT name, ip_address, transport FROM data_sources;"
```

Update the sandbox row to reflect the new transport:

```bash
docker exec -it threatsense-db psql -U threatsense -d threatsense -c "UPDATE data_sources SET transport = 'TLS', port = 6514 WHERE name = 'kali-sandbox';"
```

---

## Reverting to UDP

The Phase 5 path is unchanged and still listening. Restore the old config:

```rsyslog
*.* action(type="omfwd" target="192.168.64.1" port="1514" protocol="udp")
```

then `sudo systemctl restart rsyslog`. Useful for isolating whether a fault is
TLS-related or upstream of it.
