"""
Stream processor: captures live packets, extracts UNSW-NB15-compatible flow
features, scales them, and submits 10-flow sequences for inference.
"""

import time
import threading
import pickle
import numpy as np
from collections import deque, Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional, Callable, NamedTuple

try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

ROOT = Path(__file__).parent.parent
DATA_DIR = ROOT / "data" / "processed" / "unsw-nb15"

# UNSW-NB15 port → service mapping (matches training data encoding)
PORT_SERVICE = {
    20: "ftp-data", 21: "ftp", 22: "ssh", 23: "telnet",
    25: "smtp", 53: "dns", 67: "dhcp", 68: "dhcp",
    80: "http", 110: "pop3", 143: "imap", 161: "snmp",
    443: "ssl", 6667: "irc", 8080: "http", 8000: "http",
}

# Feature order must match metadata.json exactly (44 features)
FEATURE_NAMES = [
    "id", "dur", "proto", "service", "state",
    "spkts", "dpkts", "sbytes", "dbytes", "rate",
    "sttl", "dttl", "sload", "dload", "sloss", "dloss",
    "sinpkt", "dinpkt", "sjit", "djit",
    "swin", "stcpb", "dtcpb", "dwin",
    "tcprtt", "synack", "ackdat",
    "smean", "dmean", "trans_depth", "response_body_len",
    "ct_srv_src", "ct_state_ttl", "ct_dst_ltm",
    "ct_src_dport_ltm", "ct_dst_sport_ltm", "ct_dst_src_ltm",
    "is_ftp_login", "ct_ftp_cmd", "ct_flw_http_mthd",
    "ct_src_ltm", "ct_srv_dst", "is_sm_ips_ports",
    "attack_cat",  # 0 at inference — we don't know yet
]


class FlowKey(NamedTuple):
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    proto: str


@dataclass
class FlowRecord:
    key: FlowKey
    start_time: float
    src_pkts: list = field(default_factory=list)   # [(timestamp, size)]
    dst_pkts: list = field(default_factory=list)
    src_ttl: int = 64
    dst_ttl: int = 64
    src_win: int = 0
    dst_win: int = 0
    src_tcp_seq: int = 0
    dst_tcp_seq: int = 0
    syn_time: float = 0.0
    synack_time: float = 0.0
    ack_time: float = 0.0
    state: str = "INT"
    ftp_cmds: int = 0
    http_methods: int = 0
    trans_depth: int = 0
    response_body_len: int = 0
    last_seen: float = field(default_factory=time.time)
    closed: bool = False


class FlowTracker:
    """Tracks active network flows and emits feature vectors on completion."""

    FLOW_TIMEOUT = 5.0  # seconds of inactivity before forced close

    def __init__(self, encoders: dict, scaler, on_flow_complete: Callable):
        self.encoders = encoders
        self.scaler = scaler
        self.on_flow_complete = on_flow_complete

        self.active: dict = {}
        self.recent_raw: deque = deque(maxlen=100)  # last 100 completed flows (raw dicts)
        self.flow_id = 0
        self._lock = threading.Lock()

        t = threading.Thread(target=self._reaper, daemon=True)
        t.start()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def process_packet(self, pkt) -> None:
        if not pkt.haslayer(IP):
            return

        key, is_fwd = self._classify(pkt)
        if key is None:
            return

        now = time.time()
        size = len(pkt)

        with self._lock:
            if key not in self.active:
                flow = FlowRecord(key=key, start_time=now, last_seen=now)
                self.active[key] = flow
                if pkt.haslayer(IP):
                    flow.src_ttl = pkt[IP].ttl
            else:
                flow = self.active[key]

            flow.last_seen = now

            if is_fwd:
                flow.src_pkts.append((now, size))
            else:
                flow.dst_pkts.append((now, size))
                if pkt.haslayer(IP):
                    flow.dst_ttl = pkt[IP].ttl

            self._update_tcp(flow, pkt, is_fwd)
            should_close = flow.closed

        if should_close:
            self._close(key)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _classify(self, pkt):
        """Return (FlowKey, is_forward) or (None, None)."""
        ip = pkt[IP]
        proto_num = ip.proto

        if proto_num == 6 and pkt.haslayer(TCP):
            tcp = pkt[TCP]
            proto, sport, dport = "tcp", tcp.sport, tcp.dport
        elif proto_num == 17 and pkt.haslayer(UDP):
            udp = pkt[UDP]
            proto, sport, dport = "udp", udp.sport, udp.dport
        elif proto_num == 1:
            proto, sport, dport = "icmp", 0, 0
        else:
            proto, sport, dport = str(proto_num), 0, 0

        fwd = FlowKey(ip.src, ip.dst, sport, dport, proto)
        rev = FlowKey(ip.dst, ip.src, dport, sport, proto)

        with self._lock:
            if fwd in self.active:
                return fwd, True
            if rev in self.active:
                return rev, False
            return fwd, True  # new flow

    def _update_tcp(self, flow: FlowRecord, pkt, is_fwd: bool) -> None:
        if not pkt.haslayer(TCP):
            return

        tcp = pkt[TCP]
        f = tcp.flags
        now = time.time()

        if is_fwd:
            flow.src_win = tcp.window
            if (f & 0x02) and not (f & 0x10):  # SYN (not SYN-ACK)
                flow.syn_time = now
                flow.src_tcp_seq = tcp.seq
        else:
            flow.dst_win = tcp.window
            flow.dst_tcp_seq = tcp.seq
            if f & 0x12:  # SYN-ACK
                flow.synack_time = now
            elif (f & 0x10) and flow.synack_time and not flow.ack_time:
                flow.ack_time = now

        # State machine
        if f & 0x04:   # RST
            flow.state = "RST"
            flow.closed = True
        elif f & 0x01:  # FIN
            flow.state = "FIN"
            flow.closed = True
        elif f & 0x12:  # SYN-ACK
            flow.state = "CON"

        # FTP payload inspection
        k = flow.key
        if (k.dst_port == 21 or k.src_port == 21) and pkt.haslayer(Raw):
            try:
                payload = bytes(pkt[Raw]).decode("ascii", errors="ignore").upper()
                if any(c in payload for c in ("USER ", "PASS ", "RETR ", "STOR ")):
                    flow.ftp_cmds += 1
            except Exception:
                pass

        # HTTP payload inspection (covers default FastAPI dev port 8000 too)
        if k.dst_port in (80, 8080, 8000) and pkt.haslayer(Raw):
            try:
                payload = bytes(pkt[Raw]).decode("ascii", errors="ignore")
                if any(m in payload for m in ("GET ", "POST ", "PUT ", "DELETE ", "HEAD ")):
                    flow.http_methods += 1
                    flow.trans_depth += 1
                if "Content-Length:" in payload:
                    cl = int(payload.split("Content-Length:")[1].split("\r\n")[0].strip())
                    flow.response_body_len += cl
            except Exception:
                pass

    def _close(self, key: FlowKey) -> None:
        with self._lock:
            flow = self.active.pop(key, None)
        if flow is None:
            return

        raw, feat = self._build_features(flow)
        if feat is None:
            return

        # Store raw dict for ct_* counts on future flows
        with self._lock:
            self.recent_raw.append(raw)

        self.on_flow_complete(feat, raw)

    def _reaper(self) -> None:
        while True:
            time.sleep(0.5)
            now = time.time()
            to_close = []
            with self._lock:
                for key, flow in list(self.active.items()):
                    if now - flow.last_seen > self.FLOW_TIMEOUT:
                        to_close.append(key)
            for key in to_close:
                self._close(key)

    def _safe_encode(self, name: str, value: str) -> int:
        enc = self.encoders.get(name)
        if enc is None:
            return 0
        try:
            return int(enc.transform([value])[0])
        except Exception:
            # Unseen label → use 0 (most common class)
            return 0

    def _build_features(self, flow: FlowRecord):
        """Return (raw_dict, scaled_np_array) or (None, None)."""
        sp, dp = flow.src_pkts, flow.dst_pkts
        if not sp:
            return None, None

        now = flow.last_seen
        dur = max(now - flow.start_time, 1e-9)

        spkts = len(sp)
        dpkts = len(dp)
        sbytes = sum(s for _, s in sp)
        dbytes = sum(s for _, s in dp)
        rate = (spkts + dpkts) / dur
        sload = (sbytes * 8) / dur
        dload = (dbytes * 8) / dur

        s_ts = [t for t, _ in sp]
        d_ts = [t for t, _ in dp]
        sinpkt = float(np.mean(np.diff(s_ts)) * 1000) if len(s_ts) > 1 else 0.0
        dinpkt = float(np.mean(np.diff(d_ts)) * 1000) if len(d_ts) > 1 else 0.0
        sjit = float(np.std(np.diff(s_ts)) * 1000) if len(s_ts) > 2 else 0.0
        djit = float(np.std(np.diff(d_ts)) * 1000) if len(d_ts) > 2 else 0.0

        smean = sbytes / spkts if spkts else 0
        dmean = dbytes / dpkts if dpkts else 0

        synack_dur = (flow.synack_time - flow.syn_time) if (flow.syn_time and flow.synack_time) else 0.0
        ackdat_dur = (flow.ack_time - flow.synack_time) if (flow.synack_time and flow.ack_time) else 0.0
        tcprtt = synack_dur + ackdat_dur

        service = PORT_SERVICE.get(flow.key.dst_port, PORT_SERVICE.get(flow.key.src_port, "-"))

        # Refine state
        state = flow.state
        if state == "INT" and dpkts == 0:
            state = "REQ"

        proto_enc = self._safe_encode("proto", flow.key.proto)
        service_enc = self._safe_encode("service", service)
        state_enc = self._safe_encode("state", state)

        # Sliding-window counts (over last 100 flows, before appending current)
        with self._lock:
            recent = list(self.recent_raw)

        def ct(cond):
            return sum(1 for r in recent if cond(r))

        ct_srv_src = ct(lambda r: r["service_enc"] == service_enc and r["src_ip"] == flow.key.src_ip)
        ct_state_ttl = ct(lambda r: r["state_enc"] == state_enc and r["sttl"] == flow.src_ttl)
        ct_dst_ltm = ct(lambda r: r["dst_ip"] == flow.key.dst_ip)
        ct_src_dport_ltm = ct(lambda r: r["src_ip"] == flow.key.src_ip and r["dst_port"] == flow.key.dst_port)
        ct_dst_sport_ltm = ct(lambda r: r["dst_ip"] == flow.key.dst_ip and r["src_port"] == flow.key.src_port)
        ct_dst_src_ltm = ct(lambda r: r["dst_ip"] == flow.key.dst_ip and r["src_ip"] == flow.key.src_ip)
        ct_src_ltm = ct(lambda r: r["src_ip"] == flow.key.src_ip)
        ct_srv_dst = ct(lambda r: r["service_enc"] == service_enc and r["dst_ip"] == flow.key.dst_ip)

        is_ftp_login = 1 if flow.key.dst_port == 21 and flow.ftp_cmds > 0 else 0
        is_sm_ips_ports = 1 if (flow.key.src_ip == flow.key.dst_ip and flow.key.src_port == flow.key.dst_port) else 0

        with self._lock:
            self.flow_id += 1
            fid = self.flow_id

        raw = {
            "src_ip": flow.key.src_ip,
            "dst_ip": flow.key.dst_ip,
            "src_port": flow.key.src_port,
            "dst_port": flow.key.dst_port,
            "proto": flow.key.proto,
            "service": service,
            "service_enc": service_enc,
            "state": state,
            "state_enc": state_enc,
            "sttl": flow.src_ttl,
            "dur": dur,
            "rate": rate,
            "spkts": spkts,
            "dpkts": dpkts,
            "sbytes": sbytes,
            "dbytes": dbytes,
            "smean": smean,
            "dmean": dmean,
            "http_methods": flow.http_methods,
        }

        vec = np.array([
            fid, dur, proto_enc, service_enc, state_enc,
            spkts, dpkts, sbytes, dbytes, rate,
            flow.src_ttl, flow.dst_ttl,
            sload, dload, 0, 0,          # sloss/dloss = 0 (not tracked)
            sinpkt, dinpkt, sjit, djit,
            flow.src_win, flow.src_tcp_seq, flow.dst_tcp_seq, flow.dst_win,
            tcprtt, synack_dur, ackdat_dur,
            smean, dmean, flow.trans_depth, flow.response_body_len,
            ct_srv_src, ct_state_ttl, ct_dst_ltm,
            ct_src_dport_ltm, ct_dst_sport_ltm, ct_dst_src_ltm,
            is_ftp_login, flow.ftp_cmds, flow.http_methods,
            ct_src_ltm, ct_srv_dst, is_sm_ips_ports,
            0,  # attack_cat unknown at inference
        ], dtype=np.float64).reshape(1, -1)

        try:
            scaled = self.scaler.transform(vec)[0].astype(np.float32)
        except Exception:
            return None, None

        return raw, scaled


class StreamProcessor:
    """Glues FlowTracker → sequence building → inference callback."""

    SEQ_LEN = 10

    def __init__(self, on_prediction: Callable, iface: Optional[str] = None):
        self.on_prediction = on_prediction
        self.iface = iface
        self.seq_window: deque = deque(maxlen=self.SEQ_LEN)
        self.seq_raws: deque = deque(maxlen=self.SEQ_LEN)

        with open(DATA_DIR / "scaler.pkl", "rb") as f:
            scaler = pickle.load(f)
        with open(DATA_DIR / "encoders.pkl", "rb") as f:
            encoders = pickle.load(f)

        self.tracker = FlowTracker(
            encoders=encoders,
            scaler=scaler,
            on_flow_complete=self._on_flow,
        )

    def start(self) -> None:
        """Start sniffing in the current thread (blocking). Call from a daemon thread."""
        if not SCAPY_AVAILABLE:
            raise RuntimeError("scapy not installed")

        # Exclude Docker's internal DNS resolver (127.0.0.11) — it generates constant
        # background noise that looks like probing to the model.
        BPF = "ip and not host 127.0.0.11"
        iface = self.iface
        print(f"[StreamProcessor] Sniffing on {iface or 'eth0'} | filter: {BPF!r}")
        sniff(
            iface=iface or "eth0",
            prn=self.tracker.process_packet,
            store=False,
            filter=BPF,
        )

    def _on_flow(self, scaled_vec: np.ndarray, raw: dict) -> None:
        self.seq_window.append(scaled_vec)
        self.seq_raws.append(raw)

        if len(self.seq_window) == self.SEQ_LEN:
            sequence = np.stack(list(self.seq_window))   # (10, 44)
            raws = list(self.seq_raws)
            self.on_prediction(sequence, raws)

    @staticmethod
    def heuristic_attack_type(raws: list) -> str:
        """
        Map a 10-flow window to one of the UNSW-NB15 attack categories.

        Design rules to avoid false positives on normal Docker bridge traffic:
          - Every category requires a *source-concentration* check where applicable:
            ≥7/10 flows from the same IP = deliberate single-source activity.
          - "Exploits" now requires specific service ports + meaningful payload;
            it no longer fires on generic established connections.
          - "Reconnaissance" now requires tight nmap-like flow signatures:
            8+ unique dst ports, mostly unanswered, tiny flows (≤3 pkts each).
          - DoS flood ratio tightened to <10 % response (was 15 %).
        """
        if not raws:
            return "Generic"

        n = len(raws)

        # ── Raw lists ──────────────────────────────────────────────────────────
        rates    = [r.get("rate",    0.0) for r in raws]
        spkts_l  = [r.get("spkts",  0)   for r in raws]
        dpkts_l  = [r.get("dpkts",  0)   for r in raws]
        smeans   = [r.get("smean",  0.0) for r in raws]
        dur_l    = [r.get("dur",    0.0) for r in raws]
        sbytes_l = [r.get("sbytes", 0)   for r in raws]
        dbytes_l = [r.get("dbytes", 0)   for r in raws]

        avg_rate   = sum(rates)    / n
        max_rate   = max(rates)
        avg_spkts  = sum(spkts_l)  / n
        avg_dpkts  = sum(dpkts_l)  / n
        avg_smean  = sum(smeans)   / n
        avg_dur    = sum(dur_l)    / n
        avg_sbytes = sum(sbytes_l) / n
        avg_dbytes = sum(dbytes_l) / n

        dst_ports = [r.get("dst_port", 0)  for r in raws]
        dst_ips   = [r.get("dst_ip",   "") for r in raws]
        src_ips   = [r.get("src_ip",   "") for r in raws]
        services  = [r.get("service",  "-")for r in raws]
        states    = [r.get("state",    "") for r in raws]

        unique_dst_ports = len(set(dst_ports))
        unique_dst_ips   = len(set(dst_ips))

        unanswered  = sum(1 for s in states if s in ("RST", "REQ", "INT"))
        established = sum(1 for s in states if s in ("CON", "FIN"))

        # Source concentration: is ≥70 % of this window from one attacker IP?
        src_counter   = Counter(src_ips)
        top_src_count = src_counter.most_common(1)[0][1]
        src_concentrated = top_src_count >= 7

        ssh_flows  = sum(1 for r in raws if r.get("dst_port") == 22)
        ftp_flows  = sum(1 for r in raws if r.get("dst_port") in (20, 21))
        http_flows = sum(1 for s in services if s == "http")
        http_hits  = sum(r.get("http_methods", 0) for r in raws)

        # ── 1. Brute Force (SSH) ───────────────────────────────────────────────
        # Many short SSH connection attempts from the same source.
        if ssh_flows >= 5 and src_concentrated:
            return "Brute Force (SSH)"

        # ── 2. Backdoor ────────────────────────────────────────────────────────
        # Repeated FTP auth from same source, OR long bidirectional tunnel.
        if ftp_flows >= 5 and src_concentrated:
            return "Backdoor"
        if (avg_dur > 30
                and avg_dbytes > avg_sbytes * 0.5
                and established >= 6
                and avg_smean > 200
                and src_concentrated):
            return "Backdoor"

        # ── 3. Reconnaissance ─────────────────────────────────────────────────
        # Classic nmap signature: single source, many distinct ports, tiny flows,
        # mostly unanswered.
        avg_total_pkts = (sum(spkts_l) + sum(dpkts_l)) / n
        is_scan = (
            src_concentrated            # deliberate single-source sweep
            and unique_dst_ports >= 6   # scanning many ports (lowered: nmap -T4 fills window fast)
            and unanswered >= 5         # most probes unanswered
            and avg_total_pkts <= 5     # tiny probe flows (allows for retransmits)
            and avg_dpkts < 2.0         # little to no reply
        )
        if is_scan:
            return "Reconnaissance"
        # Fallback: extreme port diversity regardless of source (distributed scan)
        if unique_dst_ports >= 12 and unanswered >= 7:
            return "Reconnaissance"

        # ── 4. Fuzzers ─────────────────────────────────────────────────────────
        # HTTP fuzzing: many requests with varied paths/methods from one source.
        # http_hits counts packets with detected HTTP method verbs per flow.
        if http_flows >= 6 and http_hits >= 5 and src_concentrated:
            return "Fuzzers"
        if http_hits >= 8:                  # very dense HTTP method activity
            return "Fuzzers"

        # ── 5. DoS ─────────────────────────────────────────────────────────────
        # Flood ratio: victim replies < 10 % of attacker packets.
        is_flood = avg_dpkts < avg_spkts * 0.10
        if avg_rate > 1000 and is_flood:
            return "DoS"
        if max_rate > 3000 and is_flood:
            return "DoS"

        # SYN flood: all flows target the same port, nearly all unanswered,
        # ≤2 packets per flow (hping3 --flood pattern).
        port_concentration = Counter(dst_ports).most_common(1)[0][1] / n
        if (port_concentration >= 0.8
                and unanswered >= 8
                and avg_total_pkts <= 2
                and avg_spkts <= 1.5):
            return "DoS"

        # ── 6. Worms ───────────────────────────────────────────────────────────
        # Same attack replicated across many destination IPs.
        if unique_dst_ips >= 7 and src_concentrated:
            return "Worms"

        # ── 7. Shellcode ───────────────────────────────────────────────────────
        # Large payload in established connections — data exfil / shellcode delivery.
        if (avg_smean > 600
                and established >= 5
                and src_concentrated
                and avg_sbytes > 3000):
            return "Shellcode"

        # ── 8. Exploits ────────────────────────────────────────────────────────
        # Successful connections to known service ports WITH meaningful payload.
        # NOT triggered by generic TCP sessions (e.g. dashboard polling).
        EXPLOIT_PORTS = {
            21, 22, 23, 25, 53, 80, 110, 111,
            135, 137, 139, 143, 443, 445,
            1433, 3306, 5432, 8080, 8443,
        }
        exploit_flows = sum(
            1 for r in raws
            if r.get("state") in ("CON", "FIN")
            and r.get("dst_port", 0) in EXPLOIT_PORTS
            and r.get("smean", 0) > 150     # non-trivial payload
            and r.get("sbytes", 0) > 300
        )
        if exploit_flows >= 5 and src_concentrated:
            return "Exploits"

        # ── 9. Analysis ────────────────────────────────────────────────────────
        # Moderate-rate bidirectional probing that doesn't fit above categories.
        if avg_rate > 500 and avg_dpkts > avg_spkts * 0.3 and not is_flood:
            return "Analysis"

        return "Generic"
