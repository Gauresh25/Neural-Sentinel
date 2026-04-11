"""
Stream processor: captures live packets, extracts UNSW-NB15-compatible flow
features, scales them, and submits 10-flow sequences for inference.
"""

import time
import threading
import pickle
import numpy as np
from collections import deque
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
    443: "ssl", 6667: "irc", 8080: "http",
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

        # HTTP payload inspection
        if k.dst_port in (80, 8080) and pkt.haslayer(Raw):
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
            "state_enc": state_enc,
            "sttl": flow.src_ttl,
            "rate": rate,
            "spkts": spkts,
            "dpkts": dpkts,
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

        print(f"[StreamProcessor] Sniffing on {'all interfaces' if not self.iface else self.iface}")
        sniff(
            iface=self.iface,
            prn=self.tracker.process_packet,
            store=False,
            filter="ip",
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
        """Best-guess attack category from raw flow features (for display)."""
        rates = [r.get("rate", 0) for r in raws]
        avg_rate = sum(rates) / len(rates) if rates else 0

        dst_ports = {r.get("dst_port", 0) for r in raws}
        http_hits = sum(r.get("http_methods", 0) for r in raws)

        if avg_rate > 500:
            return "DoS"
        if len(dst_ports) > 5:
            return "Reconnaissance"
        if http_hits > 3:
            return "Fuzzer"
        return "Generic/Exploit"
