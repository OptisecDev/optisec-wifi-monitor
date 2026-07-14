"""Module 8 - Packet Injection Detector: passive detection of injected,
replayed, or malformed 802.11 frames.

Detection and reporting ONLY. This module observes and classifies frames
already present on the monitor interface - it never sends, injects, replays,
or crafts any 802.11 frame, and does not implement any part of an
injection/replay attack tool, even for internal testing.

It looks for three independent, passively-observable indicators:

  * Sequence-number anomalies - duplicate, out-of-order, or impossibly large
    jumps in the 12-bit 802.11 sequence-control counter from the same
    transmitter, which is the classic signature of a spoofed/injected or
    replayed frame (a legitimate NIC's sequence counter increments by one
    per new frame; injection tools frequently forge or desync it).
  * Malformed frame indicators - reserved frame-control type values,
    impossible DS-bit combinations for the declared frame type, and
    corrupt-looking Dot11Elt information-element chains (declared length
    not matching the bytes actually present), consistent with hand-crafted
    or corrupted frames rather than genuine NIC/driver output.
  * Replay patterns - the exact same frame content (by signature hash)
    appearing far more often, or without the 802.11 retry flag, more than
    normal link-layer retransmission behavior would produce.

Findings use the same alert/attack schema as AttackDetector, DeauthDetector,
RogueAPDetector and WPSDetector so they flow into the existing AI analysis
and PDF reporting pipeline unchanged.
"""

import hashlib
import threading
import time
from collections import defaultdict, deque
from datetime import datetime, timedelta

try:
    from scapy.all import sniff, Dot11, Dot11Elt
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False


DEFAULT_PACKET_INJECTION_CONFIG = {
    "enabled": True,
    "seq_jump_threshold": 1000,
    "seq_history_size": 20,
    "replay_count_threshold": 5,
    "replay_window_seconds": 10,
    "anomaly_window_seconds": 60,
    "eval_throttle_seconds": 5,
}

# 802.11 sequence-control field is a 12-bit counter (0-4095) packed into the
# top 12 bits of SC, with a 4-bit fragment number in the low bits.
SEQ_MODULUS = 4096

# Frame Control flag bits (scapy FCfield order): to_DS, from_DS, MF, retry,
# pw_mgt, MD, protected, order.
FC_TO_DS = 0x01
FC_FROM_DS = 0x02
FC_RETRY = 0x08


class PacketInjectionDetector:
    """Passive 802.11 packet injection / replay / malformed-frame detector.

    Tracks per-transmitter (addr2) sequence-number continuity and recent
    frame-content signatures, and inspects frame-control/element-chain
    consistency, to flag traffic consistent with injected or replayed
    frames (e.g. aireplay-ng, mdk4, scapy-based injection) independent of
    the deauth-burst-specific check in DeauthDetector.
    """

    def __init__(self, db, config, alert_mgr, monitor_iface: str):
        self.db = db
        self.config = config
        self.alert_mgr = alert_mgr
        self.monitor_iface = monitor_iface
        self._running = False

        # Per-source sequence tracking: {mac: {"last_seq": int, "history": deque}}
        self._seq_state: dict = {}
        # Per-source recent frame signatures: {mac: deque[(timestamp, sig, retry)]}
        self._signatures: dict = defaultdict(deque)
        # Per-source anomaly log for severity escalation: {mac: deque[(timestamp, anomaly_type)]}
        self._anomalies: dict = defaultdict(deque)
        self._lock = threading.Lock()

        # Cumulative anomaly counts by type this session, for TUI/status display.
        self._anomaly_counts: dict = defaultdict(int)

        # Per-source alert throttle, separate from the tracking state above -
        # sequence/replay continuity must be evaluated on every frame, but
        # alert emission is throttled to avoid flooding on a sustained attack.
        self._last_alert: dict = {}
        self._eval_lock = threading.Lock()

    @property
    def settings(self) -> dict:
        cfg = self.config.get("packet_injection_detection", {}) or {}
        merged = DEFAULT_PACKET_INJECTION_CONFIG.copy()
        merged.update(cfg)
        return merged

    def is_enabled(self) -> bool:
        return bool(self.settings.get("enabled", True))

    def start(self):
        self._running = True

        if not self.is_enabled():
            self.alert_mgr.info("SYSTEM", "Packet injection detector disabled via config - not starting")
            return

        if not SCAPY_AVAILABLE:
            self.alert_mgr.low("SYSTEM", "Scapy not available - packet injection detection limited")
            self._poll_fallback()
            return

        # Retry with backoff instead of giving up permanently on the first
        # sniff() failure - the monitor interface can disappear (unplugged
        # adapter, rfkill, airmon-ng restart) and come back mid-run.
        retry_delay = 5
        while self._running:
            try:
                sniff(
                    iface=self.monitor_iface,
                    prn=self._packet_handler,
                    store=False,
                    stop_filter=lambda _: not self._running,
                )
                retry_delay = 5
            except Exception as e:
                self.alert_mgr.low(
                    "SYSTEM",
                    f"Packet injection detector sniff error on {self.monitor_iface}: {e} - "
                    f"retrying in {retry_delay}s"
                )
            if not self._running:
                return
            time.sleep(retry_delay)
            retry_delay = min(retry_delay * 2, 60)

    def stop(self):
        self._running = False

    def _poll_fallback(self):
        """Minimal fallback when scapy is unavailable (permanent condition)."""
        while self._running:
            time.sleep(10)

    def _packet_handler(self, pkt):
        try:
            if pkt.haslayer(Dot11):
                self._handle_frame(pkt)
        except Exception as e:
            self.alert_mgr.low("SYSTEM", f"PacketInjectionDetector packet parse error ({type(e).__name__})")

    def _handle_frame(self, pkt):
        if not self.is_enabled():
            return

        dot11 = pkt[Dot11]
        # addr2 is the frame transmitter. Some malformed/reserved-type
        # frames leave it unset entirely, which is itself part of what
        # makes them worth flagging - fall back to a shared bucket rather
        # than silently dropping them, matching DeauthDetector's convention.
        source = dot11.addr2 or "unknown"

        findings = []

        malformed = self._detect_malformed(pkt, dot11)
        if malformed:
            findings.append(("malformed_frame", malformed))

        # Sequence numbers and retransmission behavior are only meaningful
        # for management/data frames - control frames (ACK/RTS/CTS/etc.)
        # carry no sequence-control field.
        if dot11.type in (0, 2):
            seq_anomaly = self._check_sequence(source, dot11)
            if seq_anomaly:
                findings.append(seq_anomaly)

            replay_anomaly = self._check_replay(source, pkt, dot11)
            if replay_anomaly:
                findings.append(replay_anomaly)

        if findings:
            self._record_and_maybe_alert(source, findings)

    # --- Malformed frame detection ---
    @staticmethod
    def _detect_malformed(pkt, dot11):
        ftype = dot11.type
        fc = int(dot11.FCfield)
        to_ds = bool(fc & FC_TO_DS)
        from_ds = bool(fc & FC_FROM_DS)

        if ftype == 3:
            return "reserved frame-control type value (type=3)"

        # Management frames are never relayed between DS segments - both
        # DS bits must be 0. Control frames (ACK/RTS/CTS/BlockAck/etc.)
        # likewise never carry DS routing.
        if ftype in (0, 1) and (to_ds or from_ds):
            frame_kind = "management" if ftype == 0 else "control"
            return (f"{frame_kind} frame with invalid DS bits "
                    f"(to_DS={to_ds}, from_DS={from_ds})")

        return PacketInjectionDetector._detect_malformed_elements(pkt)

    @staticmethod
    def _detect_malformed_elements(pkt):
        if not pkt.haslayer(Dot11Elt):
            return None

        elt = pkt.getlayer(Dot11Elt)
        while elt and isinstance(elt, Dot11Elt):
            try:
                declared = elt.len
                actual = len(elt.info)
                if declared is not None and declared != actual:
                    return (f"Dot11Elt ID={elt.ID} declared length {declared} "
                            f"!= actual {actual} bytes present")
            except Exception:
                return "corrupt Dot11Elt chain (parse error)"
            elt = elt.payload if isinstance(elt.payload, Dot11Elt) else None
        return None

    # --- Sequence-number anomaly detection ---
    @staticmethod
    def _seq_and_frag(dot11):
        sc = dot11.SC or 0
        seq = (sc >> 4) & 0x0FFF
        frag = sc & 0x0F
        return seq, frag

    def _check_sequence(self, source: str, dot11):
        settings = self.settings
        jump_threshold = settings.get("seq_jump_threshold", 1000)
        history_size = settings.get("seq_history_size", 20)

        seq, frag = self._seq_and_frag(dot11)
        retry = bool(int(dot11.FCfield) & FC_RETRY)

        anomaly = None
        with self._lock:
            state = self._seq_state.get(source)
            if state is None:
                self._seq_state[source] = {
                    "last_seq": seq,
                    "history": deque([seq], maxlen=history_size),
                }
                return None

            last_seq = state["last_seq"]
            history = state["history"]

            if seq == last_seq and frag == 0 and not retry:
                anomaly = ("duplicate_seq",
                           f"duplicate sequence number {seq} from {source} without retry flag set")
            elif frag == 0 and seq != last_seq and seq in history and not retry:
                behind = (last_seq - seq) % SEQ_MODULUS
                anomaly = ("out_of_order_seq",
                           f"sequence number {seq} repeats a recently-seen value from {source} "
                           f"({behind} behind current, out of order)")
            elif frag == 0:
                forward_jump = (seq - last_seq) % SEQ_MODULUS
                if forward_jump > jump_threshold:
                    anomaly = ("seq_jump",
                               f"sequence number jumped from {last_seq} to {seq} for {source} "
                               f"({forward_jump} in a single step)")

            state["last_seq"] = seq
            history.append(seq)

        return anomaly

    # --- Replay pattern detection ---
    @staticmethod
    def _frame_signature(pkt):
        try:
            raw = bytes(pkt[Dot11])
        except Exception:
            return None
        return hashlib.sha1(raw).hexdigest()

    def _check_replay(self, source: str, pkt, dot11):
        settings = self.settings
        replay_threshold = settings.get("replay_count_threshold", 5)
        window_seconds = settings.get("replay_window_seconds", 10)
        window = timedelta(seconds=window_seconds)

        sig = self._frame_signature(pkt)
        if sig is None:
            return None

        retry = bool(int(dot11.FCfield) & FC_RETRY)
        now = datetime.now()

        with self._lock:
            log = self._signatures[source]
            log.append((now, sig, retry))
            while log and (now - log[0][0]) > window:
                log.popleft()

            matches = [entry for entry in log if entry[1] == sig]
            non_retry_matches = [entry for entry in matches if not entry[2]]

        # Legitimate 802.11 retransmissions repeat identical content but
        # carry the retry flag, and stop after a small retry ceiling.
        # Identical content without that flag, or far more repeats than any
        # normal retry ceiling, indicates replayed/injected traffic rather
        # than link-layer retransmission.
        if len(non_retry_matches) >= replay_threshold or len(matches) >= replay_threshold * 2:
            return ("replay_pattern",
                    f"identical frame signature {sig[:12]} from {source} seen "
                    f"{len(matches)} times in {window_seconds}s "
                    f"({len(non_retry_matches)} without retry flag)")
        return None

    # --- Aggregation, severity escalation and alerting ---
    def _should_alert(self, source: str) -> bool:
        throttle = timedelta(seconds=self.settings.get("eval_throttle_seconds", 5))
        now = datetime.now()
        with self._eval_lock:
            last = self._last_alert.get(source)
            if last and (now - last) < throttle:
                return False
            self._last_alert[source] = now
        return True

    def _record_and_maybe_alert(self, source: str, findings: list):
        settings = self.settings
        window = timedelta(seconds=settings.get("anomaly_window_seconds", 60))
        now = datetime.now()

        with self._lock:
            log = self._anomalies[source]
            for anomaly_type, _ in findings:
                log.append((now, anomaly_type))
                self._anomaly_counts[anomaly_type] += 1
            while log and (now - log[0][0]) > window:
                log.popleft()
            total_count = len(log)
            distinct_types = len({t for _, t in log})

        if not self._should_alert(source):
            return

        # Escalate on either breadth (distinct anomaly types from the same
        # source - a more sophisticated/varied attack) or raw frequency
        # (a sustained one-technique flood), matching the burst-severity
        # style used by DeauthDetector.
        if distinct_types >= 3 or total_count >= 10:
            severity = "CRITICAL"
        elif distinct_types >= 2 or total_count >= 5:
            severity = "HIGH"
        else:
            severity = "MEDIUM"

        reasons = "; ".join(f"{t}: {d}" for t, d in findings)
        msg = f"Packet injection indicators detected from {source}"
        details = (
            f"Source MAC: {source} | Anomaly types this event: "
            f"{[t for t, _ in findings]} | Distinct anomaly types in "
            f"{settings.get('anomaly_window_seconds', 60)}s window: {distinct_types} | "
            f"Total anomalies in window: {total_count} | Detail: {reasons}"
        )

        self.alert_mgr.add("PACKET_INJECTION", severity, msg, details)
        self.db.add_attack("PACKET_INJECTION", severity, source_mac=source, details=details)

    def get_stats(self) -> dict:
        with self._lock:
            tracked_sources = len(self._seq_state)
            anomaly_counts = dict(self._anomaly_counts)
        return {
            "tracked_sources": tracked_sources,
            "anomaly_counts": anomaly_counts,
            "total_anomalies": sum(anomaly_counts.values()),
            "scapy_available": SCAPY_AVAILABLE,
            "enabled": self.is_enabled(),
        }
