"""Firmware C++ extraction benchmark: hand-annotated truth, read from source.

Covers what the Python truth cannot: free `static` functions, ISRs,
header/source split (declarations must NOT emit), function templates,
forward declarations, `struct` with body in headers. `enum class`
(`TripReason`) is deliberately absent: the extractor has no ENUM mapping,
a known gap documented below, not a scored miss.

Annotator had not read `extractor.py` beyond its documented type mapping;
assignments follow C++ structure, not extractor internals.
Reproduce: `python benchmarks/score_cpp.py` (needs the staged copy at
TARGET).
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from verifyci.contracts.entity import EntityType
from verifyci.ingestion.extractor import extract_entities
from verifyci.ingestion.parser import TreeSitterParser

TARGET = Path(r"C:\Users\satya\AppData\Local\Temp\opencode\sem-target"
              r"\firmware\ra4m1\src")
F = EntityType.FUNCTION
M = EntityType.METHOD
C = EntityType.CLASS

GROUND_TRUTH = {
    "uart_bridge.cpp": [
        ("crc16_ibm", F), ("prv_arm_dtc_tx", F), ("prv_arm_dtc_rx", F),
        ("prv_rx_available", F),
        ("sci9_tei_isr", F), ("sci9_rxi_dtc_complete_isr", F),
        ("bridge_init", F), ("bridge_send_frame", F),
        ("bridge_send_heartbeat", F), ("bridge_send_telemetry", F),
        ("bridge_send_waveform", F), ("bridge_update", F),
        ("prv_test_frame_roundtrip", F), ("prv_test_crc_corruption_resync", F),
        ("bridge_run_self_tests", F),
    ],
    "uart_bridge.h": [("BridgeMetrics", C)],
    "relay.cpp": [
        ("_set", F), ("relay_init", F), ("relay_set_phase", F),
        ("relay_is_pending", F), ("relay_apply_pending_zero_cross", F),
        ("relay_set_all", F), ("relay_is_on", F), ("relay_any_on", F),
        ("relay_is_locked_out", F), ("relay_get_reason", F),
        ("trip_reason_priority", F), ("relay_publish_reason", F),
        ("relay_check_safety", F),
    ],
    "rms.cpp": [
        ("rms_init", F), ("rms_process_buffer", F), ("compute_freq", F),
        ("compute_phase", F), ("rms_compute_3ph", F),
    ],
    "rtc_store.cpp": [
        ("EnergyLogV1", C), ("rtc_init", F), ("rtc_sync_time", F),
        ("rtc_get_time", F), ("rtc_get_time_str", F), ("find_ring_slot", F),
        ("rtc_log_trip", F), ("rtc_log_outage", F), ("rtc_load_energy", F),
        ("rtc_save_energy", F), ("rtc_save_energy_on_event", F),
        ("rtc_print_stored_logs", F),
    ],
    "dma_adc.cpp": [
        ("prv_arm_dtc", F), ("dtc_transfer_complete_isr", F),
        ("dma_adc_init", F), ("dma_adc_start", F), ("dma_adc_stop", F),
        ("prv_test_ping_pong_swap", F), ("prv_test_no_index_drift", F),
        ("prv_test_synthetic_sine_injection", F),
        ("dma_adc_run_self_tests", F),
    ],
    "display.cpp": [
        ("i2c_start", F), ("i2c_stop", F), ("i2c_write", F), ("i2c_delay", F),
        ("ssd1306_command", F), ("ssd1306_data", F),
        ("ssd1306_set_cursor", F), ("display_init", F),
        ("display_clear", F), ("display_print_char", F),
        ("display_print_string", F), ("display_update_metrics", F),
    ],
    "ds18b20.cpp": [("ds18b20_init", F), ("ds18b20_read", F)],
    "dataflash_store.cpp": [
        ("calculate_crc32", F), ("store_init", F), ("store_load_calibration", F),
        ("store_save_calibration", F), ("store_reset_defaults", F),
    ],
    "main.cpp": [("freeMemory", F), ("setup", F), ("loop", F)],
    "globals.h": [("PhaseData", C), ("PowerData3Ph", C), ("CalData", C)],
    "boot_tests.h": [("run_boot_tests", F)],
}

SCORED = {EntityType.FUNCTION, EntityType.METHOD, EntityType.CLASS}


def run_benchmark():
    import os
    target_str = os.environ.get("VERIFYCI_CPP_TARGET")
    target = Path(target_str) if target_str else TARGET
    if not target.exists() or not any((target / rel).exists() for rel in GROUND_TRUTH):
        print(f"Benchmark skipped: TARGET directory {target} does not exist.")
        print("Set VERIFYCI_CPP_TARGET environment variable to point to firmware repo.")
        return 0.0, 0.0
    parser = TreeSitterParser()
    tp = fp = fn = 0
    for rel, truth in GROUND_TRUTH.items():
        path = target / rel
        language = "cpp" if path.suffix == ".cpp" else "c"
        if path.suffix == ".h":
            language = "cpp"
        parsed = parser.parse(rel, path.read_bytes(), language)
        found = {(e.name, e.type) for e in extract_entities(parsed, "fw", "rev1")
                 if e.type in SCORED}
        truth_set = set(truth)
        for name, etype in truth:
            if (name, etype) in found:
                tp += 1
            else:
                fn += 1
                print(f"  FN: {rel}:{name} ({etype.value})")
        for name, etype in found:
            if (name, etype) not in truth_set:
                fp += 1
                print(f"  FP: {rel}:{name} ({etype.value})")
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    print(f"\nResults: TP={tp} FP={fp} FN={fn}")
    print(f"Precision: {precision:.2f}")
    print(f"Recall: {recall:.2f}")
    return precision, recall


if __name__ == "__main__":
    run_benchmark()
