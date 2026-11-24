# -*- coding: utf-8 -*-
"""Offline test for eSPI Lite (no Saleae Logic needed).  Usage: python tests/test_lite.py"""
import io
import sys
from pathlib import Path

TESTS_DIR = Path(__file__).resolve().parent
sys.path[:0] = [str(TESTS_DIR / "saleae_stub"), str(TESTS_DIR.parent), str(TESTS_DIR)]
sys.dont_write_bytecode = True

import espi_lite                   # noqa: E402
from espi_sim import Bus, STATUS   # noqa: E402


def run(traffic, **settings):
    cls = espi_lite.EspiLiteAnalyzer
    an = cls.__new__(cls)
    defaults = {"io_mode": espi_lite.IO_SINGLE, "decode_level": espi_lite.DECODE_HEADER,
                "pro_hints": espi_lite.HINT_ON}
    for k, v in {**defaults, **settings}.items():
        assert v in getattr(cls, k).choices, f"invalid choice {v!r} for {k}"
        setattr(an, k, v)
    frames, printed = [], io.StringIO()
    old, sys.stdout = sys.stdout, printed
    try:
        an.__init__()
        bus = Bus(an, frames.append, mode="S", crc=True)
        traffic(bus)
        bus.flush()
    finally:
        sys.stdout = old
    return frames, printed.getvalue()


def traffic(bus):
    bus.txn([0x21, 0x00, 0x08], [0x08, 0x0F, 0x00, 0x0C, 0x03] + STATUS)   # GET_CONFIGURATION
    bus.txn([0x04, 0x00, 0x02, 0x11], [0x08] + STATUS)                     # PUT_VWIRE
    bus.txn([0x40, 0x00, 0x66], [0x08, 0x02] + STATUS)                     # PUT_IORD_SHORT_1B
    bus.txn([0x30], [0x08] + STATUS)                                       # unknown opcode
    bus.partial([0x21])                                                    # exactly 8 clocks
    bus.clk(0); bus.clk(0); bus.gap()                                      # 2-clock glitch frame


def check(cond, msg):
    if not cond:
        raise AssertionError(msg)
    print(f"  ok  {msg}")


def main():
    print("[Lite defaults]")
    frames, out = run(traffic)
    cmds = [f for f in frames if f.type == 'command']
    txns = [f for f in frames if f.type == 'transaction']
    check([f.data['name'] for f in cmds] ==
          ["GET_CONFIGURATION", "PUT_VWIRE", "PUT_IORD_SHORT_1B", "UNKNOWN_0x30", "GET_CONFIGURATION"],
          "command opcodes decoded from IO0")
    check("Pro: config register fields" in txns[0].data['summary'], "config command shows Pro hint")
    check("Pro: Virtual Wire signals" in txns[1].data['summary'], "VWIRE command shows Pro hint")
    check("IBF/OBF" in txns[2].data['summary'], "short IO command shows Pro hint")
    check(txns[3].data['pro'] == "", "unknown opcode has no hint")
    check(txns[-1].data['summary'] == "short frame (2 clk)", "frame shorter than a byte")
    check(all(a.end_time <= b.start_time + 1e-15 for a, b in zip(frames, frames[1:])), "frames do not overlap")
    check(out.count("CMD 0x") == 5, "one Terminal line per command")

    print("[Hints hidden]")
    frames, _ = run(traffic, pro_hints=espi_lite.HINT_OFF)
    check(all("Pro:" not in f.data['summary'] for f in frames), "no Pro hints in bubbles")

    print("[Pro option selected]")
    frames, out = run(traffic, io_mode=espi_lite.IO_QUAD_PRO)
    check(frames and all(f.type == 'upgrade' for f in frames), "only upgrade bubbles")
    check("requires eSPI Pro" in frames[0].data['summary'], "upgrade bubble text")
    check("requires eSPI Pro" in out, "upgrade notice in Terminal")
    print("all checks passed")


if __name__ == "__main__":
    main()
