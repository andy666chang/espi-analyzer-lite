# -*- coding: utf-8 -*-
"""eSPI bus simulator: drives an EspiAnalyzer instance clock-by-clock, like the
Saleae Simple Parallel analyzer would (one frame per CLK edge, frame.data['data'] = IO[3:0])."""
from saleae.analyzers import AnalyzerFrame

STATUS = [0x0F, 0x03]       # Status word 0x030F (LE)
CRC_BYTE = 0xC5             # CRC is not validated by the analyzer; any value works


def le(v):
    return [v & 0xFF, (v >> 8) & 0xFF, (v >> 16) & 0xFF, (v >> 24) & 0xFF]


def be32(v):
    return [(v >> 24) & 0xFF, (v >> 16) & 0xFF, (v >> 8) & 0xFF, v & 0xFF]


class Bus:
    def __init__(self, analyzer, record, mode="S", crc=False, period=30e-9):
        self.an = analyzer
        self.record = record     # callable(frame) for every frame the analyzer emits
        self.mode = mode         # "S" single, "D" dual, "Q" quad
        self.crc = crc
        self.T = period
        self.t = 0.0

    # --- low level -------------------------------------------------------
    def clk(self, value):
        out = self.an.decode(AnalyzerFrame('data', self.t, self.t + self.T, {'data': value}))
        for f in out or []:
            self.record(f)
        self.t += self.T

    def send_byte(self, b, from_target):
        if self.mode == "Q":
            self.clk(b >> 4)
            self.clk(b & 0x0F)
        elif self.mode == "D":
            for s in (6, 4, 2, 0):
                self.clk((b >> s) & 0x03)
        else:  # Single: Controller drives IO0, Target drives IO1
            for s in range(7, -1, -1):
                bit = (b >> s) & 1
                self.clk(bit << 1 if from_target else bit)

    def gap(self, seconds=1e-6):
        self.t += seconds

    # --- transactions ----------------------------------------------------
    def txn(self, cmd, rsp, waits=0):
        """One CS# frame: CMD [+CRC], TAR, [WAIT x n], RSP [+CRC], then an idle gap."""
        cmd = list(cmd) + ([CRC_BYTE] if self.crc else [])
        rsp = list(rsp) + ([CRC_BYTE] if self.crc else [])
        for b in cmd:
            self.send_byte(b, False)
        self.clk(0)
        self.clk(0)
        for _ in range(waits):
            self.send_byte(0x0F, True)
        for b in rsp:
            self.send_byte(b, True)
        self.gap()

    def partial(self, cmd_bytes):
        """Truncated frame (CS# de-asserted early) -> analyzer should report INCOMPLETE."""
        for b in cmd_bytes:
            self.send_byte(b, False)
        self.gap()

    def flush(self):
        """A trailing clock after the last gap so the analyzer processes the final boundary."""
        self.clk(0)
        self.gap()
