# -*- coding: utf-8 -*-
"""eSPI Lite - Saleae Logic 2 High Level Analyzer (free edition).

Input : Simple Parallel analyzer, data D0..D3 = eSPI IO0..IO3, clock = eSPI CLK (rising edge).
Lite  : frames each transaction (CS# low period, detected from CLK idle gaps) and decodes the
        command opcode of Single I/O transactions (first byte on IO0).
Pro   : full packet decoding is available in eSPI Pro (see PRO_FEATURES / README.md).
"""
from saleae.analyzers import HighLevelAnalyzer, AnalyzerFrame, ChoicesSetting

UPGRADE_URL = "https://<your-store>/espi-pro"     # TODO: replace with the eSPI Pro store page

# eSPI command opcodes (Intel eSPI Base Specification)
OPCODES = {
    0x00: "PUT_PC", 0x01: "GET_PC", 0x02: "PUT_NP", 0x03: "GET_NP",
    0x04: "PUT_VWIRE", 0x05: "GET_VWIRE", 0x06: "PUT_OOB", 0x07: "GET_OOB",
    0x08: "PUT_FLASH_C", 0x09: "GET_FLASH_NP", 0x0A: "PUT_FLASH_NP", 0x0B: "GET_FLASH_C",
    0x21: "GET_CONFIGURATION", 0x22: "SET_CONFIGURATION", 0x25: "GET_STATUS",
    0x40: "PUT_IORD_SHORT_1B", 0x41: "PUT_IORD_SHORT_2B", 0x43: "PUT_IORD_SHORT_4B",
    0x44: "PUT_IOWR_SHORT_1B", 0x45: "PUT_IOWR_SHORT_2B", 0x47: "PUT_IOWR_SHORT_4B",
    0x48: "PUT_MEMRD32_SHORT_1B", 0x49: "PUT_MEMRD32_SHORT_2B", 0x4B: "PUT_MEMRD32_SHORT_4B",
    0x4C: "PUT_MEMWR32_SHORT_1B", 0x4D: "PUT_MEMWR32_SHORT_2B", 0x4F: "PUT_MEMWR32_SHORT_4B",
    0xFF: "RESET",
}

# What eSPI Pro would show for each kind of command (teaser only - no decoding here)
_PRO_PERIPHERAL = "Pro: MemRd/MemWr/Message/Completion fields, address and data"
_PRO_SHORT_IO = "Pro: port name (KBC/ACPI EC/Port80/SIO), data, IBF/OBF status bits"
_PRO_SHORT_MEM = "Pro: 32-bit address and data"
_PRO_VWIRE = "Pro: Virtual Wire signals (SLP_S3#, PLTRST#, SCI#, SMI#, IRQ0-15 ...)"
_PRO_OOB = "Pro: OOB (SMBus/MCTP) packet tag, length and payload"
_PRO_FLASH = "Pro: Flash Read/Write/Erase address, RPMC OP1/OP2 fields"
_PRO_CONFIG = "Pro: config register fields (CRC, I/O mode, frequency, channels) + auto Single/Quad switch"
_PRO_STATUS = "Pro: Response code and Status flags (PC/NP/VW/OOB/Flash FREE/AVAIL)"
PRO_HINTS = {
    0x00: _PRO_PERIPHERAL, 0x01: _PRO_PERIPHERAL, 0x02: _PRO_PERIPHERAL, 0x03: _PRO_PERIPHERAL,
    0x04: _PRO_VWIRE, 0x05: _PRO_VWIRE,
    0x06: _PRO_OOB, 0x07: _PRO_OOB,
    0x08: _PRO_FLASH, 0x09: _PRO_FLASH, 0x0A: _PRO_FLASH, 0x0B: _PRO_FLASH,
    0x21: _PRO_CONFIG, 0x22: _PRO_CONFIG,
    0x25: _PRO_STATUS,
    0x40: _PRO_SHORT_IO, 0x41: _PRO_SHORT_IO, 0x43: _PRO_SHORT_IO,
    0x44: _PRO_SHORT_IO, 0x45: _PRO_SHORT_IO, 0x47: _PRO_SHORT_IO,
    0x48: _PRO_SHORT_MEM, 0x49: _PRO_SHORT_MEM, 0x4B: _PRO_SHORT_MEM,
    0x4C: _PRO_SHORT_MEM, 0x4D: _PRO_SHORT_MEM, 0x4F: _PRO_SHORT_MEM,
}

# Settings choices. Saleae stores the chosen string: never rename an existing choice.
IO_SINGLE = "Single I/O"
IO_QUAD_PRO = "Quad I/O  [eSPI Pro]"
IO_AUTO_PRO = "Auto Single -> Quad (follow SET_CONFIGURATION)  [eSPI Pro]"
DECODE_HEADER = "Command header"
DECODE_FULL_PRO = "Full packet + Response + Status  [eSPI Pro]"
DECODE_CHANNEL_PRO = "Channel deep decode (PC / VW / OOB / Flash)  [eSPI Pro]"
HINT_ON = "Show eSPI Pro hints"
HINT_OFF = "Hide eSPI Pro hints"

DEFAULT_GAP_THRESHOLD = 250e-9   # CS# idle detection before the clock period is known
GAP_FACTOR = 2.2                 # idle gap = CLK interval > GAP_FACTOR x estimated period


class EspiLiteAnalyzer(HighLevelAnalyzer):
    io_mode = ChoicesSetting(choices=[IO_SINGLE, IO_QUAD_PRO, IO_AUTO_PRO], label="I/O Mode")
    decode_level = ChoicesSetting(choices=[DECODE_HEADER, DECODE_FULL_PRO, DECODE_CHANNEL_PRO],
                                  label="Decode")
    pro_hints = ChoicesSetting(choices=[HINT_ON, HINT_OFF], label="eSPI Pro hints")

    result_types = {
        'command': {'format': '{{data.summary}}'},
        'transaction': {'format': '{{data.summary}}'},
        'upgrade': {'format': '{{data.summary}}'},
    }

    def __init__(self):
        self.pro_selected = [s for s in (self.io_mode, self.decode_level) if s.endswith("[eSPI Pro]")]
        self.show_hints = (self.pro_hints != HINT_OFF)
        self.last_clk_time = None
        self.last_clk_delta = None
        self.clk_period = None
        self.origin_time = None
        self._reset()
        print("eSPI Lite: transaction framing + Single I/O command opcode.")
        if self.pro_selected:
            print(f"eSPI Lite: '{'; '.join(self.pro_selected)}' requires eSPI Pro -> {UPGRADE_URL}")
        elif self.show_hints:
            print(f"eSPI Lite: full decoding (Quad I/O, responses, all 4 channels) in eSPI Pro -> {UPGRADE_URL}")

    def _reset(self):
        self.clocks = 0
        self.opcode = 0
        self.txn_start = None
        self.cmd_end = None
        self.last_clk_end = None
        self.clk_period = None

    def _end_time(self, frame):
        """Clamp the end of the last frame before an idle gap to one clock period."""
        if self.last_clk_delta is not None and \
                float(frame.end_time - frame.start_time) > float(self.last_clk_delta) * 1.5:
            return frame.start_time + self.last_clk_delta
        return frame.end_time

    def _print(self, t, text):
        if self.origin_time is None:
            self.origin_time = t
        print(f"[+{float(t - self.origin_time):.7f}s] {text}")

    def _finish_transaction(self, out):
        """Emit the frames for the transaction that just ended (CS# de-asserted)."""
        if self.txn_start is None:
            return
        dur_us = float(self.last_clk_end - self.txn_start) * 1e6

        if self.pro_selected:
            text = f"eSPI transaction ({self.clocks} clk, {dur_us:.2f} us) - " \
                   f"{self.pro_selected[0].replace('  [eSPI Pro]', '')} requires eSPI Pro"
            out.append(AnalyzerFrame('upgrade', self.txn_start, self.last_clk_end,
                                     {'summary': text, 'upgrade': UPGRADE_URL}))
            return

        if self.clocks >= 8:
            name = OPCODES.get(self.opcode, f"UNKNOWN_0x{self.opcode:02X}")
            summary = f"CMD 0x{self.opcode:02X} {name}"
            out.append(AnalyzerFrame('command', self.txn_start, self.cmd_end,
                                     {'summary': summary, 'opcode': self.opcode, 'name': name}))
            self._print(self.txn_start, f"{summary}  ({self.clocks} clk, {dur_us:.2f} us)")
        if self.clocks > 8:
            hint = PRO_HINTS.get(self.opcode, "") if self.show_hints else ""
            summary = f"{self.clocks - 8} clk" + (f" | {hint}" if hint else "")
            out.append(AnalyzerFrame('transaction', self.cmd_end, self.last_clk_end,
                                     {'summary': summary, 'clocks': self.clocks,
                                      'duration_us': round(dur_us, 3), 'pro': hint}))
        elif self.clocks < 8:
            out.append(AnalyzerFrame('transaction', self.txn_start, self.last_clk_end,
                                     {'summary': f"short frame ({self.clocks} clk)",
                                      'clocks': self.clocks, 'duration_us': round(dur_us, 3), 'pro': ""}))

    def decode(self, frame: AnalyzerFrame):
        if frame.type != 'data' or 'data' not in frame.data:
            return None
        out = []

        # Transaction boundary = CLK idle gap (eSPI CLK only toggles while CS# is low)
        if self.last_clk_time is not None:
            delta = frame.start_time - self.last_clk_time
            threshold = self.clk_period * GAP_FACTOR if self.clk_period is not None else DEFAULT_GAP_THRESHOLD
            if float(delta) > threshold:
                self._finish_transaction(out)
                self._reset()
            else:
                self.last_clk_delta = delta
                gap = float(delta)
                self.clk_period = gap if self.clk_period is None else self.clk_period * 0.8 + gap * 0.2

        end = self._end_time(frame)
        self.last_clk_time = frame.start_time
        self.last_clk_end = end
        if self.txn_start is None:
            self.txn_start = frame.start_time

        # Single I/O: the Controller drives the command on IO0, MSB first
        if self.clocks < 8:
            self.opcode = (self.opcode << 1) | (frame.data['data'] & 0x01)
            if self.clocks == 7:
                self.cmd_end = end
        self.clocks += 1

        return out or None
