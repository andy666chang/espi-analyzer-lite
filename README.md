# eSPI Lite

Free Saleae Logic 2 High Level Analyzer for the Intel eSPI bus.

eSPI Lite frames every eSPI transaction and decodes the command opcode of Single I/O transactions.
Full packet decoding is available in **eSPI Pro** (see the comparison below).

## Setup

1. Add a **Simple Parallel** analyzer:
   - Data: D0 = eSPI IO0, D1 = IO1, D2 = IO2, D3 = IO3
   - Clock: eSPI CLK, **rising edge**
2. Add **eSPI Lite** on top of the Simple Parallel analyzer.
3. Recommended: enable Logic's glitch filter on the CLK channel (about 5 ns) to remove CLK glitches.

## What you see

| Bubble | Meaning |
|---|---|
| `CMD 0x21 GET_CONFIGURATION` | Command opcode (first byte on IO0, Single I/O) |
| `90 clk \| Pro: config register fields ...` | Rest of the transaction, plus what eSPI Pro decodes for this command |
| `short frame (4 clk)` | Transaction shorter than one byte |
| `CMD 0x42 ... (may be Quad I/O - decoded as Single, use eSPI Pro)` | Shown on every command after a SET_CONFIGURATION: the Controller may have switched the bus to Dual/Quad I/O, which Lite does not decode. Cleared by an in-band RESET (0xFF). |

Transactions are separated by CLK idle gaps (CLK only toggles while CS# is low), so CS# does not
need to be connected. The Terminal view prints one line per transaction.

## Settings

| Setting | Lite | eSPI Pro |
|---|---|---|
| I/O Mode | Single I/O | Quad I/O, Auto Single -> Quad (follows SET_CONFIGURATION) |
| Decode | Command header | Full packet + Response + Status, Channel deep decode |
| eSPI Pro hints | Show / Hide the "Pro:" hints in the bubbles | - |

Choosing an `[eSPI Pro]` option shows an upgrade bubble for each transaction instead of decoding.

## Lite vs Pro

| Feature | Lite | Pro |
|---|:---:|:---:|
| Transaction framing (from CLK gaps) | ✓ | ✓ |
| Command opcode, Single I/O | ✓ | ✓ |
| Dual / Quad I/O, automatic switch after SET_CONFIGURATION | | ✓ |
| Command fields and Response code, Status flags, WAIT / DEFER | | ✓ |
| Peripheral channel: MemRd/MemWr 32/64, Messages, Completions, short IO/MEM | | ✓ |
| I/O port names (KBC, ACPI EC, Port80, SIO) with IBF/OBF status bits | | ✓ |
| Virtual Wire signal names (SLP_S3#, PLTRST#, SCI#, SMI#, IRQs ...) | | ✓ |
| OOB channel packets | | ✓ |
| Flash channel Read/Write/Erase, RPMC OP1/OP2 | | ✓ |
| Configuration register fields (eSPI Rev 1.5) | | ✓ |
| Split bubble / data-table columns / multi-line Terminal output | | ✓ |

Get eSPI Pro: contact andy850821@gmail.com

## Offline test

```
python tests/test_lite.py
```

Runs the analyzer on simulated Single I/O traffic without Logic (uses `tests/saleae_stub`).
