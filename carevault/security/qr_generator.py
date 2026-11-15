"""
Pure-Python ISO/IEC 18004 QR Code Matrix + Pillow PNG Data-URL Renderer
Generates genuine camera-scannable QR codes (Byte Mode, EC Level L, Versions 1-10)
offline without external network/C dependencies.
"""
from __future__ import annotations

import base64
import io

from PIL import Image

# ISO/IEC 18004 Version 1..10 parameters for Error Correction Level L:
# (total_data_codewords, ec_codewords_per_block, num_blocks_g1, data_cw_g1, num_blocks_g2, data_cw_g2, alignment_centers)
_VERSION_TABLE: dict[int, tuple[int, int, int, int, int, int, list[int]]] = {
    1: (19, 7, 1, 19, 0, 0, []),
    2: (34, 10, 1, 34, 0, 0, [6, 18]),
    3: (55, 15, 1, 55, 0, 0, [6, 22]),
    4: (80, 20, 1, 80, 0, 0, [6, 26]),
    5: (108, 26, 1, 108, 0, 0, [6, 30]),
    6: (136, 18, 2, 68, 0, 0, [6, 34]),
    7: (156, 20, 2, 78, 0, 0, [6, 22, 38]),
    8: (194, 24, 2, 97, 0, 0, [6, 24, 42]),
    9: (232, 30, 2, 116, 0, 0, [6, 26, 46]),
    10: (274, 18, 2, 68, 2, 69, [6, 28, 50]),
}

# GF(256) log/antilog tables with primitive polynomial 0x11D
_GF_EXP = [0] * 512
_GF_LOG = [0] * 256
_val = 1
for _i in range(255):
    _GF_EXP[_i] = _val
    _GF_LOG[_val] = _i
    _val <<= 1
    if _val & 0x100:
        _val ^= 0x11D
for _i in range(255, 512):
    _GF_EXP[_i] = _GF_EXP[_i - 255]


def _gf_mul(a: int, b: int) -> int:
    if a == 0 or b == 0:
        return 0
    return _GF_EXP[_GF_LOG[a] + _GF_LOG[b]]


def _rs_generator_poly(degree: int) -> list[int]:
    poly = [1]
    for i in range(degree):
        next_poly = [0] * (len(poly) + 1)
        root = _GF_EXP[i]
        for j, coef in enumerate(poly):
            next_poly[j] ^= coef
            next_poly[j + 1] ^= _gf_mul(coef, root)
        poly = next_poly
    return poly


def _rs_encode(data: list[int], ec_len: int) -> list[int]:
    gen = _rs_generator_poly(ec_len)
    rem = [0] * ec_len
    for byte in data:
        factor = byte ^ rem[0]
        rem = rem[1:] + [0]
        if factor != 0:
            for i in range(ec_len):
                rem[i] ^= _gf_mul(gen[i + 1], factor)
    return rem


def _select_version(payload_len: int) -> int:
    for ver, spec in _VERSION_TABLE.items():
        total_data_cw = spec[0]
        char_count_bits = 8 if ver <= 9 else 16
        capacity_bytes = (total_data_cw * 8 - 4 - char_count_bits) // 8
        if payload_len <= capacity_bytes:
            return ver
    raise ValueError("QR payload exceeds Version 10 capacity.")


def _encode_codewords(payload: bytes, ver: int) -> list[int]:
    total_data_cw, ec_cw, nb1, dcw1, nb2, dcw2, _ = _VERSION_TABLE[ver]
    bits: list[int] = [0, 1, 0, 0]  # Byte mode indicator (0100)
    cc_bits = 8 if ver <= 9 else 16
    for i in range(cc_bits - 1, -1, -1):
        bits.append((len(payload) >> i) & 1)
    for b in payload:
        for i in range(7, -1, -1):
            bits.append((b >> i) & 1)

    max_bits = total_data_cw * 8
    bits.extend([0] * min(4, max_bits - len(bits)))
    while len(bits) % 8 != 0:
        bits.append(0)

    data_bytes = [
        int("".join(str(bit) for bit in bits[i : i + 8]), 2) for i in range(0, len(bits), 8)
    ]
    pad_seq = [0xEC, 0x11]
    idx = 0
    while len(data_bytes) < total_data_cw:
        data_bytes.append(pad_seq[idx % 2])
        idx += 1

    blocks_data: list[list[int]] = []
    blocks_ec: list[list[int]] = []
    pos = 0
    for _ in range(nb1):
        blk = data_bytes[pos : pos + dcw1]
        pos += dcw1
        blocks_data.append(blk)
        blocks_ec.append(_rs_encode(blk, ec_cw))
    for _ in range(nb2):
        blk = data_bytes[pos : pos + dcw2]
        pos += dcw2
        blocks_data.append(blk)
        blocks_ec.append(_rs_encode(blk, ec_cw))

    interleaved: list[int] = []
    max_dcw = max(dcw1, dcw2)
    for i in range(max_dcw):
        for blk in blocks_data:
            if i < len(blk):
                interleaved.append(blk[i])
    for i in range(ec_cw):
        for ec in blocks_ec:
            interleaved.append(ec[i])
    return interleaved


def _build_base_matrix(ver: int) -> tuple[list[list[int]], list[list[bool]]]:
    size = 17 + 4 * ver
    matrix = [[0] * size for _ in range(size)]
    reserved = [[False] * size for _ in range(size)]

    def place_finder(row: int, col: int) -> None:
        for r in range(-1, 8):
            for c in range(-1, 8):
                rr, cc = row + r, col + c
                if 0 <= rr < size and 0 <= cc < size:
                    if 0 <= r <= 6 and 0 <= c <= 6:
                        on = (
                            r in (0, 6)
                            or c in (0, 6)
                            or (2 <= r <= 4 and 2 <= c <= 4)
                        )
                        matrix[rr][cc] = 1 if on else 0
                    else:
                        matrix[rr][cc] = 0
                    reserved[rr][cc] = True

    place_finder(0, 0)
    place_finder(0, size - 7)
    place_finder(size - 7, 0)

    # Alignment patterns
    centers = _VERSION_TABLE[ver][6]
    for r in centers:
        for c in centers:
            if reserved[r][c]:
                continue
            for dr in range(-2, 3):
                for dc in range(-2, 3):
                    on = max(abs(dr), abs(dc)) in (0, 2)
                    matrix[r + dr][c + dc] = 1 if on else 0
                    reserved[r + dr][c + dc] = True

    # Timing patterns
    for i in range(8, size - 8):
        if not reserved[6][i]:
            matrix[6][i] = 1 if i % 2 == 0 else 0
            reserved[6][i] = True
        if not reserved[i][6]:
            matrix[i][6] = 1 if i % 2 == 0 else 0
            reserved[i][6] = True

    # Dark module & format reservation areas
    matrix[size - 8][8] = 1
    reserved[size - 8][8] = True
    for i in range(9):
        if i < size:
            reserved[8][i] = True
            reserved[i][8] = True
    for i in range(8):
        reserved[8][size - 1 - i] = True
        reserved[size - 1 - i][8] = True

    if ver >= 7:
        # Version info bits for v7..10
        v_info = ver << 12
        for i in range(17, 11, -1):
            if (v_info >> i) & 1:
                v_info ^= 0x1F25 << (i - 12)
        v_bits = (ver << 12) | v_info
        for i in range(18):
            bit = (v_bits >> i) & 1
            r, c = i // 3, size - 11 + (i % 3)
            matrix[r][c] = bit
            reserved[r][c] = True
            matrix[c][r] = bit
            reserved[c][r] = True

    return matrix, reserved


def _write_format_bits(matrix: list[list[int]], mask_id: int) -> None:
    size = len(matrix)
    # EC Level L = 01
    data = (0b01 << 3) | mask_id
    rem = data << 10
    for i in range(14, 9, -1):
        if (rem >> i) & 1:
            rem ^= 0x537 << (i - 10)
    fmt = ((data << 10) | rem) ^ 0x5412
    bits = [(fmt >> i) & 1 for i in range(14, -1, -1)]

    # Top-left around finder
    coords_1 = [
        (8, 0), (8, 1), (8, 2), (8, 3), (8, 4), (8, 5), (8, 7), (8, 8),
        (7, 8), (5, 8), (4, 8), (3, 8), (2, 8), (1, 8), (0, 8),
    ]
    coords_2 = [
        (size - 1, 8), (size - 2, 8), (size - 3, 8), (size - 4, 8),
        (size - 5, 8), (size - 6, 8), (size - 7, 8),
        (8, size - 8), (8, size - 7), (8, size - 6), (8, size - 5),
        (8, size - 4), (8, size - 3), (8, size - 2), (8, size - 1),
    ]
    for idx, bit in enumerate(bits):
        r1, c1 = coords_1[idx]
        r2, c2 = coords_2[idx]
        matrix[r1][c1] = bit
        matrix[r2][c2] = bit


def build_qr_png_data_url(text: str, box_size: int = 6, border: int = 4) -> str:
    payload = text.encode("utf-8")
    ver = _select_version(len(payload))
    codewords = _encode_codewords(payload, ver)
    bit_stream = [(cw >> i) & 1 for cw in codewords for i in range(7, -1, -1)]

    matrix, reserved = _build_base_matrix(ver)
    size = len(matrix)

    bit_idx = 0
    upward = True
    col = size - 1
    while col > 0:
        if col == 6:
            col -= 1
        row_iter = range(size - 1, -1, -1) if upward else range(size)
        for row in row_iter:
            for dc in (0, -1):
                c = col + dc
                if not reserved[row][c]:
                    bit = bit_stream[bit_idx] if bit_idx < len(bit_stream) else 0
                    bit_idx += 1
                    # Apply Mask Pattern 0: (row + c) % 2 == 0
                    if (row + c) % 2 == 0:
                        bit ^= 1
                    matrix[row][c] = bit
        upward = not upward
        col -= 2

    _write_format_bits(matrix, mask_id=0)

    total_px = (size + 2 * border) * box_size
    img = Image.new("RGB", (total_px, total_px), "white")
    pixels = img.load()
    if pixels is None:
        raise RuntimeError("Failed to initialize QR image pixel buffer.")
    for r in range(size):
        for c in range(size):
            if matrix[r][c]:
                x0 = (c + border) * box_size
                y0 = (r + border) * box_size
                for dy in range(box_size):
                    for dx in range(box_size):
                        pixels[x0 + dx, y0 + dy] = (11, 37, 69)

    buf = io.BytesIO()
    img.save(buf, format="PNG")
    b64 = base64.b64encode(buf.getvalue()).decode("ascii")
    return f"data:image/png;base64,{b64}"
