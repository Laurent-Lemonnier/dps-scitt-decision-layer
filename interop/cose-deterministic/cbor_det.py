"""CBOR encoder, decoder and core-deterministic validator (RFC 8949).

Written from the text of RFC 8949 (Sections 3, 4.1, 4.2.1, 4.2.3, 5.6).
No third-party CBOR library is used.

Data model used here (Python side):
  int            major type 0 / 1 (range -2**64 .. 2**64-1; no bignum tags)
  bytes          major type 2
  str            major type 3
  list           major type 4
  dict / CborMap major type 5 (CborMap keeps pairs in order, allows any key)
  Tag(n, v)      major type 6
  False/True/None/UNDEFINED/Simple(n)   major type 7 simple values
  float          major type 7 floats (NaN payload kept through its bits)
"""
import math
import struct


class CborError(Exception):
    """Base error. .kind is 'malformed', 'not-canonical' or 'unencodable'."""

    kind = "malformed"

    def __init__(self, msg, offset=None):
        self.offset = offset
        super().__init__(msg if offset is None else f"{msg} (at byte offset {offset})")


class Malformed(CborError):
    kind = "malformed"


class NotCanonical(CborError):
    kind = "not-canonical"


class Unencodable(CborError):
    kind = "unencodable"


class Tag:
    __slots__ = ("tag", "value")

    def __init__(self, tag, value):
        self.tag, self.value = tag, value

    def __eq__(self, other):
        return isinstance(other, Tag) and self.tag == other.tag and self.value == other.value

    def __repr__(self):
        return f"Tag({self.tag}, {self.value!r})"


class Simple:
    __slots__ = ("value",)

    def __init__(self, value):
        self.value = value

    def __eq__(self, other):
        return isinstance(other, Simple) and self.value == other.value

    def __hash__(self):
        return hash(("simple", self.value))

    def __repr__(self):
        return f"Simple({self.value})"


class _Undefined:
    def __repr__(self):
        return "undefined"


UNDEFINED = _Undefined()


class CborMap:
    """Ordered list of (key, value) pairs; keys may be unhashable (lists, maps)."""

    __slots__ = ("pairs",)

    def __init__(self, pairs):
        self.pairs = list(pairs)

    def __repr__(self):
        return f"CborMap({self.pairs!r})"


# ---------------------------------------------------------------- encoding

def _head(major, arg, width=None):
    """Encode a head. width=None -> shortest form (RFC 8949 Section 4.2.1)."""
    if arg < 0:
        raise Unencodable("negative argument")
    if width is None:
        if arg < 24:
            width = 0
        elif arg < 0x100:
            width = 1
        elif arg < 0x10000:
            width = 2
        elif arg < 0x100000000:
            width = 4
        elif arg < 0x10000000000000000:
            width = 8
        else:
            raise Unencodable(f"argument {arg} needs more than 64 bits")
    mt = major << 5
    if width == 0:
        if arg >= 24:
            raise Unencodable("argument too large for immediate form")
        return bytes([mt | arg])
    ai = {1: 24, 2: 25, 4: 26, 8: 27}[width]
    return bytes([mt | ai]) + arg.to_bytes(width, "big")


def _float_bytes(x):
    """Shortest IEEE 754 encoding preserving the value (RFC 8949 4.1/4.2.1)."""
    d = struct.pack(">d", x)
    if math.isnan(x):
        bits = int.from_bytes(d, "big")
        sign = bits >> 63
        mant = bits & ((1 << 52) - 1)
        if mant & ((1 << 42) - 1) == 0:
            return b"\xf9" + ((sign << 15) | (0x1F << 10) | (mant >> 42)).to_bytes(2, "big")
        if mant & ((1 << 29) - 1) == 0:
            return b"\xfa" + ((sign << 31) | (0xFF << 23) | (mant >> 29)).to_bytes(4, "big")
        return b"\xfb" + d
    try:
        h = struct.pack(">e", x)
        if struct.pack(">d", struct.unpack(">e", h)[0]) == d:
            return b"\xf9" + h
    except (OverflowError, struct.error):
        pass
    try:
        f = struct.pack(">f", x)
        if struct.pack(">d", struct.unpack(">f", f)[0]) == d:
            return b"\xfa" + f
    except (OverflowError, struct.error):
        pass
    return b"\xfb" + d


def encode(v, *, key_order="bytewise", reject_duplicates=True):
    """Encode v.

    key_order='bytewise'     -> RFC 8949 Section 4.2.1 (core-deterministic)
    key_order='length-first' -> RFC 8949 Section 4.2.3
    key_order='as-given'     -> keep map order (non-deterministic producer)
    All other aspects use preferred serialization.
    """
    out = bytearray()
    _enc(v, out, key_order, reject_duplicates)
    return bytes(out)


def _enc(v, out, ko, rd):
    if v is True:
        out += b"\xf5"
    elif v is False:
        out += b"\xf4"
    elif v is None:
        out += b"\xf6"
    elif v is UNDEFINED:
        out += b"\xf7"
    elif isinstance(v, int):
        if v >= 0:
            out += _head(0, v)
        else:
            out += _head(1, -1 - v)
    elif isinstance(v, float):
        out += _float_bytes(v)
    elif isinstance(v, (bytes, bytearray)):
        out += _head(2, len(v)) + bytes(v)
    elif isinstance(v, str):
        b = v.encode("utf-8")
        out += _head(3, len(b)) + b
    elif isinstance(v, (list, tuple)):
        out += _head(4, len(v))
        for item in v:
            _enc(item, out, ko, rd)
    elif isinstance(v, (dict, CborMap)):
        pairs = list(v.items()) if isinstance(v, dict) else v.pairs
        enc_pairs = []
        for k, val in pairs:
            kb = bytearray()
            _enc(k, kb, ko, rd)
            vb = bytearray()
            _enc(val, vb, ko, rd)
            enc_pairs.append((bytes(kb), bytes(vb)))
        if ko == "bytewise":
            enc_pairs.sort(key=lambda kv: kv[0])
        elif ko == "length-first":
            enc_pairs.sort(key=lambda kv: (len(kv[0]), kv[0]))
        if rd:
            seen = set()
            for kb, _ in enc_pairs:
                if kb in seen:
                    raise Unencodable(f"duplicate map key {kb.hex()}")
                seen.add(kb)
        out += _head(5, len(enc_pairs))
        for kb, vb in enc_pairs:
            out += kb + vb
    elif isinstance(v, Tag):
        out += _head(6, v.tag)
        _enc(v.value, out, ko, rd)
    elif isinstance(v, Simple):
        if v.value < 24:
            if v.value in (20, 21, 22, 23):
                raise Unencodable("use False/True/None/UNDEFINED for simple 20..23")
            out += bytes([0xE0 | v.value])
        elif 32 <= v.value < 256:
            out += bytes([0xF8, v.value])
        else:
            raise Unencodable(f"simple value {v.value} not encodable")
    else:
        raise Unencodable(f"type {type(v).__name__} has no CBOR mapping here")


# ---------------------------------------------------------------- decoding

def _half_to_float(h):
    sign = h >> 15
    exp = (h >> 10) & 0x1F
    mant = h & 0x3FF
    if exp == 0x1F and mant:  # NaN: widen keeping payload bits
        bits = (sign << 63) | (0x7FF << 52) | (mant << 42)
        return struct.unpack(">d", bits.to_bytes(8, "big"))[0]
    return struct.unpack(">e", h.to_bytes(2, "big"))[0]


def _single_to_float(s):
    sign = s >> 31
    exp = (s >> 23) & 0xFF
    mant = s & 0x7FFFFF
    if exp == 0xFF and mant:
        bits = (sign << 63) | (0x7FF << 52) | (mant << 29)
        return struct.unpack(">d", bits.to_bytes(8, "big"))[0]
    return struct.unpack(">f", s.to_bytes(4, "big"))[0]


class Decoder:
    """strict=True: raise NotCanonical on any deviation from RFC 8949 4.2.1.
    strict=False: accept any well-formed CBOR (indefinite lengths, long
    arguments, any key order) but still reject duplicate map keys, which
    make a map invalid (RFC 8949 Section 5.6)."""

    def __init__(self, data, strict):
        self.data = bytes(data)
        self.pos = 0
        self.strict = strict

    def _need(self, n):
        if self.pos + n > len(self.data):
            raise Malformed("truncated input", self.pos)

    def _byte(self):
        self._need(1)
        b = self.data[self.pos]
        self.pos += 1
        return b

    def _arg(self, ai, start):
        if ai < 24:
            return ai
        if ai in (24, 25, 26, 27):
            n = {24: 1, 25: 2, 26: 4, 27: 8}[ai]
            self._need(n)
            v = int.from_bytes(self.data[self.pos:self.pos + n], "big")
            self.pos += n
            if self.strict:
                shortest = len(_head(0, v)) - 1
                if n != shortest:
                    raise NotCanonical(
                        f"argument {v} encoded on {n} byte(s), shortest form is {shortest}", start)
            return v
        if ai in (28, 29, 30):
            raise Malformed(f"reserved additional information {ai}", start)
        raise AssertionError

    def item(self):
        start = self.pos
        ib = self._byte()
        major, ai = ib >> 5, ib & 0x1F
        if ai == 31:
            if major in (0, 1, 6):
                raise Malformed("indefinite length not allowed for this major type", start)
            if major == 7:
                raise Malformed("unexpected break", start)
            if self.strict:
                raise NotCanonical("indefinite-length item", start)
            return self._indefinite(major, start)
        if major == 7:
            return self._major7(ai, start)
        arg = self._arg(ai, start)
        if major == 0:
            return arg
        if major == 1:
            return -1 - arg
        if major in (2, 3):
            self._need(arg)
            raw = self.data[self.pos:self.pos + arg]
            self.pos += arg
            if major == 2:
                return raw
            try:
                return raw.decode("utf-8")
            except UnicodeDecodeError:
                raise Malformed("text string is not valid UTF-8", start)
        if major == 4:
            return [self.item() for _ in range(arg)]
        if major == 5:
            return self._map(arg, start)
        if major == 6:
            return Tag(arg, self.item())
        raise AssertionError

    def _map(self, count, start):
        pairs = []
        prev = None
        seen = set()
        for _ in range(count):
            kstart = self.pos
            k = self.item()
            kbytes = self.data[kstart:self.pos]
            v = self.item()
            canon = encode(k) if not self.strict else kbytes
            if canon in seen:
                raise Malformed(f"duplicate map key {canon.hex()}", kstart)
            seen.add(canon)
            if self.strict and prev is not None and not prev < kbytes:
                raise NotCanonical(
                    f"map keys not in bytewise lexicographic order: {prev.hex()} before {kbytes.hex()}",
                    kstart)
            prev = kbytes
            pairs.append((k, v))
        return _as_map(pairs)

    def _indefinite(self, major, start):
        if major in (2, 3):
            chunks = []
            while True:
                self._need(1)
                if self.data[self.pos] == 0xFF:
                    self.pos += 1
                    break
                cs = self.pos
                cb = self._byte()
                if cb >> 5 != major or cb & 0x1F == 31:
                    raise Malformed("bad chunk in indefinite string", cs)
                n = self._arg(cb & 0x1F, cs)
                self._need(n)
                chunks.append(self.data[self.pos:self.pos + n])
                self.pos += n
            raw = b"".join(chunks)
            if major == 2:
                return raw
            try:
                return raw.decode("utf-8")
            except UnicodeDecodeError:
                raise Malformed("text string is not valid UTF-8", start)
        items = []
        while True:
            self._need(1)
            if self.data[self.pos] == 0xFF:
                self.pos += 1
                break
            items.append(self.item())
        if major == 4:
            return items
        if len(items) % 2:
            raise Malformed("indefinite map with odd number of items", start)
        pairs = list(zip(items[0::2], items[1::2]))
        seen = set()
        for k, _ in pairs:
            ck = encode(k)
            if ck in seen:
                raise Malformed(f"duplicate map key {ck.hex()}", start)
            seen.add(ck)
        return _as_map(pairs)

    def _major7(self, ai, start):
        if ai < 20:
            return Simple(ai)
        if ai == 20:
            return False
        if ai == 21:
            return True
        if ai == 22:
            return None
        if ai == 23:
            return UNDEFINED
        if ai == 24:
            v = self._byte()
            if v < 32:
                raise Malformed("two-byte simple value below 32", start)
            return Simple(v)
        n = {25: 2, 26: 4, 27: 8}.get(ai)
        if n is None:
            raise Malformed(f"reserved additional information {ai}", start)
        self._need(n)
        raw = self.data[self.pos:self.pos + n]
        self.pos += n
        bits = int.from_bytes(raw, "big")
        x = _half_to_float(bits) if n == 2 else _single_to_float(bits) if n == 4 else struct.unpack(">d", raw)[0]
        if self.strict:
            short = _float_bytes(x)
            if short != bytes([0xE0 | ai]) + raw:
                raise NotCanonical(
                    f"float encoded on {n} bytes, shortest form preserving the value is {short.hex()}",
                    start)
        return x


def _as_map(pairs):
    """dict when every key is a plain int or str (lossless), CborMap otherwise."""
    if all(type(k) in (int, str) for k, _ in pairs):
        return dict(pairs)
    return CborMap(pairs)


def decode(data, *, strict=False, sequence=False):
    """Decode one item (or a CBOR sequence, RFC 8742). Trailing bytes are an error."""
    dec = Decoder(data, strict)
    if sequence:
        items = []
        while dec.pos < len(dec.data):
            items.append(dec.item())
        return items
    v = dec.item()
    if dec.pos != len(dec.data):
        raise Malformed(f"{len(dec.data) - dec.pos} trailing byte(s) after the data item", dec.pos)
    return v


def check_core_deterministic(data, *, sequence=False):
    """Return None if data satisfies RFC 8949 Section 4.2.1, else the CborError."""
    try:
        decode(data, strict=True, sequence=sequence)
        return None
    except CborError as e:
        return e
