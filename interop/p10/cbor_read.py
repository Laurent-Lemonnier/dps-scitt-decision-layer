"""A CBOR reader written from RFC 8949 for the P10 S2b outside reading: well-formed CBOR, definite and indefinite
lengths, any integer width (S2b imposes no deterministic encoding, prereg section 13.2). Duplicate map labels are
recorded on the decoded map, not silently overwritten, so that each caller applies the rule its text states.
`encode` writes deterministic CBOR (RFC 8949 section 4.2.1) for what this reading builds itself (Sig_structure,
COSE_Key thumbprints)."""
import struct


class CborError(ValueError):
    pass


class Tag:
    def __init__(self, tag, value):
        self.tag, self.value = tag, value

    def __repr__(self):
        return f"Tag({self.tag}, {self.value!r})"


class Simple:
    def __init__(self, value):
        self.value = value

    def __eq__(self, other):
        return isinstance(other, Simple) and other.value == self.value

    def __hash__(self):
        return hash(("simple", self.value))

    def __repr__(self):
        return f"Simple({self.value})"


class Map(dict):
    """A decoded map; `duplicate` is set when a label repeats (the later value is kept, and the flag says so)."""
    duplicate = False


def _half(h):
    s, e, f = h >> 15, (h >> 10) & 0x1F, h & 0x3FF
    if e == 0:
        v = (f / 1024.0) * 2 ** -14
    elif e == 31:
        v = float("inf") if f == 0 else float("nan")
    else:
        v = (1 + f / 1024.0) * 2 ** (e - 15)
    return -v if s else v


def decode(data, pos=0):
    """One data item starting at pos. Returns (value, end)."""
    def take(n):
        nonlocal pos
        if n < 0 or pos + n > len(data):
            raise CborError("truncated")
        pos += n
        return data[pos - n:pos]

    def head():
        ib = take(1)[0]
        major, ai = ib >> 5, ib & 0x1F
        if ai < 24:
            return major, ai, ai, False
        if ai in (24, 25, 26, 27):
            return major, ai, int.from_bytes(take({24: 1, 25: 2, 26: 4, 27: 8}[ai]), "big"), False
        if ai == 31:
            if major in (0, 1, 6):
                raise CborError("indefinite length on a major type that has none")
            return major, ai, None, True
        raise CborError("reserved additional information")

    def at_break():
        if pos >= len(data):
            raise CborError("truncated")
        if data[pos] == 0xFF:
            take(1)
            return True
        return False

    def chunks(major):
        out = b""
        while not at_break():
            m, _, n, indef = head()
            if m != major or indef:
                raise CborError("bad chunk in an indefinite-length string")
            out += take(n)
        return out

    def item():
        major, ai, n, indef = head()
        if major == 0:
            return n
        if major == 1:
            return -1 - n
        if major == 2:
            return chunks(2) if indef else take(n)
        if major == 3:
            raw = chunks(3) if indef else take(n)
            try:
                return raw.decode("utf-8")
            except UnicodeDecodeError:
                raise CborError("invalid UTF-8 in a text string")
        if major == 4:
            if indef:
                out = []
                while not at_break():
                    out.append(item())
                return out
            return [item() for _ in range(n)]
        if major == 5:
            out = Map()
            count = 0
            while (not at_break()) if indef else count < n:
                k = item()
                if isinstance(k, (list, dict)):
                    raise CborError("a map key is an array or a map")
                key = (("tag", k.tag, repr(k.value)) if isinstance(k, Tag) else k)
                v = item()
                if key in out:
                    out.duplicate = True
                out[key] = v
                count += 1
            return out
        if major == 6:
            return Tag(n, item())
        if indef:
            raise CborError("unexpected break")
        if ai < 24:
            return {20: False, 21: True, 22: None}.get(ai, Simple(ai))
        if ai == 24:
            if n < 32:
                raise CborError("a simple value below 32 in two bytes")
            return Simple(n)
        if ai == 25:
            return _half(n)
        if ai == 26:
            return struct.unpack(">f", n.to_bytes(4, "big"))[0]
        return struct.unpack(">d", n.to_bytes(8, "big"))[0]

    v = item()
    return v, pos


def decode_exact(data):
    """Exactly one item and nothing after it."""
    v, end = decode(data, 0)
    if end != len(data):
        raise CborError("trailing bytes")
    return v


def _head_bytes(major, n):
    if n < 24:
        return bytes([(major << 5) | n])
    if n < 0x100:
        return bytes([(major << 5) | 24, n])
    if n < 0x10000:
        return bytes([(major << 5) | 25]) + n.to_bytes(2, "big")
    if n < 0x100000000:
        return bytes([(major << 5) | 26]) + n.to_bytes(4, "big")
    return bytes([(major << 5) | 27]) + n.to_bytes(8, "big")


def encode(v):
    if isinstance(v, bool):
        return b"\xf5" if v else b"\xf4"
    if v is None:
        return b"\xf6"
    if isinstance(v, int):
        return _head_bytes(0, v) if v >= 0 else _head_bytes(1, -1 - v)
    if isinstance(v, (bytes, bytearray)):
        return _head_bytes(2, len(v)) + bytes(v)
    if isinstance(v, str):
        b = v.encode("utf-8")
        return _head_bytes(3, len(b)) + b
    if isinstance(v, list):
        return _head_bytes(4, len(v)) + b"".join(encode(x) for x in v)
    if isinstance(v, dict):
        items = sorted(((encode(k), encode(x)) for k, x in v.items()), key=lambda kv: kv[0])
        return _head_bytes(5, len(items)) + b"".join(k + x for k, x in items)
    if isinstance(v, Tag):
        return _head_bytes(6, v.tag) + encode(v.value)
    raise ValueError(f"cannot encode {type(v)}")
