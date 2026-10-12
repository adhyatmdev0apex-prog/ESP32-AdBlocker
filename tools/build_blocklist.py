#!/usr/bin/env python3
"""Preprocess hosts/domain blocklists into a sorted truncated-FNV-1a hash blob
with an embedded Bloom filter for the ESP32 DNS ad-blocker.

The output file format (v2; firmware remains able to read v1):

  Header (20 bytes):
    [0..3]   magic 'CADB' (0x43 0x41 0x44 0x42)
    [4]      version (2; firmware also reads version 1)
    [5]      hash_bytes (5 — must match firmware)
    [6..9]   num_hashes  (uint32 LE) — number of sorted hash entries
    [10..13] bloom_bits  (uint32 LE) — number of bits in the Bloom filter
    [14]     bloom_k     (uint8)     — number of hash functions per insert
    [15..18] CRC-32 of Bloom filter + hash table (little-endian)
    [19]     reserved    (zero)

  Bloom filter: ceil(bloom_bits / 8) bytes
  Hash table:   num_hashes * hash_bytes bytes (sorted, little-endian)

The Bloom filter is loaded into RAM on the device and used as a fast pre-filter.
Definite misses skip flash lookup; observed hit rates depend on the query workload.

Usage: build_blocklist.py [out.bin] [src ...]
  src = local file or URL. With none given, downloads a balanced daily-driver set
  (StevenBlack base + Hagezi Light) ~= 140k domains: blocks ads/trackers/malware
  but leaves WhatsApp/Instagram/social/messaging working.

  For the aggressive "test the limits" build (~500k, also blocks social/messaging):
    build_blocklist.py blocklist.bin \\
      https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/fakenews-gambling-porn-social/hosts \\
      https://raw.githubusercontent.com/hagezi/dns-blocklists/main/domains/ultimate.txt

  --bloom-bits N   override Bloom filter size (default: 1048576 = 128 KB)
  --no-bloom       skip Bloom filter (header bloom_bits=0)
"""
import sys, os, math, urllib.request, argparse, ipaddress, re, zlib

HASH_BYTES = 5                          # 40-bit hashes — must match firmware
MASK = (1 << (HASH_BYTES * 8)) - 1
FNV_OFFSET = 0xcbf29ce484222325
FNV_PRIME  = 0x100000001b3
U64 = (1 << 64) - 1
MAGIC = b'CADB'
VERSION = 2
HEADER_SIZE = 20

DEFAULT_BLOOM_BITS = 1 << 20            # 128 KB — good for up to ~250k domains

DEFAULT_SOURCES = [
    'https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts',
    'https://raw.githubusercontent.com/hagezi/dns-blocklists/main/domains/light.txt',
]

def fnv64(b: bytes) -> int:
    """Full 64-bit FNV-1a hash (used for Bloom filter double-hashing)."""
    h = FNV_OFFSET
    for c in b:
        h = ((h ^ c) * FNV_PRIME) & U64
    return h

def fnv40(b: bytes) -> int:
    """40-bit truncated FNV-1a hash (used for the sorted flash hash table)."""
    return fnv64(b) & MASK

def norm(d: str) -> str:
    d = d.strip().lower().rstrip('.')
    if d.startswith('*.'):
        d = d[2:]
    elif d.startswith('.'):
        d = d[1:]
    if d.startswith('www.'):
        d = d[4:]
    try:
        d = d.encode('idna').decode('ascii')
    except UnicodeError:
        return ''
    if not d or len(d) > 253:
        return ''
    labels = d.split('.')
    if len(labels) < 2 or any(
        not label or len(label) > 63 or label.startswith('-') or label.endswith('-') or
        any(not (ch.isascii() and (ch.isalnum() or ch == '-')) for ch in label)
        for label in labels
    ):
        return ''
    try:
        ipaddress.ip_address(d)
        return ''
    except ValueError:
        return d

def extract_domains(line: str):
    line = line.strip().lstrip('\ufeff')
    if '##' in line or '#@#' in line or (line.startswith('||') and '#' in line):
        return []
    line = line.split('#', 1)[0].strip()
    if not line or line.startswith(('!', '#', '[Adblock', '@@', '##', '#@#')):
        return []

    if line.startswith('||'):
        match = re.fullmatch(r'\|\|([A-Za-z0-9.-]+)\^(?:\$[A-Za-z0-9_,=-]+)?', line)
        if not match:
            return []
        domain = norm(match.group(1))
        return [domain] if domain else []

    if line.startswith('address=/'):
        pieces = line.split('/')
        if len(pieces) == 3 and pieces[0] == 'address=':
            domain = norm(pieces[1])
            address = pieces[2].strip().lower()
            if domain and address in ('', '#', '0.0.0.0', '::'):
                return [domain]
        return []

    if line.startswith('server=/'):
        return []

    # Hosts syntax accepts any valid IPv4/IPv6 address followed by hostnames.
    parts = line.split()
    if not parts:
        return []
    try:
        ipaddress.ip_address(parts[0])
    except ValueError:
        if len(parts) != 1:
            return []
        domain = norm(parts[0])
        return [domain] if domain else []
    domains = []
    for candidate in parts[1:]:
        domain = norm(candidate)
        if domain:
            domains.append(domain)
    return domains

def read_source(src: str) -> str:
    if os.path.exists(src):
        return open(src, errors='ignore').read()
    print(f'  downloading {src} ...', file=sys.stderr)
    return urllib.request.urlopen(src, timeout=180).read().decode('utf-8', 'ignore')

def optimal_k(num_items: int, bloom_bits: int) -> int:
    if num_items == 0 or bloom_bits == 0:
        return 0
    k = round((bloom_bits / num_items) * math.log(2))
    return max(1, min(k, 30))

def bloom_positions(h64: int, bloom_bits: int, k: int):
    """Double hashing: g_i = (h1 + i * h2) % m."""
    h1 = h64 & 0xFFFFFFFF
    h2 = (h64 >> 32) & 0xFFFFFFFF
    if h2 == 0:
        h2 = 0xFFFFFFFF
    for i in range(k):
        yield (h1 + i * h2) % bloom_bits

def main():
    ap = argparse.ArgumentParser(description='Build ESP32-C3 ad-blocker blocklist.bin')
    ap.add_argument('out', nargs='?', default='blocklist.bin', help='output file')
    ap.add_argument('sources', nargs='*', help='local files or URLs (default: StevenBlack + Hagezi Light)')
    ap.add_argument('--bloom-bits', type=int, default=DEFAULT_BLOOM_BITS,
                    help=f'Bloom filter size in bits (default: {DEFAULT_BLOOM_BITS} = 128 KB)')
    ap.add_argument('--no-bloom', action='store_true', help='skip Bloom filter')
    args = ap.parse_args()

    sources = args.sources if args.sources else DEFAULT_SOURCES
    bloom_bits = 0 if args.no_bloom else args.bloom_bits
    if bloom_bits < 0 or bloom_bits > (1 << 21):
        ap.error('--bloom-bits must be between 0 and 2097152')

    domains = set()
    failed_sources = []
    for src in sources:
        try:
            data = read_source(src)
        except Exception as e:
            print(f'  !! skipped {src}: {e}', file=sys.stderr)
            failed_sources.append(src)
            continue
        for line in data.splitlines():
            domains.update(extract_domains(line.split('#', 1)[0]))
    if failed_sources:
        ap.error('one or more sources failed; refusing to emit a partial blocklist')
    if not domains:
        ap.error('no valid domains found; refusing to create an empty blocklist')

    # Compute 40-bit hashes for the sorted flash table
    domain_list = sorted(domains)
    hash_to_domains = {}
    for d in domain_list:
        h40 = fnv40(d.encode())
        hash_to_domains.setdefault(h40, []).append(d)

    uniq_hashes = sorted(hash_to_domains.keys())
    num_hashes = len(uniq_hashes)
    if num_hashes == 0:
        bloom_bits = 0
    colliding_domains = []
    for h, doms in hash_to_domains.items():
        if len(doms) > 1:
            colliding_domains.append((h, doms))

    # Build Bloom filter (if enabled)
    k = optimal_k(num_hashes, bloom_bits) if bloom_bits > 0 and num_hashes > 0 else 0
    bloom_bytes = bytearray()
    if bloom_bits > 0 and k > 0:
        bloom_arr = bytearray((bloom_bits + 7) // 8)
        for d in domain_list:
            h64 = fnv64(d.encode())
            for pos in bloom_positions(h64, bloom_bits, k):
                bloom_arr[pos >> 3] |= (1 << (pos & 7))
        bloom_bytes = bloom_arr

    # Write binary: header + bloom + hash table
    hash_bytes = b''.join(h.to_bytes(HASH_BYTES, 'little') for h in uniq_hashes)
    payload = bytes(bloom_bytes) + hash_bytes
    header = bytearray(HEADER_SIZE)
    header[0:4] = MAGIC
    header[4] = VERSION
    header[5] = HASH_BYTES
    header[6:10] = num_hashes.to_bytes(4, 'little')
    header[10:14] = bloom_bits.to_bytes(4, 'little')
    header[14] = k
    header[15:19] = zlib.crc32(payload).to_bytes(4, 'little')
    temp_out = args.out + '.tmp'
    try:
        with open(temp_out, 'wb') as f:
            f.write(header)
            f.write(payload)
            f.flush()
            os.fsync(f.fileno())
        os.replace(temp_out, args.out)
    finally:
        if os.path.exists(temp_out):
            os.unlink(temp_out)

    blob_size = HEADER_SIZE + len(bloom_bytes) + num_hashes * HASH_BYTES
    bloom_kb = len(bloom_bytes) / 1024
    fpr = 0.0
    if bloom_bits > 0 and k > 0 and num_hashes > 0:
        fpr = (1 - math.exp(-k * num_hashes / bloom_bits)) ** k

    print(f'source domains   : {len(domains):,}')
    print(f'hash entries     : {num_hashes:,}  ({HASH_BYTES}-byte / {HASH_BYTES*8}-bit)')
    print(f'collisions       : {len(colliding_domains)}  (domain pairs sharing a 40-bit hash -> over-block)')
    if colliding_domains:
        coll_path = args.out + '.collisions.txt'
        with open(coll_path, 'w') as cf:
            for h, doms in sorted(colliding_domains):
                cf.write(f'0x{h:010x}: {", ".join(doms)}\n')
        print(f'  (details -> {coll_path})')
    print(f'bloom filter     : {bloom_kb:.0f} KB, k={k}, FPR~{fpr:.1%}')
    print(f'flash blob       : {blob_size:,} bytes  ({blob_size/1024/1024:.2f} MB)  -> {args.out}')
    print(f'lookup           : ~{math.ceil(math.log2(max(num_hashes,2)))} flash reads/query (bloom miss = 0)')

if __name__ == '__main__':
    main()
