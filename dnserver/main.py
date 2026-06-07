from __future__ import annotations as _annotations

import logging
from datetime import datetime
from pathlib import Path
from textwrap import wrap
from typing import Any, List
import ctypes
import queue
import threading
import time
from collections import OrderedDict

from dnslib import QTYPE, RR, DNSLabel, dns
from dnslib.proxy import ProxyResolver as LibProxyResolver
from dnslib.server import BaseResolver as LibBaseResolver, DNSServer as LibDNSServer

from .load_records import Records, Zone, load_records

__all__ = 'DNSServer', 'logger'

SERIAL_NO = int((datetime.utcnow() - datetime(1970, 1, 1)).total_seconds())

handler = logging.StreamHandler()
handler.setLevel(logging.INFO)
handler.setFormatter(logging.Formatter('%(asctime)s: %(message)s', datefmt='%H:%M:%S'))

logger = logging.getLogger(__name__)
logger.addHandler(handler)
logger.setLevel(logging.INFO)

TYPE_LOOKUP = {
    'A': (dns.A, QTYPE.A),
    'AAAA': (dns.AAAA, QTYPE.AAAA),
    'CAA': (dns.CAA, QTYPE.CAA),
    'CNAME': (dns.CNAME, QTYPE.CNAME),
    'DNSKEY': (dns.DNSKEY, QTYPE.DNSKEY),
    'MX': (dns.MX, QTYPE.MX),
    'NAPTR': (dns.NAPTR, QTYPE.NAPTR),
    'NS': (dns.NS, QTYPE.NS),
    'PTR': (dns.PTR, QTYPE.PTR),
    'RRSIG': (dns.RRSIG, QTYPE.RRSIG),
    'SOA': (dns.SOA, QTYPE.SOA),
    'SRV': (dns.SRV, QTYPE.SRV),
    'TXT': (dns.TXT, QTYPE.TXT),
    'SPF': (dns.TXT, QTYPE.TXT),
}
DEFAULT_PORT = 53
DEFAULT_UPSTREAM = '1.1.1.1'

# --- nftset writer tuning ---
NFT_QUEUE_MAXSIZE = 2048      # bounded queue; updates beyond this are dropped (logged), never block DNS
NFT_CACHE_MAXSIZE = 65536     # max distinct (set, ip) entries remembered, to skip repeat adds
NFT_CACHE_TTL = 600           # seconds; re-add an ip at most once per TTL (self-heals after a set flush)
THREAD_MONITOR_INTERVAL = 60  # seconds between active-thread-count log lines


class Record:
    def __init__(self, zone: Zone):
        self._rname = DNSLabel(zone.host)

        rd_cls, self._rtype = TYPE_LOOKUP[zone.type]

        args: list[Any]
        if isinstance(zone.answer, str):
            if self._rtype == QTYPE.TXT:
                args = [wrap(zone.answer, 255)]
            else:
                args = [zone.answer]
        else:
            if self._rtype == QTYPE.SOA and len(zone.answer) == 2:
                # add sensible times to SOA
                args = zone.answer + [(SERIAL_NO, 3600, 3600 * 3, 3600 * 24, 3600)]
            else:
                args = zone.answer

        if self._rtype in (QTYPE.NS, QTYPE.SOA):
            ttl = 3600 * 24
        else:
            ttl = 300

        self.rr = RR(
            rname=self._rname,
            rtype=self._rtype,
            rdata=rd_cls(*args),
            ttl=ttl,
        )

    def match(self, q):
        return q.qname == self._rname and (q.qtype == QTYPE.ANY or q.qtype == self._rtype)

    def sub_match(self, q):
        return self._rtype == QTYPE.SOA and q.qname.matchSuffix(self._rname)

    def __str__(self):
        return str(self.rr)


def resolve(request, handler, records):
    records = [Record(zone) for zone in records.zones]
    type_name = QTYPE[request.q.qtype]
    reply = request.reply()
    for record in records:
        if record.match(request.q):
            reply.add_answer(record.rr)

    if reply.rr:
        logger.info('found zone for %s[%s], %d replies', request.q.qname, type_name, len(reply.rr))
        return reply

    # no direct zone so look for an SOA record for a higher level zone
    for record in records:
        if record.sub_match(request.q):
            reply.add_answer(record.rr)

    if reply.rr:
        logger.info('found higher level SOA resource for %s[%s]', request.q.qname, type_name)
        return reply


class BaseResolver(LibBaseResolver):
    def __init__(self, records: Records):
        self.records = records
        super().__init__()

    def resolve(self, request, handler):
        answer = resolve(request, handler, self.records)
        if answer:
            return answer

        type_name = QTYPE[request.q.qtype]
        logger.info('no local zone found, not proxying %s[%s]', request.q.qname, type_name)
        return request.reply()


class ProxyResolver(LibProxyResolver):
    def __init__(self, records: Records, upstream: str):
        self.records = records
        super().__init__(address=upstream, port=53, timeout=5)

    def resolve(self, request, handler):
        answer = resolve(request, handler, self.records)
        if answer:
            return answer

        type_name = QTYPE[request.q.qtype]
        logger.debug('no local zone found, proxying %s[%s]', request.q.qname, type_name)
        return super().resolve(request, handler)

def _start_thread_monitor(interval: int = THREAD_MONITOR_INTERVAL):
    """Periodically log the live thread count so leaks are visible in the logs."""

    def _loop():
        while True:
            time.sleep(interval)
            logger.info('active threads: %d', threading.active_count())

    t = threading.Thread(target=_loop, name='thread-monitor', daemon=True)
    t.start()
    return t


class _NftBackend:
    """Run nft commands in-process via libnftables (no fork per query).

    Initialisation is strict / fail-fast: if libnftables cannot be loaded, an nft
    context cannot be created, or a read-only self-test command fails (e.g. missing
    permissions), __init__ raises so the server aborts at startup instead of silently
    running without populating any nftset. Not thread-safe: a single nft context is
    reused, so all calls must come from one worker thread.
    """

    def __init__(self):
        lib = ctypes.CDLL('libnftables.so.1')
        lib.nft_ctx_new.restype = ctypes.c_void_p
        lib.nft_ctx_new.argtypes = [ctypes.c_uint32]
        lib.nft_ctx_buffer_output.argtypes = [ctypes.c_void_p]
        lib.nft_ctx_buffer_error.argtypes = [ctypes.c_void_p]
        lib.nft_ctx_get_error_buffer.restype = ctypes.c_char_p
        lib.nft_ctx_get_error_buffer.argtypes = [ctypes.c_void_p]
        lib.nft_run_cmd_from_buffer.restype = ctypes.c_int
        lib.nft_run_cmd_from_buffer.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
        lib.nft_ctx_free.argtypes = [ctypes.c_void_p]
        ctx = lib.nft_ctx_new(0)
        if not ctx:
            raise OSError('nft_ctx_new returned NULL')
        # buffer both streams BEFORE running any command, so libnftables never writes
        # to our stdout/stderr (and so we can read error text back). Buffers auto-reset
        # on each run. Skipping output buffering before a `list` command segfaults.
        lib.nft_ctx_buffer_output(ctx)
        lib.nft_ctx_buffer_error(ctx)
        self._lib = lib
        self._ctx = ctx
        # self-test: prove we can actually talk to nftables (lib + perms + kernel),
        # not merely that the .so loaded. Raises on failure -> server fails fast.
        ok, err = self.run('list tables')
        if not ok:
            raise OSError('nftables self-test failed: %s' % err.strip())
        logger.info('nft backend ready: in-process libnftables')

    def run(self, command: str):
        """Execute one nft command string. Returns (ok: bool, err: str)."""
        rc = self._lib.nft_run_cmd_from_buffer(self._ctx, command.encode())
        if rc != 0:
            err = self._lib.nft_ctx_get_error_buffer(self._ctx) or b''
            return False, err.decode(errors='replace')
        return True, ''


class ProxyResolverWithNFT(ProxyResolver):
    def __init__(self, records, upstream, ipv4_nftset, ipv6_nftset):
        super().__init__(records, upstream)
        self.ipv4_nftset = ipv4_nftset
        self.ipv6_nftset = ipv6_nftset
        self._backend = _NftBackend()
        # bounded queue: request threads enqueue without ever blocking; a single
        # worker drains it, so the thread count is decoupled from nft throughput.
        self._queue: queue.Queue = queue.Queue(maxsize=NFT_QUEUE_MAXSIZE)
        self._seen: 'OrderedDict[tuple, float]' = OrderedDict()  # (set, ip) -> expiry, worker-only
        self._dropped = 0
        worker = threading.Thread(target=self._worker_loop, name='nft-writer', daemon=True)
        worker.start()

    def _worker_loop(self):
        while True:
            nftset, addrs = self._queue.get()
            try:
                fresh = self._dedup(nftset, addrs)
                if fresh:
                    ok, err = self._backend.run(
                        'add element inet fw4 %s { %s }' % (nftset, ', '.join(fresh))
                    )
                    if not ok:
                        logger.warning('nft add failed for %s {%s}: %s', nftset, ', '.join(fresh), err.strip())
            except Exception as e:  # pragma: no cover - defensive
                logger.error('nft worker error: %s', e)
            finally:
                self._queue.task_done()

    def _dedup(self, nftset, addrs):
        """Drop ips added within the TTL; runs only in the worker thread (no lock needed)."""
        now = time.monotonic()
        while len(self._seen) > NFT_CACHE_MAXSIZE:
            self._seen.popitem(last=False)
        fresh = []
        for ip in addrs:
            key = (nftset, ip)
            exp = self._seen.get(key)
            self._seen[key] = now + NFT_CACHE_TTL
            self._seen.move_to_end(key)
            if exp is None or exp <= now:
                fresh.append(ip)
        return fresh

    def _enqueue(self, nftset, addrs):
        if not nftset or not addrs:
            return
        try:
            self._queue.put_nowait((nftset, addrs))
        except queue.Full:
            self._dropped += 1
            if self._dropped % 100 == 1:
                logger.warning('nft queue full (max=%d); dropped %d updates so far', NFT_QUEUE_MAXSIZE, self._dropped)

    def nft_add(self, result):
        if result is None:
            return
        ipv4_list = []
        ipv6_list = []
        for rr in result.rr:
            if rr.rtype == QTYPE.A:
                ipv4_list.append(str(rr.rdata))
            elif rr.rtype == QTYPE.AAAA:
                ipv6_list.append(str(rr.rdata))
        self._enqueue(self.ipv4_nftset, ipv4_list)
        self._enqueue(self.ipv6_nftset, ipv6_list)

    def resolve(self, request, handler):
        result = super().resolve(request, handler)
        if request.q.qtype in (QTYPE.A, QTYPE.AAAA):
            # non-blocking: hand the nft work to the background worker and return at once
            self.nft_add(result)
        return result

class DNSServer:
    def __init__(
        self,
        records: Records | None = None,
        port: int | str | None = DEFAULT_PORT,
        upstream: str | None = DEFAULT_UPSTREAM,
    ):
        self.port: int = DEFAULT_PORT if port is None else int(port)
        self.upstream: str | None = upstream
        self.udp_server: LibDNSServer | None = None
        self.tcp_server: LibDNSServer | None = None
        self.records: Records = records if records else Records(zones=[])

    @classmethod
    def from_toml(
        cls, zones_file: str | Path, *, port: int | str | None = DEFAULT_PORT, upstream: str | None = DEFAULT_UPSTREAM
    ) -> 'DNSServer':
        records = load_records(zones_file)
        logger.info(
            'loaded %d zone record from %s, with %s as a proxy DNS server',
            len(records.zones),
            zones_file,
            upstream,
        )
        return DNSServer(records, port=port, upstream=upstream)

    def start(self):
        if self.upstream:
            logger.info('starting DNS server on port %d, upstream DNS server "%s"', self.port, self.upstream)
            resolver = ProxyResolver(self.records, self.upstream)
        else:
            logger.info('starting DNS server on port %d, without upstream DNS server', self.port)
            resolver = BaseResolver(self.records)

        self.udp_server = LibDNSServer(resolver, port=self.port)
        self.tcp_server = LibDNSServer(resolver, port=self.port, tcp=True)
        self.udp_server.start_thread()
        self.tcp_server.start_thread()
        ths = [self.udp_server.thread, self.tcp_server.thread]
        for th in ths:
            th.join()

    def stop(self):
        # guard against being called when start() aborted before the servers were created
        # (e.g. the nft backend self-test failed), so the original error is not masked.
        if self.udp_server is not None:
            self.udp_server.stop()
            self.udp_server.server.server_close()
        if self.tcp_server is not None:
            self.tcp_server.stop()
            self.tcp_server.server.server_close()

    @property
    def is_running(self):
        return (self.udp_server and self.udp_server.isAlive()) or (self.tcp_server and self.tcp_server.isAlive())

    def add_record(self, zone: Zone):
        self.records.zones.append(zone)

    def set_records(self, zones: List[Zone]):
        self.records.zones = zones


class DNSServerWithNFT(DNSServer):
    def __init__(self, records = None, port = DEFAULT_PORT, upstream = DEFAULT_UPSTREAM, ipv4_nftset = None, ipv6_nftset = None):
        super().__init__(records, port, upstream)
        self.ipv4_nftset = ipv4_nftset
        self.ipv6_nftset = ipv6_nftset

    def start(self):
        _start_thread_monitor()
        if self.upstream:
            logger.info('starting DNS server on port %d, upstream DNS server "%s"', self.port, self.upstream)
            resolver = ProxyResolverWithNFT(self.records, self.upstream, self.ipv4_nftset, self.ipv6_nftset)
        else:
            logger.info('starting DNS server on port %d, without upstream DNS server', self.port)
            resolver = BaseResolver(self.records)

        self.udp_server = LibDNSServer(resolver, port=self.port)
        self.tcp_server = LibDNSServer(resolver, port=self.port, tcp=True)
        self.udp_server.start_thread()
        self.tcp_server.start_thread()
        ths = [self.udp_server.thread, self.tcp_server.thread]
        for th in ths:
            th.join()
