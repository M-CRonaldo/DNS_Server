import os
import re
import json
import signal
import logging
import subprocess

from copy import copy
from pathlib import Path
from textwrap import wrap
from datetime import datetime

from dnslib.server import DNSServer
from dnslib.proxy import ProxyResolver
from dnslib import DNSLabel, QTYPE, RR, dns
from dnslib import DNSRecord, DNSQuestion
from flask import Flask, request, render_template


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


class Record:
    def __init__(self, rname, rtype, args):
        self._rname = DNSLabel(rname)

        rd_cls, self._rtype = TYPE_LOOKUP[rtype]

        if self._rtype == QTYPE.SOA and len(args) == 2:
            # add sensible times to SOA
            args += (SERIAL_NO, 3600, 3600 * 3, 3600 * 24, 3600),

        if self._rtype == QTYPE.TXT and len(args) == 1 and isinstance(args[0], str) and len(args[0]) > 255:
            # wrap long TXT records as per dnslib's docs.
            args = wrap(args[0], 255),

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


class Resolver(ProxyResolver):
    def __init__(self, upstream, zone_file):
        super().__init__(upstream, 53, 5)
        self.records = self.load_zones(zone_file)

    def zone_lines(self):
        current_line = ''
        for line in zone_file.open():
            if line.startswith('#'):
                continue
            line = line.rstrip('\r\n\t ')
            if not line.startswith(' ') and current_line:
                yield current_line
                current_line = ''
            current_line += line.lstrip('\r\n\t ')
        if current_line:
            yield current_line

    def load_zones(self, zone_file):
        # assert zone_file.exists(), f'zone files "{zone_file}" does not exist'
        logger.info('loading zone file "%s":', zone_file)
        zones = []
        for line in self.zone_lines():
            try:
                rname, rtype, args_ = line.split(maxsplit=2)

                if args_.startswith('['):
                    args = tuple(json.loads(args_))
                else:
                    args = (args_,)
                record = Record(rname, rtype, args)
                zones.append(record)
                logger.info(' %2d: %s', len(zones), record)
            except Exception as e:
                raise RuntimeError(f'Error processing line ({e.__class__.__name__}: {e}) "{line.strip()}"') from e
        logger.info('%d zone resource records generated from zone file', len(zones))
        return zones

    def resolve(self, request, handler):
        type_name = QTYPE[request.q.qtype]
        reply = request.reply()
        for record in self.records:
            if record.match(request.q):
                reply.add_answer(record.rr)

        if reply.rr:
            logger.info('found zone for %s[%s], %d replies', request.q.qname, type_name, len(reply.rr))
            return reply

        # no direct zone so look for an SOA record for a higher level zone
        for record in self.records:
            if record.sub_match(request.q):
                reply.add_answer(record.rr)

        if reply.rr:
            logger.info('found higher level SOA resource for %s[%s]', request.q.qname, type_name)
            return reply

        logger.info('no local zone found, proxying %s[%s]', request.q.qname, type_name)
        response = super().resolve(request, handler)
        if response.header.get_rcode() == 3: #NXERROR
            for record in self.records:
                #Check the query type (e.g. A or MX) matches
                if record.rr.rtype == response.q.qtype:
                    newrec = copy(record.rr) #Copy the record so we can change it safely
                    newrec.rname = request.q.qname #Overwrite the name with the request's name
                    reply.add_answer(newrec)
            if reply.rr:
                logger.info('no proxying zone, returning spoof local zone %s[%s]', request.q.qname, type_name)
                return reply
            else:
                return response
        else:
            return response


def handle_sig(signum, frame):
    logger.info('pid=%d, got signal: %s, stopping...', os.getpid(), signal.Signals(signum).name)
    exit(0)


app = Flask(__name__)


class DNSError(Exception):
    pass


@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'GET' and 'site' in request.values and 'type' in request.values:
        query_domain = request.values.get('site')
        query_type = request.values.get('type').upper()
        address = '0.0.0.0'
        port = 5053
        from dnslib.bimap import Bimap
        QTYPE = Bimap('QTYPE',
                      {1: 'A', 2: 'NS', 5: 'CNAME', 6: 'SOA', 12: 'PTR', 15: 'MX',
                       16: 'TXT', 17: 'RP', 18: 'AFSDB', 24: 'SIG', 25: 'KEY', 28: 'AAAA',
                       29: 'LOC', 33: 'SRV', 35: 'NAPTR', 36: 'KX', 37: 'CERT', 38: 'A6',
                       39: 'DNAME', 41: 'OPT', 42: 'APL', 43: 'DS', 44: 'SSHFP',
                       45: 'IPSECKEY', 46: 'RRSIG', 47: 'NSEC', 48: 'DNSKEY', 49: 'DHCID',
                       50: 'NSEC3', 51: 'NSEC3PARAM', 52: 'TLSA', 55: 'HIP', 99: 'SPF',
                       249: 'TKEY', 250: 'TSIG', 251: 'IXFR', 252: 'AXFR', 255: 'ANY',
                       257: 'CAA', 32768: 'TA', 32769: 'DLV'},
                      DNSError)
        q = DNSRecord(q=DNSQuestion(query_domain, getattr(QTYPE, query_type)))
        a_pkt = q.send(address, port, tcp=False)
        a = DNSRecord.parse(a_pkt)
        if a.header.tc:
            # Truncated - retry in TCP mode
            a_pkt = q.send(address, port, tcp=True)
            a = DNSRecord.parse(a_pkt)
        out = str(a)
        pattern = re.compile(r";; ANSWER SECTION:\n(.*)", re.DOTALL)
        out = pattern.findall(out)
        if out:
            lines = out[0].splitlines()
            return render_template('output.html', lines=lines)
        else:
            not_found = ['No answer section']
            return render_template('output.html', lines=not_found)
    return render_template('index.html')


if __name__ == '__main__':
    signal.signal(signal.SIGTERM, handle_sig)

    port = int(os.getenv('PORT', 5053))
    upstream = os.getenv('UPSTREAM', '8.8.8.8')
    zone_file = Path(os.getenv('ZONE_FILE', './zones.txt'))
    resolver = Resolver(upstream, zone_file)
    udp_server = DNSServer(resolver, port=port)
    tcp_server = DNSServer(resolver, port=port, tcp=True)

    logger.info('starting DNS server on port %d, upstream DNS server "%s"', port, upstream)
    udp_server.start_thread()
    tcp_server.start_thread()
    app.run(debug=True, use_reloader=False, host='0.0.0.0')
    # try:
    #     while udp_server.isAlive():
    #         sleep(1)
    # except KeyboardInterrupt:
    #     pass
