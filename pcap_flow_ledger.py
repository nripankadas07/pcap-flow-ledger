"""Bounded classic Ethernet/IPv4 TCP capture accounting without payload output."""
import argparse,ipaddress,json,struct,sys
from pathlib import Path

def ledger(raw):
    if not isinstance(raw,bytes) or len(raw)>32*1024*1024 or len(raw)<24:raise ValueError('pcap must be 24 bytes..32 MiB')
    formats={b'\xd4\xc3\xb2\xa1':('<',1000000),b'\xa1\xb2\xc3\xd4':('>',1000000),b'\x4d\x3c\xb2\xa1':('<',1000000000),b'\xa1\xb2\x3c\x4d':('>',1000000000)}
    if raw[:4] not in formats:raise ValueError('classic pcap required; pcapng unsupported')
    endian,scale=formats[raw[:4]];major,minor,zone,sig,snap,link=struct.unpack(endian+'HHiiII',raw[4:24])
    if (major,minor)!=(2,4) or link!=1 or not 14<=snap<=32*1024*1024:raise ValueError('version 2.4 Ethernet linktype 1 required')
    flows={};offset=24;packets=0;skips={'non_ipv4':0,'non_tcp':0,'fragmented':0};wire=0;first=None;last=None
    while offset<len(raw):
        if packets>=100000 or len(raw)-offset<16:raise ValueError('packet limit or truncated record header')
        sec,frac,cap,orig=struct.unpack(endian+'IIII',raw[offset:offset+16]);offset+=16
        if frac>=scale or cap>snap or cap>orig or cap<14 or offset+cap>len(raw):raise ValueError('invalid or truncated packet record')
        if cap<orig:raise ValueError('snaplen-truncated capture unsupported')
        frame=raw[offset:offset+cap];offset+=cap;packets+=1;wire+=orig;ts=sec*scale+frac
        first=ts if first is None else min(first,ts);last=ts if last is None else max(last,ts)
        if frame[12:14]!=b'\x08\x00':skips['non_ipv4']+=1;continue
        ip=frame[14:]
        if len(ip)<20 or ip[0]>>4!=4:raise ValueError('invalid IPv4 header')
        ihl=(ip[0]&15)*4;total=int.from_bytes(ip[2:4],'big')
        if ihl<20 or total<ihl or total>len(ip):raise ValueError('invalid IPv4 lengths')
        if int.from_bytes(ip[6:8],'big')&0x3fff:skips['fragmented']+=1;continue
        if ip[9]!=6:skips['non_tcp']+=1;continue
        tcp=ip[ihl:total]
        if len(tcp)<20:raise ValueError('short TCP header')
        thl=(tcp[12]>>4)*4
        if thl<20 or thl>len(tcp):raise ValueError('invalid TCP header length')
        src=(str(ipaddress.ip_address(ip[12:16])),int.from_bytes(tcp[:2],'big'));dst=(str(ipaddress.ip_address(ip[16:20])),int.from_bytes(tcp[2:4],'big'))
        key=tuple(sorted((src,dst)));direction=0 if src==key[0] else 1
        if key not in flows:
            if len(flows)>=10000:raise ValueError('flow limit exceeded')
            flows[key]={'endpoints':[{'ip':x[0],'port':x[1]} for x in key],'directions':[{'packets':0,'payload_bytes':0,'wire_bytes':0,'syn':0,'fin':0,'rst':0} for _ in range(2)]}
        d=flows[key]['directions'][direction];d['packets']+=1;d['payload_bytes']+=len(tcp)-thl;d['wire_bytes']+=orig
        for flag,bit in [('syn',2),('fin',1),('rst',4)]:d[flag]+=bool(tcp[13]&bit)
    return {'packets':packets,'wire_bytes':wire,'skipped':skips,'timestamp_resolution':scale,'first_tick':first,'last_tick':last,'flows':[flows[k] for k in sorted(flows)],'scope':'captured bytes, including retransmissions; no reassembly/checksum validation or connection splitting'}

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('capture');a=p.parse_args()
    try:
        with Path(a.capture).open('rb') as f:raw=f.read(32*1024*1024+1)
        print(json.dumps(ledger(raw),sort_keys=True));return 0
    except (ValueError,OSError,TypeError,struct.error) as e:print(json.dumps({'error':str(e)}));return 2
if __name__=='__main__':sys.exit(main())
