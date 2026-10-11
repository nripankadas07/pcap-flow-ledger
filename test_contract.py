import struct,unittest
from pcap_flow_ledger import ledger
def packet(src=b'\xc0\x00\x02\x01',dst=b'\xc0\x00\x02\x02',sp=1234,dp=443,payload=b'abc',flags=2,proto=6,fragment=0):
    tcp=struct.pack('!HHIIBBHHH',sp,dp,1,0,80,flags,1000,0,0)+payload
    ip=struct.pack('!BBHHHBBH4s4s',69,0,20+len(tcp),0,fragment,64,proto,0,src,dst)
    return b'\0'*12+b'\x08\x00'+ip+tcp
def capture(frames,endian='<',nano=False):
    magic=(b'\x4d\x3c\xb2\xa1' if nano else b'\xd4\xc3\xb2\xa1') if endian=='<' else (b'\xa1\xb2\x3c\x4d' if nano else b'\xa1\xb2\xc3\xd4')
    return magic+struct.pack(endian+'HHiiII',2,4,0,0,65535,1)+b''.join(struct.pack(endian+'IIII',10,i,len(f),len(f))+f for i,f in enumerate(frames))
class Contract(unittest.TestCase):
    def test_accounting(self):
        r=ledger(capture([packet()]));self.assertEqual(r['packets'],1);self.assertEqual(r['wire_bytes'],57);self.assertEqual(r['flows'][0]['directions'][0]['payload_bytes'],3)
    def test_reverse_direction(self):
        r=ledger(capture([packet(),packet(src=b'\xc0\x00\x02\x02',dst=b'\xc0\x00\x02\x01',sp=443,dp=1234,payload=b'xy',flags=1)]))
        self.assertEqual(len(r['flows']),1);self.assertEqual(r['flows'][0]['directions'][1]['fin'],1)
    def test_retransmissions_counted(self):self.assertEqual(ledger(capture([packet(),packet()]))['flows'][0]['directions'][0]['payload_bytes'],6)
    def test_big_endian(self):self.assertEqual(ledger(capture([packet()],endian='>'))['wire_bytes'],57)
    def test_nanosecond(self):self.assertEqual(ledger(capture([packet()],nano=True))['timestamp_resolution'],1000000000)
    def test_no_packets(self):self.assertEqual(ledger(capture([]))['flows'],[])
    def test_non_tcp(self):self.assertEqual(ledger(capture([packet(proto=17)]))['skipped']['non_tcp'],1)
    def test_fragments(self):self.assertEqual(ledger(capture([packet(fragment=8192)]))['skipped']['fragmented'],1)
    def test_non_ipv4(self):self.assertEqual(ledger(capture([b'\0'*12+b'\x86\xdd'+b'\0'*40]))['skipped']['non_ipv4'],1)
    def test_truncated_file(self):
        with self.assertRaises(ValueError):ledger(capture([packet()])[:-1])
    def test_truncated_record(self):
        with self.assertRaises(ValueError):ledger(capture([])+b'\0')
    def test_pcapng(self):
        with self.assertRaises(ValueError):ledger(b'\x0a\x0d\x0d\x0a'+b'\0'*20)
    def test_unsupported_link(self):
        p=bytearray(capture([]));p[20:24]=struct.pack('<I',101)
        with self.assertRaises(ValueError):ledger(bytes(p))
    def test_invalid_ip(self):
        p=bytearray(packet());p[14]=64
        with self.assertRaises(ValueError):ledger(capture([bytes(p)]))
    def test_snaplen_truncation(self):
        p=bytearray(capture([packet()]));p[36:40]=struct.pack('<I',100)
        with self.assertRaises(ValueError):ledger(bytes(p))
    def test_payload_not_exposed(self):self.assertNotIn('PRIVATE_PAYLOAD',str(ledger(capture([packet(payload=b'PRIVATE_PAYLOAD')]))))
