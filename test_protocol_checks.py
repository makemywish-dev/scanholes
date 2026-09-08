import contextlib
import io
import json
import socket
import socketserver
import struct
import threading
import unittest
from unittest.mock import Mock,patch
import protocol_checks as pc
import scanner_engine as se


class FakeSocket:
    def __init__(self,data,fragment=3):self.data=data;self.sent=[];self.fragment=fragment;self.closed=False
    def recv(self,n):
        part=self.data[:min(n,self.fragment)];self.data=self.data[len(part):];return part
    def sendall(self,data):self.sent.append(data)
    def settimeout(self,timeout):pass
    def close(self):self.closed=True


def run(protocol,data,port=12345):
    sock=FakeSocket(data)
    with patch('socket.create_connection',return_value=sock):
        result=pc.audit(protocol,'127.0.0.1',port,timeout=.2)
    assert sock.closed
    return result,b''.join(sock.sent)


def smb_response(security=1,status=0):
    header=struct.pack('<4sHHIHHIIQIIQ16s',b'\xfeSMB',64,0,status,0,1,1,0,0,0,0,0,bytes(16))
    body=struct.pack('<HHH',65,security,0x302)+bytes(58)
    payload=header+body
    return len(payload).to_bytes(4,'big')+payload


def rdp_response(kind=2,selected=1):
    return b'\x03\x00\x00\x13\x0e\xd0\x00\x00\x00\x00\x00'+struct.pack('<BBHI',kind,0,8,selected)


class ProtocolTests(unittest.TestCase):
    def test_vnc_none_offered_no_session_started(self):
        result,sent=run('vnc',b'RFB 003.008\n\x02\x01\x02')
        self.assertEqual(result.checks[0]['status'],'POTENTIAL')
        self.assertEqual(result.checks[0]['risk'],'HIGH')
        self.assertEqual(sent,b'RFB 003.008\n')

    def test_vnc_password_offer_not_none(self):
        result,_=run('vnc',b'RFB 003.008\n\x01\x02')
        self.assertEqual(result.checks[0]['status'],'PASS')

    def test_vnc_33_none(self):
        result,_=run('vnc',b'RFB 003.003\n\x00\x00\x00\x01')
        self.assertEqual(result.checks[0]['status'],'POTENTIAL')

    def test_vnc_bad_response_unknown(self):
        result,_=run('vnc',b'RFB 003.008\n\xff')
        self.assertEqual(result.checks[-1]['status'],'UNKNOWN')
        self.assertFalse(any(c['risk'] for c in result.checks))

    def test_smb_request_is_negotiate_only(self):
        data=pc.smb_request()
        self.assertEqual(int.from_bytes(data[:4],'big'),len(data)-4)
        self.assertEqual(data[4:8],b'\xfeSMB')
        self.assertEqual(struct.unpack_from('<H',data,16)[0],0)
        self.assertEqual(struct.unpack_from('<H',data,68)[0],36)
        self.assertEqual(struct.unpack_from('<H',data,70)[0],3)

    def test_smb_optional_signing(self):
        result,sent=run('smb',smb_response(1))
        self.assertEqual(result.checks[0]['risk'],'MEDIUM')
        self.assertFalse(result.metadata['signing_required'])
        self.assertEqual(len(sent),110)

    def test_smb_required_signing(self):
        result,_=run('smb',smb_response(3))
        self.assertEqual(result.checks[0]['status'],'PASS')

    def test_smb_error_not_signing_finding(self):
        result,_=run('smb',smb_response(0,status=0xc000000d))
        self.assertFalse(result.confirmed)
        self.assertEqual(result.checks[0]['status'],'UNKNOWN')

    def test_rdp_tls_selected_is_candidate_only(self):
        result,sent=run('rdp',rdp_response())
        self.assertEqual(result.checks[0]['status'],'POTENTIAL')
        self.assertEqual(len(sent),19)

    def test_rdp_hybrid_required(self):
        result,_=run('rdp',rdp_response(3,5))
        self.assertEqual(result.checks[0]['status'],'PASS')

    def test_rdp_malformed_not_nla_finding(self):
        result,_=run('rdp',b'\x03\x00\x00\x13'+b'X'*15)
        self.assertFalse(result.confirmed)
        self.assertEqual(result.checks[0]['status'],'UNKNOWN')

    def test_mqtt_clean_anonymous_connect_then_disconnect(self):
        result,sent=run('mqtt',b'\x20\x02\x00\x00')
        self.assertEqual(result.checks[0]['risk'],'MEDIUM')
        self.assertEqual(sent[0],0x10)
        self.assertEqual(sent[9],2) # Clean session, no username/password/Will.
        self.assertTrue(sent.endswith(b'\xe0\x00'))
        self.assertEqual(len(sent),sent[1]+4)

    def test_mqtt_anonymous_rejected(self):
        result,_=run('mqtt',b'\x20\x02\x00\x05')
        self.assertEqual(result.checks[0]['status'],'PASS')

    def test_mqtt_unavailable_not_auth_failure(self):
        result,_=run('mqtt',b'\x20\x02\x00\x03')
        self.assertEqual(result.checks[0]['status'],'UNKNOWN')

    def test_redis_version_metadata_only(self):
        data=b'# Server\r\nredis_version:7.2.5\r\n'
        result,sent=run('redis',b'+PONG\r\n$'+str(len(data)).encode()+b'\r\n'+data+b'\r\n')
        self.assertEqual(result.version,'7.2.5')
        self.assertEqual(result.checks[0]['risk'],'LOW')
        self.assertEqual(sent,b'*1\r\n$4\r\nPING\r\n*2\r\n$4\r\nINFO\r\n$6\r\nserver\r\n')

    def test_redis_noauth_no_more_commands(self):
        result,sent=run('redis',b'-NOAUTH Authentication required.\r\n')
        self.assertEqual(result.checks[0]['status'],'PASS')
        self.assertNotIn(b'INFO',sent)

    def test_redis_ping_does_not_imply_data_access(self):
        result,_=run('redis',b'+PONG\r\n-NOPERM this user cannot run info\r\n')
        self.assertFalse(any(c['risk'] for c in result.checks))

    def test_redis_big_response_rejected(self):
        result,_=run('redis',b'+PONG\r\n$999999999\r\n')
        self.assertEqual(result.checks[-1]['status'],'UNKNOWN')

    def test_ftp_no_tls_without_attempting_login(self):
        result,sent=run('ftp',b'220 FTP server ready\r\n211 No features\r\n502 Not implemented\r\n')
        self.assertEqual(result.checks[0]['risk'],'MEDIUM')
        self.assertEqual(sent,b'FEAT\r\nAUTH TLS\r\n')

    def test_ftp_nonftp_220_not_vulnerability(self):
        result,_=run('ftp',b'220 hello\r\n500 unknown command\r\n')
        self.assertFalse(result.confirmed)
        self.assertFalse(any(c['risk'] for c in result.checks))

    def test_ftp_starttls_handshake(self):
        sock=FakeSocket(b'220 FTP ready\r\n211 No features\r\n234 Ready for TLS\r\n')
        with patch('socket.create_connection',return_value=sock),patch.object(pc.Channel,'upgrade_tls',return_value='TLSv1.3') as tls:
            result=pc.audit('ftp','127.0.0.1',21,.2)
        self.assertTrue(result.metadata['starttls'])
        tls.assert_called_once()

    def test_smtp_plain_auth_advertisement_is_candidate(self):
        result,sent=run('smtp',b'220 mail ESMTP\r\n250-mail\r\n250 AUTH PLAIN LOGIN\r\n')
        self.assertEqual(result.checks[0]['status'],'POTENTIAL')
        self.assertEqual(sent,b'EHLO audit.invalid\r\n')

    def test_smtp_starttls(self):
        sock=FakeSocket(b'220 mail ESMTP\r\n250-mail\r\n250 STARTTLS\r\n220 Ready\r\n')
        with patch('socket.create_connection',return_value=sock),patch.object(pc.Channel,'upgrade_tls',return_value='TLSv1.3'):
            result=pc.audit('smtp','127.0.0.1',25,.2)
        self.assertTrue(result.metadata['starttls'])
        self.assertFalse(any(c['risk'] for c in result.checks))

    def test_nats_missing_auth_not_assumed_disabled(self):
        result,sent=run('nats',b'INFO {"server_id":"test","version":"2.10.1"}\r\n')
        self.assertEqual(result.checks[0]['status'],'UNKNOWN')
        self.assertEqual(sent,b'')

    def test_nats_explicit_false_candidate(self):
        result,_=run('nats',b'INFO {"server_id":"test","auth_required":false}\r\n')
        self.assertEqual(result.checks[0]['status'],'POTENTIAL')

    def test_memcached_metadata_not_data_access(self):
        result,sent=run('memcached',b'VERSION 1.6.22\r\n')
        self.assertEqual(result.version,'1.6.22')
        self.assertEqual(result.checks[0]['status'],'PASS')
        self.assertEqual(sent,b'version\r\n')

    def test_rtsp_options_not_stream_access(self):
        result,sent=run('rtsp',b'RTSP/1.0 200 OK\r\nCSeq: 1\r\nPublic: OPTIONS, DESCRIBE\r\n\r\n')
        self.assertEqual(result.checks[0]['status'],'PASS')
        self.assertNotIn(b'DESCRIBE',sent)

    def test_rtsp_wrong_cseq_unknown(self):
        result,_=run('rtsp',b'RTSP/1.0 200 OK\r\nCSeq: 99\r\n\r\n')
        self.assertEqual(result.checks[0]['status'],'UNKNOWN')

    def test_cancellation_before_connect(self):
        cancel=threading.Event();cancel.set()
        with patch('socket.create_connection') as connect:result=pc.audit('mqtt','127.0.0.1',1883,cancel=cancel)
        connect.assert_not_called()
        self.assertEqual(result.checks[0]['status'],'UNKNOWN')

    def test_service_map_validation(self):
        self.assertEqual(se.ScannerEngineV6('127.0.0.1',service_map='1884=mqtt').service_hints,{1884:'mqtt'})
        for mapping in ('0=mqtt','99999=rdp','80=something','80:mqtt'):
            with self.assertRaises(ValueError):se.ScannerEngineV6('127.0.0.1',service_map=mapping)


class MqttHandler(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(2)
        # Discovery TCP connect does not send bytes; a protocol probe does.
        header=self.request.recv(2)
        if len(header)!=2:return
        data=bytearray()
        while len(data)<header[1]:
            part=self.request.recv(header[1]-len(data))
            if not part:return
            data.extend(part)
        self.request.sendall(b'\x20\x02\x00\x00')
        self.request.recv(2)


class PipelineTests(unittest.TestCase):
    def test_universal_nonstandard_mqtt_pipeline(self):
        with socketserver.ThreadingTCPServer(('127.0.0.1',0),MqttHandler) as server:
            server.daemon_threads=True
            thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
            port=server.server_address[1]
            engine=se.ScannerEngineV6('127.0.0.1',ports=str(port),service_map=f'{port}=mqtt',timeout=.2)
            try:
                with patch.object(engine,'_get_ttl',return_value=None),contextlib.redirect_stdout(io.StringIO()):
                    result=engine.scan()
                self.assertEqual(result.stats['status'],'completed')
                self.assertEqual(result.services[0].service,'mqtt')
                self.assertEqual(result.vulnerabilities[0].id,'MQTT-ANONYMOUS')
                self.assertEqual(result.stats['protocol_modules'],['mqtt'])
            finally:
                server.shutdown();thread.join()


if __name__=='__main__':unittest.main()
