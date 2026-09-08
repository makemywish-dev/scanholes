"""Router-specific regressions; no external network access."""
import contextlib
import http.server
import io
import json
import socket
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import Mock,patch
import scanner_engine as se


def svc(port=80):
    return se.Service('127.0.0.1',port,se.ServiceProtocol.TCP,se.PortState.OPEN)


class KeeneticTests(unittest.TestCase):
    def setUp(self):
        self.e=se.ScannerEngineV6('127.0.0.1',mode=se.ScanMode.KEENETIC,timeout=.1,max_workers=2)
        self.quiet=contextlib.redirect_stdout(io.StringIO());self.quiet.__enter__()

    def tearDown(self):self.quiet.__exit__(None,None,None)

    def identify(self,version='4.2.1',model='KN-1010'):
        self.e.result.resolved_addresses=['127.0.0.1']
        self.e._observe_keenetic('127.0.0.1',json.dumps({'product':'Keenetic','model':model,'release':version}),{},'GET /version.js')

    def test_port_443_timeout_not_https_or_certificate_finding(self):
        with patch.object(self.e,'_http_request',side_effect=socket.timeout('slow')),patch.object(self.e,'_check_tls',return_value=False):
            result=self.e._fingerprint_single(svc(443))
        self.assertEqual(result.service,'unknown')
        self.e.result.services=[result]
        with patch.object(self.e,'_check_certificate') as cert:
            self.e._scan_tls()
        cert.assert_not_called()
        self.assertTrue(any(c['status']=='UNKNOWN' for c in self.e.result.checks))

    def test_tls_without_http_keeps_tls_type(self):
        with patch.object(self.e,'_http_request',side_effect=se.http.client.BadStatusLine('mail')),patch.object(self.e,'_check_tls',return_value=True):
            result=self.e._fingerprint_single(svc(443))
        self.assertEqual(result.service,'tls')
        self.assertTrue(result.extra['tls'])

    def test_telnet_fragmented_negotiation_sends_no_credentials(self):
        sock=Mock();sock.__enter__=Mock(return_value=sock);sock.__exit__=Mock(return_value=False)
        sock.recv.side_effect=[b'\xff',b'\xfb',b'\x01\xff\xfd\x18',b'Keenetic KN-1010\r\nLogin:']
        with patch('socket.create_connection',return_value=sock):
            result=self.e._fingerprint_telnet(svc(23))
        self.assertTrue(result.extra['telnet_confirmed'])
        self.assertIn('Login:',result.banner)
        sent=b''.join(c.args[0] for c in sock.sendall.call_args_list)
        self.assertEqual(sent,b'\xff\xfe\x01\xff\xfc\x18')
        self.assertEqual(self.e.result.vulnerabilities[0].id,'TELNET-CLEARTEXT')

    def test_plain_login_on_port_23_not_telnet_confirmation(self):
        sock=Mock();sock.__enter__=Mock(return_value=sock);sock.__exit__=Mock(return_value=False)
        sock.recv.return_value=b'Login:'
        with patch('socket.create_connection',return_value=sock):
            result=self.e._fingerprint_telnet(svc(23))
        self.assertFalse(result.extra['telnet_confirmed'])
        self.assertFalse(self.e.result.vulnerabilities)

    def test_product_version_not_javascript_library(self):
        self.e._observe_keenetic('127.0.0.1','<title>Keenetic</title><script>jquery.version="1.2.3"</script>',{},'http root page')
        self.assertEqual(self.e._identity('127.0.0.1')['version'],'')
        self.identify('4.2.1')
        self.assertEqual(self.e._identity('127.0.0.1')['version'],'4.2.1')

    def test_conflicting_firmware_not_silently_selected(self):
        self.identify('4.2.1');self.identify('5.0.4')
        self.e._check_keenetic_advisories()
        self.assertTrue(self.e._identity('127.0.0.1')['conflict'])
        self.assertFalse(self.e.result.vulnerabilities)

    def test_exact_version_boundaries_and_prereleases(self):
        cases=[('4.2.9','4.3.0',False,True),('4.3.0','4.3.0',False,False),
               ('4.3','4.3.2',False,None),('4.3.2','4.3.2',False,False),
               ('4.1.2','4.1.2.15',True,None),('4.1.2.15','4.1.2.15',True,True),
               ('4.1.2.16','4.1.2.15',True,False),('4.3.0-alpha','4.3.0',False,None)]
        for value,bound,inclusive,expected in cases:
            with self.subTest(value=value,bound=bound):
                self.assertIs(self.e._version_in_range(value,bound,inclusive),expected)

    def test_version_candidates_without_online_api(self):
        self.identify('4.2.1')
        with patch('urllib.request.urlopen') as network:self.e._check_keenetic_advisories()
        network.assert_not_called()
        ids={v.id for v in self.e.result.vulnerabilities}
        self.assertIn('CVE-2025-56007',ids)
        self.assertNotIn('CVE-2024-4021',ids)
        self.assertTrue(all(v.status==se.FindingStatus.POTENTIALLY_VULNERABLE for v in self.e.result.vulnerabilities))

    def test_fixed_firmware_has_no_catalog_candidates(self):
        self.identify('5.0.4')
        self.e._check_keenetic_advisories()
        self.assertFalse(self.e.result.vulnerabilities)

    def test_unknown_model_does_not_get_model_specific_cves(self):
        self.identify('4.1.2.15','KN-9999')
        self.e._check_keenetic_advisories()
        self.assertNotIn('CVE-2024-4021',{v.id for v in self.e.result.vulnerabilities})

    def test_profile_alone_not_vendor_detection(self):
        self.e.result.resolved_addresses=['127.0.0.1']
        self.e._check_keenetic_advisories()
        self.assertFalse(self.e.result.vulnerabilities)
        self.assertTrue(any(c['id']=='KEENETIC-IDENTITY' and c['status']=='UNKNOWN' for c in self.e.result.checks))

    def test_protected_metadata_not_reported_exposed(self):
        web=se.WebService('127.0.0.1',80,'http','http://127.0.0.1:80/')
        self.e.result.web_services=[web]
        with patch.object(self.e,'_http_request',return_value=(401,{},b'')) as request:
            self.e._probe_keenetic_web()
        self.assertEqual(request.call_count,4)
        self.assertFalse(self.e.result.vulnerabilities)
        self.assertTrue(all(c['status']=='PASS' for c in self.e.result.checks))

    def test_missing_security_headers_only_low_and_http_admin_medium(self):
        self.identify()
        web=se.WebService('127.0.0.1',80,'http','http://127.0.0.1/',status_code=200,
                          extra={'html':True,'password_form':True})
        self.e._check_web_security(web)
        ids={v.id:v.risk for v in self.e.result.vulnerabilities}
        self.assertEqual(ids['HTTP-ADMIN-CLEARTEXT'],se.RiskLevel.MEDIUM)
        self.assertEqual(ids['WEB-NOSNIFF'],se.RiskLevel.LOW)
        self.assertNotIn('WEB-HSTS',ids)

    def test_security_headers_and_ip_hsts_exemption(self):
        web=se.WebService('127.0.0.1',443,'https','https://127.0.0.1/',status_code=200,is_https=True,
             headers={'x-frame-options':'DENY','x-content-type-options':'nosniff'},extra={'html':True})
        self.e._check_web_security(web)
        self.assertFalse(self.e.result.vulnerabilities)
        self.assertTrue(any(c['id']=='WEB-HSTS' and c['status']=='SKIPPED' for c in self.e.result.checks))

    def test_cookie_values_not_in_reports(self):
        service=svc();service.service='http'
        headers={'content-type':'text/html','set-cookie':'session=TOP_SECRET; Path=/\nlang=ru; Path=/'}
        with patch.object(self.e,'_http_request',return_value=(200,headers,b'<title>Keenetic</title>')):
            web=self.e._fingerprint_web_single(service)
        self.e.result.web_services=[web]
        self.assertEqual(len(web.extra['cookies']),2)
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/'out.json';se.generate_json_report(self.e.result,str(path))
            self.assertNotIn('TOP_SECRET',path.read_text())
            self.assertEqual(web.title,'Keenetic')

    def test_manual_hints_on_subnet_rejected(self):
        engine=se.ScannerEngineV6('192.0.2.0/30',device_model='KN-1010',firmware='4.2.1')
        with patch.object(engine,'_discover') as discovery:
            result=engine.scan()
        discovery.assert_not_called()
        self.assertTrue(result.errors)

    def test_html_escapes_remote_title_banner_and_references(self):
        self.e.result.services=[svc()]
        self.e.result.services[0].banner='<img src=x onerror=alert(1)>'
        self.e.result.web_services=[se.WebService('127.0.0.1',80,'http','http://127.0.0.1/',title='<script>alert(1)</script>')]
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/'out.html';se.generate_html_report(self.e.result,str(path))
            html=path.read_text()
        self.assertNotIn('<script>',html);self.assertNotIn('<img',html)
        self.assertIn('&lt;script&gt;',html)


class KeeneticLikeHandler(http.server.BaseHTTPRequestHandler):
    calls=[]
    def log_message(self,*args):pass
    def do_GET(self):
        type(self).calls.append(self.path)
        if self.path=='/':
            status=200;data=b'<html><title>Keenetic Lab</title><input type="password"></html>'
            content_type='text/html'
        elif self.path=='/version.js':
            status=200;data=b'var version={"vendor":"Keenetic", "model":"KN-1010", "release":"4.2.1"};'
            content_type='application/javascript'
        else:
            status=401;data=b'';content_type='text/plain'
        self.send_response(status);self.send_header('Content-Type',content_type);self.end_headers();self.wfile.write(data)


class PipelineTests(unittest.TestCase):
    def test_full_loopback_pipeline_identity_cves_report(self):
        server=http.server.ThreadingHTTPServer(('127.0.0.1',0),KeeneticLikeHandler)
        thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
        try:
            port=server.server_port
            engine=se.ScannerEngineV6(f'http://127.0.0.1:{port}',mode=se.ScanMode.KEENETIC,
                                     ports=str(port),timeout=.2,max_workers=1)
            with patch.object(engine,'_get_ttl',return_value=64),contextlib.redirect_stdout(io.StringIO()):
                result=engine.scan()
            self.assertEqual(result.stats['status'],'completed')
            self.assertEqual(result.devices[0].os_name,'KeeneticOS')
            self.assertEqual(result.devices[0].os_version,'4.2.1')
            self.assertEqual(result.web_services[0].title,'Keenetic Lab')
            self.assertIn('CVE-2025-56007',{v.id for v in result.vulnerabilities})
            self.assertEqual(KeeneticLikeHandler.calls.count('/'),1) # cached page avoids repeated requests.
            self.assertGreater(len(result.checks),15)
            with tempfile.TemporaryDirectory() as tmp:
                with contextlib.redirect_stdout(io.StringIO()):
                    se.generate_html_report(result,str(Path(tmp)/'report.html'))
                    se.generate_json_report(result,str(Path(tmp)/'report.json'))
                self.assertIn('Keenetic Lab',(Path(tmp)/'report.html').read_text())
        finally:
            server.shutdown();server.server_close();thread.join()


if __name__=='__main__':unittest.main()
