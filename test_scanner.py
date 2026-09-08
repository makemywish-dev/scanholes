"""Regression tests. Only loopback listeners and mocked network/API responses."""
import contextlib
import http.server
import io
import json
from pathlib import Path
import socket
import ssl
import subprocess
import tempfile
import threading
import unittest
from unittest.mock import Mock, patch
import scanner_engine as se


def service(port=80, address='127.0.0.1', protocol=se.ServiceProtocol.TCP):
    return se.Service(address,port,protocol,se.PortState.OPEN)


class ScannerTests(unittest.TestCase):
    def setUp(self):
        self.e = se.ScannerEngineV6('127.0.0.1',timeout=0.2,max_workers=2)
        self.quiet = contextlib.redirect_stdout(io.StringIO())
        self.quiet.__enter__()

    def tearDown(self):
        self.quiet.__exit__(None,None,None)

    def test_ports_and_validation(self):
        self.assertEqual(self.e.parse_ports('443,22,22,8000-8002'),[22,443,8000,8001,8002])
        for spec in ('','0','65536','5-2','22,','x','-1'):
            with self.assertRaises(ValueError): self.e.parse_ports(spec)
        for kwargs in ({'timeout':float('nan')},{'max_workers':0},{'max_hosts':0}):
            with self.assertRaises(ValueError): se.ScannerEngineV6('127.0.0.1',**kwargs)

    def test_ipv6_large_subnet_rejected(self):
        for cidr in ('2001:db8::/64','2001:db8::/65','2001:db8::/112','10.0.0.0/8'):
            with self.assertRaises(ValueError): self.e._resolve_target(cidr)

    def test_small_cidrs_and_single_ips(self):
        for cidr,count in [('127.0.0.1',1),('::1',1),('192.0.2.0/31',2),('2001:db8::/127',2),('2001:db8::/128',1)]:
            self.assertEqual(len(self.e._resolve_target(cidr)),count)

    def test_url_preserves_host_port(self):
        with patch.object(self.e,'_resolve_host',return_value=[]):
            self.e._resolve_target('https://example.test:18443/admin')
        self.assertEqual(self.e._server_name('127.0.0.1'),'example.test')
        self.assertEqual(self.e._target.port,18443)
        self.assertEqual(self.e._target.scheme,'https')

    def test_bad_targets(self):
        for target in ('https://u:p@example.test','ftp://example.test','https://example.test:70000','https://example.test:0','hello\r\nX:foo'):
            with self.assertRaises(ValueError): self.e._resolve_target(target)

    def test_failed_scan_finalized(self):
        self.e.target_str = '2001:db8::/65'
        result = self.e.scan()
        self.assertTrue(result.end_time)
        self.assertTrue(result.errors)
        self.assertEqual(result.stats['status'],'completed_with_errors')

    def test_cancelled_scan_finalized(self):
        self.e.cancel()
        result = self.e.scan()
        self.assertTrue(result.end_time)
        self.assertEqual(result.stats['status'],'cancelled')

    def test_discovery_udp_every_address_and_extended_ports(self):
        self.e.mode = se.ScanMode.EXTENDED
        self.e.udp_enabled = True
        addresses = [se.ResolvedAddress('192.0.2.'+str(i),socket.AF_INET,False) for i in (1,2)]
        with patch.object(self.e,'_probe_tcp',return_value=None) as tcp, patch.object(self.e,'_probe_udp',return_value=None) as udp:
            self.e._discover(addresses)
        self.assertEqual(udp.call_count,4)
        ports = {call.args[1] for call in tcp.call_args_list}
        self.assertTrue({5555,62078,9100,1883,554}.issubset(ports))

    def test_discovery_stops_scheduling_after_cancel(self):
        self.e.custom_ports = list(range(1,101))
        def probe(a,p):
            self.e.cancel()
        with patch.object(self.e,'_probe_tcp',side_effect=probe) as tcp:
            self.e._discover([se.ResolvedAddress('127.0.0.1',socket.AF_INET,False)])
        self.assertLessEqual(tcp.call_count,2)

    def test_udp_not_tcp_fingerprinted(self):
        with patch.object(self.e,'_check_tls') as check:
            self.e._fingerprint_single(service(53,protocol=se.ServiceProtocol.UDP))
        check.assert_not_called()

    def test_tls_mail_not_https(self):
        with patch.object(self.e,'_check_tls',return_value=True), patch.object(self.e,'_http_request') as http:
            result = self.e._fingerprint_single(service(993))
        self.assertEqual(result.service,'imaps')
        http.assert_not_called()

    def test_version_is_product_bound(self):
        self.assertEqual(self.e._extract_version('SSH-2.0-OpenSSH_9.6p1 Ubuntu-3',['OpenSSH']),'9.6p1')
        self.assertEqual(self.e._extract_version('HTTP/1.1 200 OK Server: nginx/1.24.0',['nginx']),'1.24.0')

    def test_open_ports_do_not_claim_nla_or_smbv1(self):
        self.e.result.services = [service(3389),service(445)]
        self.e._check_configuration()
        self.assertTrue(all(v.risk==se.RiskLevel.INFO for v in self.e.result.vulnerabilities))

    def test_soft404_does_not_become_git_finding(self):
        web=se.WebService('127.0.0.1',80,'http','http://127.0.0.1:80/')
        with patch.object(self.e,'_http_request',return_value=(200,{},b'<html>Welcome KEY</html>')):
            self.assertIsNone(self.e._check_path(web,'/.git/HEAD',{}))
            self.assertIsNone(self.e._check_path(web,'/.env',{}))
        with patch.object(self.e,'_http_request',return_value=(200,{},b'ref: refs/heads/main\n')):
            self.assertIsNotNone(self.e._check_path(web,'/.git/HEAD',{}))

    def test_no_cve_lookup_without_opt_in(self):
        with patch('urllib.request.urlopen') as network:
            self.assertEqual(self.e._get_cves_cpe('nginx','1.24.0'),[])
        network.assert_not_called()

    def test_nvd_encoded_cpe_cvss_and_cache(self):
        self.e.cve_lookup=True
        self.e._cve_cache=Mock()
        self.e._cve_cache.get.return_value=None
        response=Mock()
        response.__enter__=Mock(return_value=response)
        response.__exit__=Mock(return_value=False)
        response.read.return_value=json.dumps({'totalResults':1,'vulnerabilities':[{'cve':{
            'id':'CVE-2024-12345','metrics':{'cvssMetricV31':[{'cvssData':{'baseScore':7.5}}]}}}]}).encode()
        with patch('urllib.request.urlopen',return_value=response) as call:
            records=self.e._get_cves_cpe('nginx','1.24.0')
        self.assertEqual(records[0]['cvss'],7.5)
        self.assertIn('cpeName=cpe%3A2.3%3Aa%3Anginx',call.call_args.args[0].full_url)
        self.e._cve_cache.set.assert_called_once()

    def test_nvd_failure_not_cached_or_retried_forever(self):
        self.e.cve_lookup=True
        self.e._cve_cache=Mock()
        self.e._cve_cache.get.return_value=None
        with patch('urllib.request.urlopen',side_effect=se.urllib.error.HTTPError('test',429,'limited',{},None)) as call:
            self.assertEqual(self.e._get_cves_cpe('nginx','1.24.0'),[])
        self.assertEqual(call.call_count,1)
        self.e._cve_cache.set.assert_not_called()
        self.assertTrue(self.e.result.errors)

    def test_reports_preserve_status_and_escape(self):
        result=se.ScanResult('<script>alert(1)</script>',stats={'status':'cancelled'})
        result.services=[service()]
        with tempfile.TemporaryDirectory() as tmp:
            html=Path(tmp)/'report.html'; data=Path(tmp)/'report.json'
            se.generate_html_report(result,str(html)); se.generate_json_report(result,str(data))
            self.assertNotIn('<script>',html.read_text())
            self.assertIn('cancelled',html.read_text())
            self.assertEqual(json.loads(data.read_text())['services'][0]['protocol'],'tcp')

    def test_certificate_failure_is_a_finding(self):
        exc=ssl.SSLCertVerificationError(1,'certificate expired')
        exc.verify_code=10;exc.verify_message='certificate has expired'
        ctx=Mock();ctx.wrap_socket.side_effect=exc
        with patch('ssl.create_default_context',return_value=ctx),patch('socket.create_connection'):
            self.e._check_certificate(service(443))
        self.assertEqual(len(self.e.result.vulnerabilities),1)
        self.assertIn('expired',self.e.result.vulnerabilities[0].description)


class Handler(http.server.BaseHTTPRequestHandler):
    hosts=[]
    def log_message(self,*args): pass
    def do_GET(self):
        type(self).hosts.append(self.headers.get('Host'))
        status=302 if self.path=='/redirect' else 401
        self.send_response(status)
        self.send_header('Location','http://outside.invalid/')
        self.send_header('Server','nginx/1.24.0')
        self.end_headers()
        self.wfile.write(b'Authentication required')


class LoopbackTests(unittest.TestCase):
    def test_http_and_https_preserve_status_host_and_sni(self):
        with tempfile.TemporaryDirectory() as tmp:
            key=Path(tmp)/'key.pem';cert=Path(tmp)/'cert.pem'
            subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-days','1',
                            '-keyout',str(key),'-out',str(cert),'-subj','/CN=example.test'],
                           check=True,capture_output=True)
            for tls in (False,True):
                server=http.server.ThreadingHTTPServer(('127.0.0.1',0),Handler)
                seen_sni=[]
                if tls:
                    ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                    ctx.load_cert_chain(cert,key)
                    ctx.set_servername_callback(lambda sock,name,ctx:seen_sni.append(name))
                    server.socket=ctx.wrap_socket(server.socket,server_side=True)
                thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
                try:
                    port=server.server_port;scheme='https' if tls else 'http'
                    engine=se.ScannerEngineV6(f'{scheme}://example.test:{port}',timeout=1)
                    engine._target=se.Target(engine.target_str,'example.test',port,scheme,is_hostname=True,is_url=True)
                    status,headers,body=engine._http_request('127.0.0.1',port,scheme,'/redirect')
                    self.assertEqual(status,302)  # Never follows outside scope.
                    self.assertEqual(Handler.hosts[-1],f'example.test:{port}')
                    svc=service(port);svc.service=scheme
                    web=engine._fingerprint_web_single(svc)
                    self.assertEqual(web.status_code,401)
                    self.assertIn('nginx',web.server)
                    if tls:self.assertIn('example.test',seen_sni)
                finally:
                    server.shutdown();server.server_close();thread.join()


if __name__=='__main__':
    unittest.main()
