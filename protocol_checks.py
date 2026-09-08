"""Bounded protocol checks for authorized network audits. No exploit payloads or data access.

All modules return observations. A successful metadata command is never treated as
proof that application data can be read or modified. See README for scope/sources.
"""
import json
import os
import re
import socket
import ssl
import struct
import time
from dataclasses import dataclass, field


class ProbeError(ValueError):
    pass


@dataclass
class Outcome:
    protocol: str
    confirmed: bool = False
    product: str = ''
    version: str = ''
    banner: str = ''
    tls: bool = False
    checks: list = field(default_factory=list)
    metadata: dict = field(default_factory=dict)

    def record(self, code, status, detail, risk='', remediation='', references=()):
        self.checks.append(dict(id=code,status=status,detail=detail,risk=risk,
                                remediation=remediation,references=list(references)))


class Channel:
    """Single connection, shared wall-clock budget and bounded reads."""
    def __init__(self,address,port,timeout,cancel=None):
        self.deadline=time.monotonic()+max(.1,timeout)*3
        self.timeout=timeout
        self.cancel=cancel
        self.sock=socket.create_connection((address,port),timeout=timeout)
        self.buffer=bytearray()

    def __enter__(self):return self
    def __exit__(self,*args):self.sock.close()

    def budget(self):
        if self.cancel and self.cancel.is_set():raise ProbeError('Проверка отменена')
        left=self.deadline-time.monotonic()
        if left<=0:raise TimeoutError('Исчерпан бюджет проверки')
        self.sock.settimeout(min(self.timeout,left))

    def send(self,data):
        self.budget();self.sock.sendall(data)

    def exact(self,n):
        if not 0<=n<=16384:raise ProbeError('Размер сообщения вне допустимого диапазона')
        while len(self.buffer)<n:
            self.budget()
            data=self.sock.recv(min(4096,n-len(self.buffer)))
            if not data:raise ProbeError('Неполный ответ / соединение закрыто')
            self.buffer.extend(data)
        data=bytes(self.buffer[:n]);del self.buffer[:n]
        return data

    def line(self,limit=4096):
        while b'\n' not in self.buffer:
            if len(self.buffer)>=limit:raise ProbeError('Строка ответа слишком длинная')
            self.budget();data=self.sock.recv(min(1024,limit-len(self.buffer)))
            if not data:raise ProbeError('Неполная строка ответа')
            self.buffer.extend(data)
        end=self.buffer.index(b'\n')+1
        if end>limit:raise ProbeError('Строка ответа слишком длинная')
        result=bytes(self.buffer[:end]);del self.buffer[:end]
        return result

    def upgrade_tls(self,name):
        if self.buffer:raise ProbeError('Лишние данные перед TLS handshake')
        self.budget()
        ctx=ssl.create_default_context()
        ctx.check_hostname=False;ctx.verify_mode=ssl.CERT_NONE
        # Verification is a separate check. No credentials/application data follow.
        self.sock=ctx.wrap_socket(self.sock,server_hostname=name)
        return self.sock.version()


def response_code(ch,limit=40):
    first=ch.line()
    if not re.match(rb'^[1-5][0-9]{2}[ -]',first):raise ProbeError('Неверный ответ текстового протокола')
    code=int(first[:3]);lines=[first]
    if first[3:4]==b'-':
        for _ in range(limit):
            line=ch.line();lines.append(line)
            if line.startswith(first[:3]+b' '):break
        else:raise ProbeError('Слишком длинный многострочный ответ')
    return code,b''.join(lines).decode('utf-8',errors='replace')


def probe_vnc(ch,out,name):
    banner=ch.exact(12)
    if not re.fullmatch(rb'RFB 003\.(?:003|007|008)\n',banner):raise ProbeError('Неподдерживаемая версия RFB')
    out.confirmed=True;out.banner=banner.decode().strip()
    ch.send(banner)
    if banner==b'RFB 003.003\n':
        types=[struct.unpack('>I',ch.exact(4))[0]]
        if types[0]==0:raise ProbeError('RFB отказал в согласовании безопасности')
    else:
        count=ch.exact(1)[0]
        if not 1<=count<=64:raise ProbeError('RFB: отсутствует допустимый список SecurityTypes')
        types=list(ch.exact(count))
        if 0 in types:raise ProbeError('RFB: недопустимый SecurityType 0')
    out.metadata['security_types']=types
    if 1 in types:
        out.record('VNC-NONE-OFFERED','POTENTIAL',
                   'RFB предлагает тип безопасности None. Сеанс рабочего стола не открывался; дополнительный контроль доступа не проверен.',
                   'HIGH','Запретите None и ограничьте VNC доверенной сетью или VPN.',
                   ['https://www.rfc-editor.org/rfc/rfc6143.html'])
    else:out.record('VNC-NONE-OFFERED','PASS','В этом согласовании None не предлагался; это не проверка стойкости пароля.')
    # Do not select a security type or request a framebuffer.


def smb_request():
    header=struct.pack('<4sHHIHHIIQIIQ16s',b'\xfeSMB',64,0,0,0,1,0,0,0,0,0,0,bytes(16))
    body=struct.pack('<HHHHI16sQ',36,3,1,0,0,os.urandom(16),0)+struct.pack('<HHH',0x202,0x210,0x302)
    packet=header+body
    return len(packet).to_bytes(4,'big')+packet


def parse_smb_response(data):
    if len(data)<128 or data[:4]!=b'\xfeSMB' or struct.unpack_from('<H',data,4)[0]!=64:
        raise ProbeError('Не получен полный SMB2 NEGOTIATE')
    status=struct.unpack_from('<I',data,8)[0]
    if status or struct.unpack_from('<H',data,12)[0]!=0 or not struct.unpack_from('<I',data,16)[0]&1:
        raise ProbeError(f'SMB NEGOTIATE не подтверждён (status=0x{status:08x})')
    if struct.unpack_from('<Q',data,24)[0]!=0 or struct.unpack_from('<H',data,64)[0]!=65:
        raise ProbeError('SMB: неверный MessageId/StructureSize')
    security,dialect=struct.unpack_from('<HH',data,66)
    if security & ~3 or dialect not in (0x202,0x210,0x302):
        raise ProbeError('SMB: неожиданное согласование security/dialect')
    return security,dialect


def probe_smb(ch,out,name):
    ch.send(smb_request())
    frame=ch.exact(4)
    if frame[0]!=0:raise ProbeError('Неожиданный тип SMB transport frame')
    security,dialect=parse_smb_response(ch.exact(int.from_bytes(frame[1:],'big')))
    out.confirmed=True;out.banner=f'SMB dialect 0x{dialect:04x}'
    out.metadata.update(dialect=f'0x{dialect:04x}',signing_required=bool(security&2))
    if not security&2:
        out.record('SMB-SIGNING','FINDING','В ответе SMB2 NEGOTIATE сервер не требует подпись. Возможность relay и доступ к общим папкам не проверялись.',
                   'MEDIUM','Включите обязательную подпись SMB с учётом совместимости клиентов.',
                   ['https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/63abf97c-0d09-47e2-88d6-6bfa552949a5'])
    else:out.record('SMB-SIGNING','PASS','В данном согласовании SMB подпись обязательна.')
    # No authentication, tree connect, share enumeration or file operations.


def parse_rdp(data):
    if len(data)!=19 or data[:2]!=b'\x03\x00' or int.from_bytes(data[2:4],'big')!=19 or data[4:6]!=b'\x0e\xd0':
        raise ProbeError('Не получен полный X.224 Connection Confirm с RDP Negotiation')
    kind,flags,length,selected=struct.unpack_from('<BBHI',data,11)
    if kind not in (2,3) or length!=8:raise ProbeError('Неверное поле RDP negotiation')
    return kind,selected


def probe_rdp(ch,out,name):
    ch.send(b'\x03\x00\x00\x13\x0e\xe0\x00\x00\x00\x00\x00'+struct.pack('<BBHI',1,0,8,1))
    head=ch.exact(4);length=int.from_bytes(head[2:4],'big')
    if not 4<=length<=512:raise ProbeError('Неверная длина RDP transport frame')
    kind,selected=parse_rdp(head+ch.exact(length-4))
    out.confirmed=True;out.metadata.update(negotiation_type=kind,selected_or_failure=selected)
    if kind==2 and selected==1:
        out.record('RDP-CREDSSP','POTENTIAL','Сервер выбрал TLS при запросе без CredSSP. Возможен вход без NLA; дальнейшая политика входа не проверялась.',
                   'MEDIUM','Проверьте обязательность NLA и ограничьте RDP через VPN/список доступа.',
                   ['https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/b2975bdc-6d56-49ee-9c57-f2ff3a0b6817'])
    elif kind==3 and selected==5:
        out.record('RDP-CREDSSP','PASS','Сервер отклонил TLS-only с кодом HYBRID_REQUIRED_BY_SERVER.')
    else:out.record('RDP-CREDSSP','UNKNOWN',f'Ответ type={kind}, value={selected}; однозначный вывод о NLA не сделан.')


def probe_mqtt(ch,out,name):
    # New short client ID, clean session, no Will, username/password, topics or retained writes.
    client=('audit'+os.urandom(8).hex()).encode()
    packet=b'\x00\x04MQTT\x04\x02\x00\x0a'+len(client).to_bytes(2,'big')+client
    ch.send(b'\x10'+bytes([len(packet)])+packet)
    reply=ch.exact(4)
    if reply[:2]!=b'\x20\x02' or reply[2]!=0 or reply[3]>5:
        raise ProbeError('Неверный MQTT 3.1.1 CONNACK')
    out.confirmed=True;out.metadata['connack_code']=reply[3]
    if reply[3]==0:
        out.record('MQTT-ANONYMOUS','FINDING','Брокер принял соединение без учётных данных. Права на публикацию и подписку не проверялись.',
                   'MEDIUM','Если анонимные клиенты не нужны, включите аутентификацию и ACL для тем.',
                   ['https://docs.oasis-open.org/mqtt/mqtt/v3.1.1/os/mqtt-v3.1.1-os.html'])
        ch.send(b'\xe0\x00')
    elif reply[3] in (4,5):out.record('MQTT-ANONYMOUS','PASS','Соединение без учётных данных отклонено.')
    else:out.record('MQTT-ANONYMOUS','UNKNOWN',f'CONNACK code={reply[3]} не устанавливает политику аутентификации.')


def resp_string(ch):
    line=ch.line()
    if line[:1] in (b'+',b'-'):return line[:1],line[1:].rstrip(b'\r\n')
    if line.startswith(b'$'):
        try:size=int(line[1:])
        except ValueError:raise ProbeError('Неверная RESP длина')
        if not 0<=size<=8192:raise ProbeError('RESP ответ слишком большой или отсутствует')
        body=ch.exact(size+2)
        if not body.endswith(b'\r\n'):raise ProbeError('RESP: отсутствует завершающий CRLF')
        return b'$',body[:-2]
    raise ProbeError('Ответ не соответствует RESP')


def probe_redis(ch,out,name):
    ch.send(b'*1\r\n$4\r\nPING\r\n');kind,body=resp_string(ch)
    if kind==b'-' and body.startswith((b'NOAUTH',b'NOPERM',b'DENIED')):
        out.confirmed=True;out.product='Redis'
        out.record('REDIS-METADATA','PASS','PING запрещён без дополнительных прав; доступ к ключам не проверялся.')
        return
    if kind!=b'+' or body!=b'PONG':raise ProbeError('Не получен Redis PONG')
    out.confirmed=True;out.product='Redis'
    ch.send(b'*2\r\n$4\r\nINFO\r\n$6\r\nserver\r\n');kind,body=resp_string(ch)
    if kind==b'$':
        match=re.search(rb'(?m)^redis_version:([0-9]+(?:\.[0-9]+)+)\r?$',body)
        if match:out.version=match.group(1).decode()
        out.record('REDIS-METADATA','FINDING','PING и INFO server доступны без входа. Доступ к ключам, CONFIG и административным операциям не проверялся.',
                   'LOW','Проверьте ACL и ограничьте сетевой доступ к Redis.',
                   ['https://redis.io/docs/latest/operate/oss_and_stack/management/security/acl/'])
    elif kind==b'-':out.record('REDIS-METADATA','PASS','PING доступен, но INFO server отклонён; это не доказательство доступа к данным.')
    else:out.record('REDIS-METADATA','UNKNOWN','INFO server вернул неожиданный тип ответа.')


def probe_ftp(ch,out,name):
    code,banner=response_code(ch)
    if code!=220:raise ProbeError('Не получено FTP приветствие 220')
    out.banner=banner[:512]
    ch.send(b'FEAT\r\n');feat_code,_=response_code(ch)
    if feat_code!=211 and not re.search(r'ftp',banner,re.I):
        raise ProbeError('220 без признаков FTP; протокол не подтверждён')
    out.confirmed=True
    ch.send(b'AUTH TLS\r\n');code,_=response_code(ch)
    if code==234:
        version=ch.upgrade_tls(name)
        out.metadata.update(starttls=True,tls_version=version)
        out.record('FTP-AUTH-TLS','PASS','AUTH TLS и TLS handshake успешны. Обязательность TLS и доверие сертификату отдельно не проверялись.')
    elif code in (500,502,504):
        out.record('FTP-AUTH-TLS','FINDING','AUTH TLS не поддержан в этом сеансе. Учётные данные не отправлялись; наличие отдельного FTPS неизвестно.',
                   'MEDIUM','Используйте SFTP/FTPS и ограничьте незашифрованный FTP.',
                   ['https://www.rfc-editor.org/rfc/rfc4217'])
    else:out.record('FTP-AUTH-TLS','UNKNOWN',f'AUTH TLS ответ {code}; причина отказа не установлена.')


def probe_smtp(ch,out,name):
    code,banner=response_code(ch)
    if code!=220:raise ProbeError('Не получено SMTP приветствие 220')
    out.confirmed=True;out.banner=banner[:512]
    ch.send(b'EHLO audit.invalid\r\n');code,reply=response_code(ch)
    if code!=250:raise ProbeError('SMTP EHLO отклонён')
    caps=[line[4:].strip().upper() for line in reply.splitlines() if len(line)>=4]
    out.metadata['capabilities']=[c.split(' ',1)[0] for c in caps][:40]
    starttls='STARTTLS' in caps
    plain_auth=any(re.match(r'AUTH[ =].*\b(?:PLAIN|LOGIN)\b',c) for c in caps)
    if plain_auth and not out.tls:
        out.record('SMTP-AUTH-PLAINTEXT','POTENTIAL','EHLO до TLS рекламирует AUTH PLAIN/LOGIN. Фактический приём учётных данных не проверялся.',
                   'MEDIUM','Не рекламируйте парольные механизмы AUTH до TLS; проверьте требования шифрования.',
                   ['https://www.rfc-editor.org/rfc/rfc4954.html'])
    if out.tls:
        out.record('SMTP-TRANSPORT','PASS','Приветствие получено внутри TLS; политика входа не проверялась.')
    elif starttls:
        ch.send(b'STARTTLS\r\n');code,_=response_code(ch)
        if code==220:
            version=ch.upgrade_tls(name);out.metadata.update(starttls=True,tls_version=version)
            out.record('SMTP-STARTTLS','PASS','STARTTLS handshake успешен. Обязательность TLS не проверялась.')
        else:out.record('SMTP-STARTTLS','UNKNOWN',f'STARTTLS объявлен, но получен ответ {code}.')
    else:out.record('SMTP-STARTTLS','UNKNOWN','STARTTLS не объявлен. Для SMTP-реле это само по себе не доказывает уязвимость.')


def probe_nats(ch,out,name):
    line=ch.line()
    if not line.startswith(b'INFO '):raise ProbeError('Нет NATS INFO')
    info=json.loads(line[5:])
    if not isinstance(info,dict) or not isinstance(info.get('server_id'),str):raise ProbeError('Неполный NATS INFO')
    out.confirmed=True;out.product='NATS'
    version=info.get('version','')
    if isinstance(version,str) and re.fullmatch(r'[0-9]+(?:\.[0-9]+)+',version):out.version=version
    out.metadata={k:info[k] for k in ('auth_required','tls_required') if isinstance(info.get(k),bool)}
    if info.get('auth_required') is False:
        out.record('NATS-AUTH','POTENTIAL','В приветствии NATS явно указано auth_required=false. Права на сообщения и ограничения пользователей не проверялись.',
                   'MEDIUM','Проверьте аутентификацию NATS и разрешения publish/subscribe.',
                   ['https://docs.nats.io/reference/protocols/client'])
    elif info.get('auth_required') is True:out.record('NATS-AUTH','PASS','В INFO явно указано auth_required=true.')
    else:out.record('NATS-AUTH','UNKNOWN','Поле auth_required не получено; политика не угадывается.')


def probe_memcached(ch,out,name):
    ch.send(b'version\r\n');line=ch.line()
    match=re.fullmatch(rb'VERSION ([0-9]+(?:\.[0-9]+)+)\r\n',line)
    if not match:raise ProbeError('Нет корректного Memcached VERSION')
    out.confirmed=True;out.product='Memcached';out.version=match.group(1).decode()
    out.record('MEMCACHED-VERSION','PASS','VERSION доступен; операции чтения/записи кеша и их ACL не проверялись.')


def probe_rtsp(ch,out,name):
    ch.send(b'OPTIONS * RTSP/1.0\r\nCSeq: 1\r\nUser-Agent: NetworkSecurityScanner/6.5\r\n\r\n')
    first=ch.line()
    match=re.fullmatch(rb'RTSP/[12]\.0 ([1-5][0-9]{2})[^\r\n]*\r\n',first)
    if not match:raise ProbeError('Нет корректного RTSP ответа')
    headers={}
    for _ in range(40):
        line=ch.line()
        if line==b'\r\n':break
        if b':' not in line:raise ProbeError('Повреждённый RTSP заголовок')
        key,value=line.decode('utf-8',errors='replace').split(':',1);headers[key.lower()]=value.strip()
    else:raise ProbeError('Слишком много RTSP заголовков')
    if headers.get('cseq')!='1':raise ProbeError('RTSP CSeq не соответствует запросу')
    out.confirmed=True;out.banner=first.decode().strip();out.metadata['options_status']=int(match.group(1))
    out.metadata['methods']=headers.get('public','')[:512]
    out.record('RTSP-OPTIONS','PASS','Получен ответ OPTIONS. Доступ к видеопотоку не проверялся; HTTP-подобный код 200 не означает просмотр без пароля.')


PROBES={'vnc':probe_vnc,'smb':probe_smb,'rdp':probe_rdp,'mqtt':probe_mqtt,'redis':probe_redis,
        'ftp':probe_ftp,'smtp':probe_smtp,'nats':probe_nats,'memcached':probe_memcached,'rtsp':probe_rtsp}
PORTS={21:'ftp',2121:'ftp',25:'smtp',465:'smtp',587:'smtp',445:'smb',3389:'rdp',
       1883:'mqtt',8883:'mqtt',6379:'redis',4222:'nats',11211:'memcached',554:'rtsp',8554:'rtsp',
       5900:'vnc',5901:'vnc',5902:'vnc',5903:'vnc'}


def select_protocol(port,service='',banner=''):
    # Wire signatures take precedence over customary ports.
    if banner.startswith('RFB '):return 'vnc'
    if banner.startswith('INFO '):return 'nats'
    if service in PROBES:return service
    return PORTS.get(port)


def audit(protocol,address,port,timeout=3,cancel=None,server_name=None):
    out=Outcome(protocol)
    if protocol not in PROBES:raise ValueError('Unknown audit protocol')
    try:
        if cancel and cancel.is_set():raise ProbeError('Проверка отменена')
        with Channel(address,port,timeout,cancel) as ch:
            if (protocol,port) in (('mqtt',8883),('smtp',465)):
                out.metadata['tls_version']=ch.upgrade_tls(server_name or address);out.tls=True
            PROBES[protocol](ch,out,server_name or address)
    except (OSError,ValueError,TypeError,KeyError,struct.error) as exc:
        out.record(protocol.upper()+'-AUDIT','UNKNOWN',f'{type(exc).__name__}: {exc}')
    return out
