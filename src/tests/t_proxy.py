from k5test import *
import ssl
import threading

# Skip this test if we're missing proxy functionality.
if runenv.tls_impl == 'no':
    skip_rest('HTTP proxy tests', 'TLS build support not enabled')

# Construct a krb5.conf fragment configuring the client to use a local proxy
# server.
proxycerts = os.path.join(srctop, 'tests', 'proxy-certs')
proxysubjectpem = os.path.join(proxycerts, 'proxy-subject.pem')
proxysanpem = os.path.join(proxycerts, 'proxy-san.pem')
proxyidealpem = os.path.join(proxycerts, 'proxy-ideal.pem')
proxywrongpem = os.path.join(proxycerts, 'proxy-no-match.pem')
proxybadpem = os.path.join(proxycerts, 'proxy-badsig.pem')
proxyca = os.path.join(proxycerts, 'ca.pem')
proxyurl = 'https://localhost:$port5/KdcProxy'
proxyurlupcase = 'https://LocalHost:$port5/KdcProxy'
proxyurl4 = 'https://127.0.0.1:$port5/KdcProxy'
proxyurl6 = 'https://[::1]:$port5/KdcProxy'

unanchored_krb5_conf = {'realms': {'$realm': {
                        'kdc': proxyurl,
                        'kpasswd_server': proxyurl}}}
anchored_name_krb5_conf = {'realms': {'$realm': {
                           'kdc': proxyurl,
                           'kpasswd_server': proxyurl,
                           'http_anchors': 'FILE:%s' % proxyca}}}
anchored_upcasename_krb5_conf = {'realms': {'$realm': {
                                 'kdc': proxyurlupcase,
                                 'kpasswd_server': proxyurlupcase,
                                 'http_anchors': 'FILE:%s' % proxyca}}}
anchored_kadmin_krb5_conf = {'realms': {'$realm': {
                             'kdc': proxyurl,
                             'admin_server': proxyurl,
                             'http_anchors': 'FILE:%s' % proxyca}}}
anchored_ipv4_krb5_conf = {'realms': {'$realm': {
                           'kdc': proxyurl4,
                           'kpasswd_server': proxyurl4,
                           'http_anchors': 'FILE:%s' % proxyca}}}
kpasswd_input = (password('user') + '\n' + password('user') + '\n' +
                 password('user') + '\n')

def start_proxy(realm, keycertpem):
    proxy_conf_path = os.path.join(realm.testdir, 'kdcproxy.conf')
    proxy_exec_path = os.path.join(srctop, 'util', 'wsgiref-kdcproxy.py')
    conf = open(proxy_conf_path, 'w')
    conf.write('[%s]\n' % realm.realm)
    conf.write('kerberos = kerberos://localhost:%d\n' % realm.portbase)
    conf.write('kpasswd = kpasswd://localhost:%d\n' % (realm.portbase + 2))
    conf.close()
    realm.env['KDCPROXY_CONFIG'] = proxy_conf_path
    cmd = [sys.executable, proxy_exec_path, str(realm.server_port()),
           keycertpem]
    return realm.start_server(cmd, sentinel='proxy server ready')

# Accept TLS connections on the realm's server port, read each request, and
# close the connection without sending a reply.
def read_request(s):
    req = b''
    while b'\r\n\r\n' not in req:
        data = s.recv(4096)
        if not data:
            return
        req += data
    head, sep, body = req.partition(b'\r\n\r\n')
    for line in head.split(b'\r\n'):
        name, colon, value = line.partition(b':')
        if name.strip().lower() == b'content-length':
            while len(body) < int(value):
                data = s.recv(4096)
                if not data:
                    return
                body += data

def start_closing_proxy(realm, keycertpem):
    sslctx = ssl.create_default_context(purpose=ssl.Purpose.CLIENT_AUTH)
    sslctx.load_cert_chain(certfile=keycertpem)
    lsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    lsock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    lsock.bind(('localhost', realm.server_port()))
    lsock.listen(5)
    lsock.settimeout(0.1)
    stop = threading.Event()
    def serve():
        while not stop.is_set():
            try:
                conn, addr = lsock.accept()
            except socket.timeout:
                continue
            conn.settimeout(10)
            try:
                with sslctx.wrap_socket(conn, server_side=True) as s:
                    read_request(s)
            except (OSError, ValueError):
                pass
        lsock.close()
    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    return stop, thread

def stop_closing_proxy(proxy):
    stop, thread = proxy
    stop.set()
    thread.join()

# Fail cleanly if the proxy closes the connection without replying.
mark('proxy closes without reply')
realm = K5Realm(krb5_conf=anchored_name_krb5_conf, get_creds=False,
                create_host=False)
proxy = start_closing_proxy(realm, proxyidealpem)
realm.kinit(realm.user_princ, password=password('user'), expected_code=1,
            expected_msg='Cannot contact any KDC',
            expected_trace=('HTTPS error:',))
stop_closing_proxy(proxy)
realm.stop()

# The remaining tests require the Python kdcproxy module.
try:
    import kdcproxy
except:
    skip_rest('HTTP proxy tests', 'Python kdcproxy module not found')

# Fail: untrusted issuer and hostname doesn't match.
mark('untrusted issuer, hostname mismatch')
output("running pass 1: issuer not trusted and hostname doesn't match\n")
realm = K5Realm(krb5_conf=unanchored_krb5_conf, get_creds=False,
                create_host=False)
proxy = start_proxy(realm, proxywrongpem)
realm.kinit(realm.user_princ, password=password('user'), expected_code=1)
stop_daemon(proxy)
realm.stop()

# Fail: untrusted issuer, host name matches subject.
mark('untrusted issuer, hostname subject match')
output("running pass 2: subject matches, issuer not trusted\n")
realm = K5Realm(krb5_conf=unanchored_krb5_conf, get_creds=False,
                create_host=False)
proxy = start_proxy(realm, proxysubjectpem)
realm.kinit(realm.user_princ, password=password('user'), expected_code=1)
stop_daemon(proxy)
realm.stop()

# Fail: untrusted issuer, host name matches subjectAltName.
mark('untrusted issuer, hostname SAN match')
output("running pass 3: subjectAltName matches, issuer not trusted\n")
realm = K5Realm(krb5_conf=unanchored_krb5_conf, get_creds=False,
                create_host=False)
proxy = start_proxy(realm, proxysanpem)
realm.kinit(realm.user_princ, password=password('user'), expected_code=1)
stop_daemon(proxy)
realm.stop()

# Fail: untrusted issuer, certificate signature is bad.
mark('untrusted issuer, bad signature')
output("running pass 4: subject matches, issuer not trusted\n")
realm = K5Realm(krb5_conf=unanchored_krb5_conf, get_creds=False,
                create_host=False)
proxy = start_proxy(realm, proxybadpem)
realm.kinit(realm.user_princ, password=password('user'), expected_code=1)
stop_daemon(proxy)
realm.stop()

# Fail: trusted issuer but hostname doesn't match.
mark('trusted issuer, hostname mismatch')
output("running pass 5: issuer trusted but hostname doesn't match\n")
realm = K5Realm(krb5_conf=anchored_name_krb5_conf, get_creds=False,
                create_host=False)
proxy = start_proxy(realm, proxywrongpem)
realm.kinit(realm.user_princ, password=password('user'), expected_code=1)
stop_daemon(proxy)
realm.stop()

# Succeed: trusted issuer and host name matches subject.
mark('trusted issuer, hostname subject match')
output("running pass 6: issuer trusted, subject matches\n")
realm = K5Realm(krb5_conf=anchored_name_krb5_conf, start_kadmind=True,
                get_creds=False)
proxy = start_proxy(realm, proxysubjectpem)
realm.kinit(realm.user_princ, password=password('user'))
realm.run([kvno, realm.host_princ])
realm.run([kpasswd, realm.user_princ], input=kpasswd_input)
stop_daemon(proxy)
realm.stop()

# Succeed: trusted issuer and host name matches subjectAltName.
mark('trusted issuer, hostname SAN match')
output("running pass 7: issuer trusted, subjectAltName matches\n")
realm = K5Realm(krb5_conf=anchored_name_krb5_conf, start_kadmind=True,
                get_creds=False)
proxy = start_proxy(realm, proxysanpem)
realm.kinit(realm.user_princ, password=password('user'))
realm.run([kvno, realm.host_princ])
realm.run([kpasswd, realm.user_princ], input=kpasswd_input)
stop_daemon(proxy)
realm.stop()

# Fail: certificate signature is bad.
mark('bad signature')
output("running pass 8: issuer trusted and subjectAltName matches, sig bad\n")
realm = K5Realm(krb5_conf=anchored_name_krb5_conf,
                get_creds=False,
		                create_host=False)
proxy = start_proxy(realm, proxybadpem)
realm.kinit(realm.user_princ, password=password('user'), expected_code=1)
stop_daemon(proxy)
realm.stop()

# Fail: trusted issuer but IP doesn't match.
mark('trusted issuer, IP mismatch')
output("running pass 9: issuer trusted but no name matches IP\n")
realm = K5Realm(krb5_conf=anchored_ipv4_krb5_conf, get_creds=False,
                create_host=False)
proxy = start_proxy(realm, proxywrongpem)
realm.kinit(realm.user_princ, password=password('user'), expected_code=1)
stop_daemon(proxy)
realm.stop()

# Fail: trusted issuer, but subject does not match.
mark('trusted issuer, IP mismatch (hostname in subject)')
output("running pass 10: issuer trusted, but subject does not match IP\n")
realm = K5Realm(krb5_conf=anchored_ipv4_krb5_conf, get_creds=False,
                create_host=False)
proxy = start_proxy(realm, proxysubjectpem)
realm.kinit(realm.user_princ, password=password('user'), expected_code=1)
stop_daemon(proxy)
realm.stop()

# Succeed: trusted issuer and host name matches subjectAltName.
mark('trusted issuer, IP SAN match')
output("running pass 11: issuer trusted, subjectAltName matches IP\n")
realm = K5Realm(krb5_conf=anchored_ipv4_krb5_conf, start_kadmind=True,
                get_creds=False)
proxy = start_proxy(realm, proxysanpem)
realm.kinit(realm.user_princ, password=password('user'))
realm.run([kvno, realm.host_princ])
realm.run([kpasswd, realm.user_princ], input=kpasswd_input)
stop_daemon(proxy)
realm.stop()

# Fail: certificate signature is bad.
mark('bad signature (IP hostname)')
output("running pass 12: issuer trusted, names don't match, signature bad\n")
realm = K5Realm(krb5_conf=anchored_ipv4_krb5_conf, get_creds=False,
                create_host=False)
proxy = start_proxy(realm, proxybadpem)
realm.kinit(realm.user_princ, password=password('user'), expected_code=1)
stop_daemon(proxy)
realm.stop()

# Succeed: trusted issuer and host name matches subject, using kadmin
# configuration to find kpasswdd.
mark('trusted issuer, hostname subject match (kadmin)')
output("running pass 13: issuer trusted, subject matches\n")
realm = K5Realm(krb5_conf=anchored_kadmin_krb5_conf, start_kadmind=True,
                get_creds=False, create_host=False)
proxy = start_proxy(realm, proxysubjectpem)
realm.run([kpasswd, realm.user_princ], input=kpasswd_input)
stop_daemon(proxy)
realm.stop()

# Succeed: trusted issuer and host name matches subjectAltName, using
# kadmin configuration to find kpasswdd.
mark('trusted issuer, hostname SAN match (kadmin)')
output("running pass 14: issuer trusted, subjectAltName matches\n")
realm = K5Realm(krb5_conf=anchored_kadmin_krb5_conf, start_kadmind=True,
                get_creds=False, create_host=False)
proxy = start_proxy(realm, proxysanpem)
realm.run([kpasswd, realm.user_princ], input=kpasswd_input)
stop_daemon(proxy)
realm.stop()

# Succeed: trusted issuer and host name matches subjectAltName (give or take
# case).
mark('trusted issuer, hostname SAN case-insensitive match')
output("running pass 15: issuer trusted, subjectAltName case-insensitive\n")
realm = K5Realm(krb5_conf=anchored_upcasename_krb5_conf, start_kadmind=True,
                get_creds=False, create_host=False)
proxy = start_proxy(realm, proxysanpem)
realm.run([kpasswd, realm.user_princ], input=kpasswd_input)
stop_daemon(proxy)
realm.stop()

success('MS-KKDCP proxy')
