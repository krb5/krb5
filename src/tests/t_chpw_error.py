import base64
import socket
import threading
from k5test import *

realm = K5Realm(create_host=False, get_creds=False)

# A KRB-ERROR for kadmin/changepw@KRBTEST.COM with no e-data and an error-code
# of 1765328384, which is the negation of the krb5 error table base.  A
# protocol error number that far out of range must not be translated into one
# of libkrb5's own error codes.
reply = base64.b16decode(
    '7E5A3058A003020105A10302011EA411180F32303031303930393031343634305A'
    'A503020100A60602046938C600A90D1B0B4B5242544553542E434F4DAA1D301BA0'
    '03020101A11430121B066B61646D696E1B086368616E67657077')

# Answer kpasswd requests with the canned reply.  Only UDP is served, so the
# client's TCP attempt is refused and it falls back to UDP.
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind((hostname, 0))
kpasswd_port = sock.getsockname()[1]


def serve():
    while True:
        request, addr = sock.recvfrom(65536)
        sock.sendto(reply, addr)


threading.Thread(target=serve, daemon=True).start()

conf = {'realms': {'$realm': {
    'kpasswd_server': '%s:%d' % (hostname, kpasswd_port)}}}
env = realm.special_env('badkpasswd', False, krb5_conf=conf)

realm.run([kpasswd, realm.user_princ], env=env,
          input=password('user') + '\nnewpw\nnewpw\n', expected_code=1,
          expected_msg='Generic error')

success('kpasswd reply with out-of-range KRB-ERROR code')
