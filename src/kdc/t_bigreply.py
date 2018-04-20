#!/usr/bin/python
from k5test import *

# Set the maximum UDP reply size very low, so that all replies go
# through the RESPONSE_TOO_BIG path.
kdc_conf = {'kdcdefaults': {'kdc_max_dgram_reply_size': '10'}}
realm = K5Realm(kdc_conf=kdc_conf, get_creds=False)

realm.kinit(realm.user_princ, password('user'))
realm.run([kvno, realm.host_princ])

success('Large KDC replies')
