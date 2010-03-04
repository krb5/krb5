#!/usr/bin/python
from k5test import *

# Skip this test if pkinit wasn't built.
if not os.path.exists(os.path.join(plugins, 'preauth', 'pkinit.so')):
    success()
    exit(0)

# Construct a krb5.conf fragment configuring pkinit.
certs = os.path.join(srctop, 'tests', 'dejagnu', 'pkinit-certs')
ca_pem = os.path.join(certs, 'ca.pem')
kdc_pem = os.path.join(certs, 'kdc.pem')
privkey_pem = os.path.join(certs, 'privkey.pem')
pkinit_krb5_conf = {
    'all' : {
        'libdefaults' : {
            'pkinit_anchors' : 'FILE:' + ca_pem
        },
        'realms' : {
            '$realm' : {
                'pkinit_anchors' : 'FILE:%s' % ca_pem,
                'pkinit_identity' : 'FILE:%s,%s' % (kdc_pem, privkey_pem),
            }
        }
    }
}

realm = K5Realm(krb5_conf=pkinit_krb5_conf, create_user=False,
                create_host=False)
realm.addprinc('WELLKNOWN/ANONYMOUS')
realm.kinit('@%s' % realm.realm, flags=['-n'])
realm.klist('WELLKNOWN/ANONYMOUS@WELLKNOWN:ANONYMOUS')

success()
