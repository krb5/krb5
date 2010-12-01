#!/usr/bin/python
from k5test import *

# Skip this test if pkinit wasn't built.
if not os.path.exists(os.path.join(plugins, 'preauth', 'pkinit.so')):
    success('Warning: not testing pkinit because it is not built.')
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

restrictive_kdc_conf = {
    'all': { 'realms' : { '$realm' : {
                'restrict_anonymous_to_tgt' : 'true' } } } }

# In the basic test, anonymous is not restricted, so kvno should succeed.
realm = K5Realm(krb5_conf=pkinit_krb5_conf, create_user=False)
realm.addprinc('WELLKNOWN/ANONYMOUS')
realm.kinit('@%s' % realm.realm, flags=['-n'])
realm.klist('WELLKNOWN/ANONYMOUS@WELLKNOWN:ANONYMOUS')
realm.run_as_client([kvno, realm.host_princ])
realm.stop()

# Now try again with anonymous restricted; kvno should fail.
realm = K5Realm(krb5_conf=pkinit_krb5_conf, kdc_conf=restrictive_kdc_conf,
                create_user=False)
realm.addprinc('WELLKNOWN/ANONYMOUS')
realm.kinit('@%s' % realm.realm, flags=['-n'])
realm.run_as_client([kvno, realm.host_princ], expected_code=1)

success('Anonymous PKINIT.')
