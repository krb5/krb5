#!/usr/bin/python
from k5test import *

rollover_krb5_conf = {'all' : {'libdefaults' : {'allow_weak_crypto' : 'true'}}}

realm = K5Realm(krbtgt_keysalt='des-cbc-crc:normal',
                krb5_conf=rollover_krb5_conf)

princ1 = 'host/test1@%s' % (realm.realm,)
princ2 = 'host/test2@%s' % (realm.realm,)
realm.addprinc(princ1)
realm.addprinc(princ2)

realm.run_as_client([kvno, realm.host_princ])

# Change key for TGS, keeping old key.
realm.run_kadminl('cpw -randkey -e aes256-cts:normal -keepold krbtgt/%s@%s' %
                  (realm.realm, realm.realm))

# Ensure that kvno still works with an old TGT.
realm.run_as_client([kvno, princ1])

realm.run_kadminl('purgekeys krbtgt/%s@%s' % (realm.realm, realm.realm))
# Make sure an old TGT fails after purging old TGS key.
realm.run_as_client([kvno, princ2], expected_code=1)
output = realm.run_as_client([klist, '-e'])

expected = 'krbtgt/%s@%s\n\tEtype (skey, tkt): des-cbc-crc, des-cbc-crc' % \
    (realm.realm, realm.realm)

if expected not in output:
    fail('keyrollover: expected TGS enctype not found')

# Check that new key actually works.
realm.kinit(realm.user_princ, password('user'))
realm.run_as_client([kvno, realm.host_princ])
output = realm.run_as_client([klist, '-e'])

expected = 'krbtgt/%s@%s\n\tEtype (skey, tkt): ' \
    'aes256-cts-hmac-sha1-96, aes256-cts-hmac-sha1-96' % \
    (realm.realm, realm.realm)

if expected not in output:
    fail('keyrollover: expected TGS enctype not found after change')

success('keyrollover')
