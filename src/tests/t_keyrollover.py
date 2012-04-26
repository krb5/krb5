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

# Test that the KDC only accepts the first enctype for a kvno, for a
# local-realm TGS request.  To set this up, we abuse an edge-case
# behavior of modprinc -kvno.  First, set up a DES3 krbtgt entry at
# kvno 1 and cache a krbtgt ticket.
realm.run_kadminl('cpw -randkey -e des3-cbc-sha1:normal krbtgt/%s' %
                  realm.realm)
realm.run_kadminl('modprinc -kvno 1 krbtgt/%s' % realm.realm)
realm.kinit(realm.user_princ, password('user'))
# Add an AES krbtgt entry at kvno 2, and then reset it to kvno 1
# (modprinc -kvno sets the kvno on all entries without deleting any).
realm.run_kadminl('cpw -randkey -keepold -e aes256-cts:normal krbtgt/%s' %
                  realm.realm)
realm.run_kadminl('modprinc -kvno 1 krbtgt/%s' % realm.realm)
output = realm.run_kadminl('getprinc krbtgt/%s' % realm.realm)
if 'vno 1, aes256' not in output or 'vno 1, des3' not in output:
    fail('keyrollover: setup for TGS enctype test failed')
# Now present the DES3 ticket to the KDC and make sure it's rejected.
realm.run_as_client([kvno, realm.host_princ], expected_code=1)

realm.stop()

# Test a cross-realm TGT key rollover scenario where realm 1 mimics
# the Active Directory behavior of always using kvno 0 when issuing
# cross-realm TGTs.  The first kvno invocation caches a cross-realm
# TGT with the old key, and the second kvno invocation sends it to
# r2's KDC with no kvno to identify it, forcing the KDC to try
# multiple keys.
r1, r2 = cross_realms(2)
r1.run_kadminl('modprinc -kvno 0 krbtgt/%s' % r2.realm)
r1.run_as_client([kvno, r2.host_princ])
r2.run_kadminl('cpw -pw newcross -keepold krbtgt/%s@%s' % (r2.realm, r1.realm))
r1.run_kadminl('cpw -pw newcross krbtgt/%s' % r2.realm)
r1.run_kadminl('modprinc -kvno 0 krbtgt/%s' % r2.realm)
r1.run_as_client([kvno, r2.user_princ])

success('keyrollover')
