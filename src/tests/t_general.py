#!/usr/bin/python
from k5test import *

for realm in multipass_realms(create_host=False):
    # Check that kinit fails appropriately with the wrong password.
    output = realm.run([kinit, realm.user_princ], input='wrong\n',
                       expected_code=1)
    if 'Password incorrect while getting initial credentials' not in output:
        fail('Expected error message not seen in kinit output')

    # Check that we can kinit as a different principal.
    realm.kinit(realm.admin_princ, password('admin'))
    realm.klist(realm.admin_princ)

    # Test FAST kinit.
    fastpw = password('fast')
    realm.run_kadminl('ank -pw %s +requires_preauth user/fast' % fastpw)
    realm.kinit('user/fast', fastpw)
    realm.kinit('user/fast', fastpw, flags=['-T', realm.ccache])
    realm.klist('user/fast@%s' % realm.realm)

    # Test kinit against kdb keytab
    realm.run([kinit, "-k", "-t", "KDB:", realm.user_princ])

realm = K5Realm(create_host=False)

# Spot-check KRB5_TRACE output
tracefile = os.path.join(realm.testdir, 'trace')
realm.run(['env', 'KRB5_TRACE=' + tracefile, kinit, realm.user_princ],
          input=(password('user') + "\n"))
f = open(tracefile, 'r')
trace = f.read()
f.close()
expected = ('Sending initial UDP request',
            'Received answer',
            'Selected etype info',
            'AS key obtained',
            'Decrypted AS reply',
            'FAST negotiation: available',
            'Storing user@KRBTEST.COM')
for e in expected:
    if e not in trace:
        fail('Expected output not in kinit trace log')

success('FAST kinit, trace logging')
