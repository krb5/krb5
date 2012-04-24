#!/usr/bin/python
from k5test import *

for realm in multipass_realms(create_host=False, start_kadmind=False):
    # Check that kinit fails appropriately with the wrong password.
    output = realm.run_as_client([kinit, realm.user_princ], input='wrong\n',
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
    realm.run_as_master([kinit, "-k", "-t", "KDB:", realm.user_princ])

realm = K5Realm(create_host=False, start_kadmind=False)

# Create a policy and see if it survives a dump/load.
realm.run_kadminl('addpol fred')
dumpfile = os.path.join(realm.testdir, 'dump')
realm.run_as_master([kdb5_util, 'dump', dumpfile])
realm.run_as_master([kdb5_util, 'load', dumpfile])
output = realm.run_kadminl('getpols')
if 'fred\n' not in output:
    fail('Policy not preserved across dump/load.')

# Test kdestroy and klist of a non-existent ccache.
realm.run_as_client([kdestroy])
output = realm.run_as_client([klist], expected_code=1)
if 'No credentials cache found' not in output:
    fail('Expected error message not seen in klist output')

success('Dump/load, FAST kinit, kdestroy')
