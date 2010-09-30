#!/usr/bin/python
from k5test import *

for realm in multipass_realms(create_host=False):
    # Create a policy and see if it survives a dump/load.
    realm.run_kadminl('addpol fred')
    dumpfile = os.path.join(realm.testdir, 'dump')
    realm.run_as_master([kdb5_util, 'dump', dumpfile])
    realm.run_as_master([kdb5_util, 'load', dumpfile])
    output = realm.run_kadminl('getpols')
    if 'fred\n' not in output:
        fail('Policy not preserved across dump/load.')

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
    realm.run_as_master([kinit, "-k", "-t",
                         "KDB:", realm.user_princ])


    # Test kdestroy and klist of a non-existent ccache.
    realm.run_as_client([kdestroy])
    output = realm.run_as_client([klist], expected_code=1)
    if 'No credentials cache found' not in output:
        fail('Expected error message not seen in klist output')

    # Test handling of kvno values beyond 255.
    princ = 'foo/bar@%s' % realm.realm
    realm.addprinc(princ)
    realm.run_kadminl('modprinc -kvno 252 %s' % princ)
    for kvno in range(253, 259):
        realm.run_kadminl('ktadd -k %s %s' % (realm.keytab, princ))
        realm.klist_keytab(princ)
    output = realm.run_kadminl('getprinc %s' % princ)
    if 'Key: vno 258,' not in output:
        fail('Expected vno not seen in kadmin.local output')

success('Dump/load, FAST kinit, kdestroy, kvno wrapping.')
