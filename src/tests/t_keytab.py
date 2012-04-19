#!/usr/bin/python
from k5test import *

realm = K5Realm(start_kadmind=False)

# Test kinit with a keytab.
realm.kinit(realm.host_princ, flags=['-k'])

# Test kinit with a partial keytab.
pkeytab = realm.keytab + '.partial'
realm.run_as_master([ktutil], input=('rkt %s\ndelent 1\nwkt %s\n' %
                                     (realm.keytab, pkeytab)))
realm.kinit(realm.host_princ, flags=['-k', '-t', pkeytab], expected_code=1)

# Test handling of kvno values beyond 255.
princ = 'foo/bar@%s' % realm.realm
realm.addprinc(princ)
os.remove(realm.keytab)
realm.run_kadminl('modprinc -kvno 252 %s' % princ)
for kvno in range(253, 259):
    realm.run_kadminl('ktadd -k %s %s' % (realm.keytab, princ))
    realm.kinit(princ, flags=['-k'])
    realm.klist_keytab(princ)
    os.remove(realm.keytab)
output = realm.run_kadminl('getprinc %s' % princ)
if 'Key: vno 258,' not in output:
    fail('Expected vno not seen in kadmin.local output')

success('Keytab-related tests')
