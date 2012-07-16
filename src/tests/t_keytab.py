#!/usr/bin/python
from k5test import *

for realm in multipass_realms(create_user=False):
    # Test kinit with a keytab.
    realm.kinit(realm.host_princ, flags=['-k'])

realm = K5Realm(get_creds=False)

# Test kinit with a partial keytab.
pkeytab = realm.keytab + '.partial'
realm.run_as_master([ktutil], input=('rkt %s\ndelent 1\nwkt %s\n' %
                                     (realm.keytab, pkeytab)))
realm.kinit(realm.host_princ, flags=['-k', '-t', pkeytab])

# Test kinit with no keys for client in keytab.
output = realm.kinit(realm.user_princ, flags=['-k'], expected_code=1)
if 'no suitable keys' not in output:
    fail('Expected error not seen in kinit output')

# Test kinit and klist with client keytab defaults.
realm.extract_keytab(realm.user_princ, realm.client_keytab);
realm.kinit(realm.user_princ, flags=['-k', '-i'])
realm.klist(realm.user_princ)
out = realm.run_as_client([klist, '-k', '-i'])
if realm.client_keytab not in out or realm.user_princ not in out:
    fail('Expected output not seen from klist -k -i')

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
