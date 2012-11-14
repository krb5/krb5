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

# Test implicit request for keytab (-i or -t without -k)
realm.run_as_client([kdestroy])
output = realm.kinit(realm.host_princ, flags=['-t', realm.keytab])
if 'keytab specified, forcing -k' not in output:
    fail('Expected output not seen from kinit -t keytab')
realm.klist(realm.host_princ)
realm.run_as_client([kdestroy])
output = realm.kinit(realm.user_princ, flags=['-i'])
if 'keytab specified, forcing -k' not in output:
    fail('Expected output not seen from kinit -i')
realm.klist(realm.user_princ)

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

# Test parameter expansion in profile variables
realm.stop()
conf = {'client': {'libdefaults': {
            'default_keytab_name': 'testdir/%{null}abc%{uid}',
            'default_client_keytab_name': 'testdir/%{null}xyz%{uid}'}}}
realm = K5Realm(krb5_conf=conf, create_kdb=False)
del realm.env_client['KRB5_KTNAME']
del realm.env_client['KRB5_CLIENT_KTNAME']
uidstr = str(os.getuid())
out = realm.run_as_client([klist, '-k'], expected_code=1)
if 'FILE:testdir/abc%s' % uidstr not in out:
    fail('Wrong keytab in klist -k output')
out = realm.run_as_client([klist, '-ki'], expected_code=1)
if 'FILE:testdir/xyz%s' % uidstr not in out:
    fail('Wrong keytab in klist -ki output')

success('Keytab-related tests')
