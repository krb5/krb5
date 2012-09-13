#!/usr/bin/python
from k5test import *

# Set up a basic realm and a client keytab containing two user principals.
# Point HOME at realm.testdir for tests using .k5identity.
realm = K5Realm(get_creds=False)
bob = 'bob@' + realm.realm
phost = 'p:' + realm.host_princ
puser = 'p:' + realm.user_princ
pbob = 'p:' + bob
gssserver = 'h:host@' + hostname
realm.env_client['HOME'] = realm.testdir
realm.addprinc(bob, password('bob'))
realm.extract_keytab(realm.user_princ, realm.client_keytab)
realm.extract_keytab(bob, realm.client_keytab)

# Test 1: no name/cache specified, pick first principal from client keytab
out = realm.run_as_client(['./t_ccselect', phost])
if realm.user_princ not in out:
    fail('Authenticated as wrong principal')
realm.run_as_client([kdestroy])

# Test 2: no name/cache specified, pick principal from k5identity
k5idname = os.path.join(realm.testdir, '.k5identity')
k5id = open(k5idname, 'w')
k5id.write('%s service=host host=%s\n' % (bob, hostname))
k5id.close()
out = realm.run_as_client(['./t_ccselect', gssserver])
if bob not in out:
    fail('Authenticated as wrong principal')
os.remove(k5idname)
realm.run_as_client([kdestroy])

# Test 3: no name/cache specified, default ccache has name but no creds
realm.run_as_client(['./ccinit', realm.ccache, bob])
out = realm.run_as_client(['./t_ccselect', phost])
if bob not in out:
    fail('Authenticated as wrong principal')
# Leave tickets for next test.

# Test 4: name specified, non-collectable default cache doesn't match
out = realm.run_as_client(['./t_ccselect', phost, puser], expected_code=1)
if 'Principal in credential cache does not match desired name' not in out:
    fail('Expected error not seen')
realm.run_as_client([kdestroy])

# Test 5: name specified, nonexistent default cache
out = realm.run_as_client(['./t_ccselect', phost, pbob])
if bob not in out:
    fail('Authenticated as wrong principal')
# Leave tickets for next test.

# Test 6: name specified, matches default cache, time to refresh
realm.run_as_client(['./ccrefresh', realm.ccache, '1'])
out = realm.run_as_client(['./t_ccselect', phost, pbob])
if bob not in out:
    fail('Authenticated as wrong principal')
out = realm.run_as_client(['./ccrefresh', realm.ccache])
if int(out) < 1000:
    fail('Credentials apparently not refreshed')
realm.run_as_client([kdestroy])

# Test 7: empty ccache specified, pick first principal from client keytab
realm.run_as_client(['./t_imp_cred', phost])
realm.klist(realm.user_princ)
realm.run_as_client([kdestroy])

# Test 8: ccache specified with name but no creds; name not in client keytab
realm.run_as_client(['./ccinit', realm.ccache, realm.host_princ])
out = realm.run_as_client(['./t_imp_cred', phost], expected_code=1)
if 'Credential cache is empty' not in out:
    fail('Expected error not seen')
realm.run_as_client([kdestroy])

# Test 9: ccache specified with name but no creds; name in client keytab
realm.run_as_client(['./ccinit', realm.ccache, bob])
realm.run_as_client(['./t_imp_cred', phost])
realm.klist(bob)
# Leave tickets for next test.

# Test 10: ccache specified with creds, time to refresh
realm.run_as_client(['./ccrefresh', realm.ccache, '1'])
realm.run_as_client(['./t_imp_cred', phost])
realm.klist(bob)
out = realm.run_as_client(['./ccrefresh', realm.ccache])
if int(out) < 1000:
    fail('Credentials apparently not refreshed')
realm.run_as_client([kdestroy])

# Use a cache collection for the remaining tests.
ccdir = os.path.join(realm.testdir, 'cc')
ccname = 'DIR:' + ccdir
os.mkdir(ccdir)
realm.env_client['KRB5CCNAME'] = ccname

# Test 11: name specified, matching cache in collection with no creds
bobcache = os.path.join(ccdir, 'tktbob')
realm.run_as_client(['./ccinit', bobcache, bob])
out = realm.run_as_client(['./t_ccselect', phost, pbob])
if bob not in out:
    fail('Authenticated as wrong principal')
# Leave tickets for next test.

# Test 12: name specified, matching cache in collection, time to refresh
realm.run_as_client(['./ccrefresh', bobcache, '1'])
out = realm.run_as_client(['./t_ccselect', phost, pbob])
if bob not in out:
    fail('Authenticated as wrong principal')
out = realm.run_as_client(['./ccrefresh', bobcache])
if int(out) < 1000:
    fail('Credentials apparently not refreshed')
realm.run_as_client([kdestroy, '-A'])

# Test 13: name specified, collection has default for different principal
realm.kinit(realm.user_princ, password('user'))
out = realm.run_as_client(['./t_ccselect', phost, pbob])
if bob not in out:
    fail('Authenticated as wrong principal')
out = realm.run_as_client([klist])
if 'Default principal: %s\n' % realm.user_princ not in out:
    fail('Default cache overwritten by acquire_cred')
realm.run_as_client([kdestroy, '-A'])

# Test 14: name specified, collection has no default cache
out = realm.run_as_client(['./t_ccselect', phost, pbob])
if bob not in out:
    fail('Authenticated as wrong principal')
# Make sure the tickets we acquired didn't become the default
out = realm.run_as_client([klist], expected_code=1)
if 'No credentials cache found' not in out:
    fail('Expected error not seen')
realm.run_as_client([kdestroy, '-A'])

success('Client keytab tests')
