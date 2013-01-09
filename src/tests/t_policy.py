#!/usr/bin/python
from k5test import *
import re

realm = K5Realm(create_host=False)

# Test password quality enforcement.
realm.run_kadminl('addpol -minlength 6 -minclasses 2 pwpol')
realm.run_kadminl('addprinc -randkey -policy pwpol pwuser')
out = realm.run_kadminl('cpw -pw sh0rt pwuser')
if 'Password is too short' not in out:
    fail('short password')
out = realm.run_kadminl('cpw -pw longenough pwuser')
if 'Password does not contain enough character classes' not in out:
    fail('insufficient character classes')
out = realm.run_kadminl('cpw -pw l0ngenough pwuser')
if ' changed.' not in out:
    fail('acceptable password')

# Test some password history enforcement.  Even with no history value,
# the current password should be denied.
out = realm.run_kadminl('cpw -pw l0ngenough pwuser')
if 'Cannot reuse password' not in out:
    fail('reuse of current password')
realm.run_kadminl('modpol -history 2 pwpol')
realm.run_kadminl('cpw -pw an0therpw pwuser')
out = realm.run_kadminl('cpw -pw l0ngenough pwuser')
if 'Cannot reuse password' not in out:
    fail('reuse of old password')
realm.run_kadminl('cpw -pw 3rdpassword pwuser')
out = realm.run_kadminl('cpw -pw l0ngenough pwuser')
if ' changed.' not in out:
    fail('reuse of third-oldest password with history 2')

# Test references to nonexistent policies.
out = realm.run_kadminl('addprinc -randkey -policy newpol newuser')
if ('WARNING: policy "newpol" does not exist' not in out or
    ' created.' not in out):
    fail('creation with nonexistent policy')
out = realm.run_kadminl('getprinc newuser')
if 'Policy: newpol [does not exist]\n' not in out:
    fail('getprinc output for principal referencing nonexistent policy')
out = realm.run_kadminl('modprinc -policy newpol pwuser')
if ('WARNING: policy "newpol" does not exist' not in out or
    ' modified.' not in out):
    fail('modification to nonexistent policy')
# pwuser should allow reuse of the current password since newpol doesn't exist.
out = realm.run_kadminl('cpw -pw 3rdpassword pwuser')
if ' changed.' not in out:
    fail('reuse of current password with nonexistent policy')

# Create newpol and verify that it is enforced.
realm.run_kadminl('addpol -minlength 3 newpol')
out = realm.run_kadminl('getprinc pwuser')
if 'Policy: newpol\n' not in out:
    fail('getprinc after creating policy (pwuser)')
out = realm.run_kadminl('cpw -pw aa pwuser')
if 'Password is too short' not in out:
    fail('short password after creating policy (pwuser)')
out = realm.run_kadminl('cpw -pw 3rdpassword pwuser')
if 'Cannot reuse password' not in out:
    fail('reuse of current password after creating policy')

out = realm.run_kadminl('getprinc newuser')
if 'Policy: newpol\n' not in out:
    fail('getprinc after creating policy (newuser)')
out = realm.run_kadminl('cpw -pw aa newuser')
if 'Password is too short' not in out:
    fail('short password after creating policy (newuser)')

# Delete the policy and verify that it is no longer enforced.
realm.run_kadminl('delpol -force newpol')
out = realm.run_kadminl('getpol newpol')
if 'Policy does not exist' not in out:
    fail('deletion of referenced policy')
out = realm.run_kadminl('cpw -pw aa pwuser')
if ' changed.' not in out:
    fail('short password after deleting policy')

# Test basic password lockout support.

realm.run_kadminl('addpol -maxfailure 2 -failurecountinterval 5m lockout')
realm.run_kadminl('modprinc +requires_preauth -policy lockout user')

# kinit twice with the wrong password.
output = realm.run([kinit, realm.user_princ], input='wrong\n', expected_code=1)
if 'Password incorrect while getting initial credentials' not in output:
    fail('Expected error message not seen in kinit output')
output = realm.run([kinit, realm.user_princ], input='wrong\n', expected_code=1)
if 'Password incorrect while getting initial credentials' not in output:
    fail('Expected error message not seen in kinit output')

# Now the account should be locked out.
output = realm.run([kinit, realm.user_princ], expected_code=1)
if 'Clients credentials have been revoked while getting initial credentials' \
        not in output:
    fail('Expected lockout error message not seen in kinit output')

# Check that modprinc -unlock allows a further attempt.
output = realm.run_kadminl('modprinc -unlock user')
realm.kinit(realm.user_princ, password('user'))

# Make sure a nonexistent policy reference doesn't prevent authentication.
realm.run_kadminl('delpol -force lockout')
realm.kinit(realm.user_princ, password('user'))

# Regression test for issue #7099: databases created prior to krb5 1.3 have
# multiple history keys, and kadmin prior to 1.7 didn't necessarily use the
# first one to create history entries.

realm.stop()
realm = K5Realm(start_kdc=False)
# Create a history principal with two keys.
realm.run(['./hist', 'make'])
realm.run_kadminl('addpol -history 2 pol')
realm.run_kadminl('modprinc -policy pol user')
realm.run_kadminl('cpw -pw pw2 user')
# Swap the keys, simulating older kadmin having chosen the second entry.
realm.run(['./hist', 'swap'])
# Make sure we can read the history entry.
output = realm.run_kadminl('cpw -pw %s user' % password('user'))
if 'Cannot reuse password' not in output:
    fail('Expected error not seen in output')

# Test key/salt constraints.

realm.stop()
krb5_conf1 = {'libdefaults': {'supported_enctypes': 'aes256-cts'}}
realm = K5Realm(krb5_conf=krb5_conf1, create_host=False, get_creds=False)

# Add policy.
realm.run_kadminl('addpol -allowedkeysalts aes256-cts:normal ak')
realm.run_kadminl('addprinc -randkey -e aes256-cts:normal server')

# Test with one-enctype allowed_keysalts.
realm.run_kadminl('modprinc -policy ak server')
realm.run_kadminl('getprinc server')
output = realm.run_kadminl('cpw -randkey -e aes128-cts:normal server')
if not 'Invalid key/salt tuples' in output:
    fail('allowed_keysalts policy not applied properly')
realm.run_kadminl('getprinc server')
output = realm.run_kadminl('cpw -randkey -e aes256-cts:normal server')
if 'Invalid key/salt tuples' in output:
    fail('allowed_keysalts policy not applied properly')
realm.run_kadminl('getprinc server')

# Now test a multi-enctype allowed_keysalts.  Test that subsets are allowed,
# the the complete set is allowed, that order doesn't matter, and that
# enctypes outside the set are not allowed.

# Test modpol.
realm.run_kadminl('modpol -allowedkeysalts '
                  'aes256-cts:normal,rc4-hmac:normal ak')
output = realm.run_kadminl('getpol ak')
if not 'Allowed key/salt types: aes256-cts:normal,rc4-hmac:normal' in output:
    fail('getpol does not implement allowedkeysalts?')

# Test one subset.
output = realm.run_kadminl('cpw -randkey -e rc4-hmac:normal server')
if 'Invalid key/salt tuples' in output:
    fail('allowed_keysalts policy not applied properly')
realm.run_kadminl('getprinc server')

# Test another subset.
output = realm.run_kadminl('cpw -randkey -e aes256-cts:normal server')
if 'Invalid key/salt tuples' in output:
    fail('allowed_keysalts policy not applied properly')
realm.run_kadminl('getprinc server')
output = realm.run_kadminl('cpw -randkey -e '
                           'rc4-hmac:normal,aes256-cts:normal server')
if 'Invalid key/salt tuples' in output:
    fail('allowed_keysalts policy not applied properly')
realm.run_kadminl('getprinc server')

# Test full set.
output = realm.run_kadminl('cpw -randkey -e aes256-cts:normal,rc4-hmac:normal '
                           'server')
if 'Invalid key/salt tuples' in output:
    fail('allowed_keysalts policy not applied properly')
realm.run_kadminl('getprinc server')
output = realm.run_kadminl('cpw -randkey -e rc4-hmac:normal,aes128-cts:normal '
                           'server')
if not 'Invalid key/salt tuples' in output:
    fail('allowed_keysalts policy not applied properly')
realm.run_kadminl('getprinc server')
output = realm.run_kadminl('getprinc -terse server')
if not '2\t1\t6\t18\t0\t1\t6\t23\t0' in output:
    fail('allowed_keysalts policy did not preserve order')

# Test full set in opposite order.
output = realm.run_kadminl('cpw -randkey -e rc4-hmac:normal,aes256-cts:normal,'
                           'aes128-cts:normal server')
if not 'Invalid key/salt tuples' in output:
    fail('allowed_keysalts policy not applied properly')

# Check that the order we got is the one from the policy.
realm.run_kadminl('getprinc server')
output = realm.run_kadminl('getprinc -terse server')
if not '2\t1\t6\t18\t0\t1\t6\t23\t0' in output:
    fail('allowed_keysalts policy did not preserve order')

# Test reset of allowedkeysalts.
realm.run_kadminl('modpol -allowedkeysalts - ak')
output = realm.run_kadminl('getpol ak')
if 'Allowed key/salt types' in output:
    fail('failed to clear allowedkeysalts')
output = realm.run_kadminl('cpw -randkey -e aes128-cts:normal server')
if 'Invalid key/salt tuples' in output:
    fail('key change rejected that should have been permitted')
realm.run_kadminl('getprinc server')

success('Policy tests')
