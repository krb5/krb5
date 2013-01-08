#!/usr/bin/python
from k5test import *
import re

realm = K5Realm(create_host=False)

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
