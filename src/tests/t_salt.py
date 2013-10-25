#!/usr/bin/python
from k5test import *
import re

realm = K5Realm(create_user=False)

# Check that a non-default salt type applies only to the key it is matched
# with and not to subsequent keys.  e1 is a enctype:salt string with
# non-default salt, and e2 is an enctype:salt string with default salt.
# The string argument corresponds to the salt type of e1, and must appear
# exactly once in the getprinc output, corresponding to just the first key.
def test_salt(realm, e1, string, e2):
    query = 'ank -e ' + e1 + ',' + e2 + ' -pw password user'
    realm.run_kadminl(query)
    out = realm.run_kadminl('getprinc user')
    if len(re.findall(string, out)) != 1:
        fail(string + ' present in second enctype or not present')
    realm.run_kadminl('delprinc -force user')

# Enctype/salt pairs chosen with non-default salt types.
# The enctypes are mostly arbitrary, though afs3 must only be used with des.
# We do not enforce that v4 salts must only be used with des, but it seems
# like a good idea.
salts = [('des-cbc-crc:afs3', 'AFS version 3'),
         ('des3-cbc-sha1:norealm', 'Version 5 - No Realm'),
         ('arcfour-hmac:onlyrealm', 'Version 5 - Realm Only'),
         ('des-cbc-crc:v4', 'Version 4'),
         ('aes128-cts-hmac-sha1-96:special', 'Special')]
# These enctypes are chosen to cover the different string-to-key routines.
second_kstypes = ['aes256-cts-hmac-sha1-96:normal', 'arcfour-hmac:normal',
                  'des3-cbc-sha1:normal', 'des-cbc-crc:normal']

# Test using different salt types in a principal's key list.
# Parameters from one key in the list must not leak over to later ones.
for e1, string in salts:
    for e2 in second_kstypes:
        test_salt(realm, e1, string, e2)

# Attempt to create a principal with a non-des enctype and the afs3 salt,
# verifying that the expected error is received and the principal creation
# fails.
def test_reject_afs3(realm, etype):
    query = 'ank -e ' + etype + ':afs3 -pw password princ1'
    out = realm.run_kadminl(query)
    if 'Invalid key generation parameters from KDC' not in out:
        fail('Allowed afs3 salt for ' + etype)
    out = realm.run_kadminl('getprinc princ1')
    if 'Principal does not exist' not in out:
        fail('Created principal with afs3 salt and enctype ' + etype)

# Verify that the afs3 salt is rejected for arcfour and pbkdf2 enctypes.
# We do not currently do any verification on the key-generation parameters
# for the triple-DES enctypes, so that test is commented out.
test_reject_afs3(realm, 'arcfour-hmac')
test_reject_afs3(realm, 'aes256-cts-hmac-sha1-96')
#test_reject_afs3(realm, 'des3-cbc-sha1')

success("Salt types")
