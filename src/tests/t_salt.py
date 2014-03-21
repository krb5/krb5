#!/usr/bin/python
from k5test import *
import re

realm = K5Realm(create_user=False)

# Check that a non-default salt type applies only to the key it is
# matched with and not to subsequent keys.  e1 and e2 are enctypes,
# and salt is a non-default salt type.
def test_salt(realm, e1, salt, e2):
    query = 'ank -e %s:%s,%s -pw password user' % (e1, salt, e2)
    realm.run_kadminl(query)
    out = realm.run_kadminl('getprinc user')
    if len(re.findall(':' + salt, out)) != 1:
        fail(salt + ' present in second enctype or not present')
    realm.run_kadminl('delprinc -force user')

# Enctype/salt pairs chosen with non-default salt types.
# The enctypes are mostly arbitrary, though afs3 must only be used with des.
# We do not enforce that v4 salts must only be used with des, but it seems
# like a good idea.
salts = [('des-cbc-crc', 'afs3'),
         ('des3-cbc-sha1', 'norealm'),
         ('arcfour-hmac', 'onlyrealm'),
         ('des-cbc-crc', 'v4'),
         ('aes128-cts-hmac-sha1-96', 'special')]
# These enctypes are chosen to cover the different string-to-key routines.
# Omit ":normal" from aes256 to check that salttype defaulting works.
second_kstypes = ['aes256-cts-hmac-sha1-96', 'arcfour-hmac:normal',
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
