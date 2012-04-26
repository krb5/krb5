#!/usr/bin/python
from k5test import *

# Regression test for issue #7099: databases created prior to krb5 1.3 have
# multiple history keys, and kadmin prior to 1.7 didn't necessarily use the
# first one to create history entries.
realm = K5Realm(start_kdc=False)
# Create a history principal with two keys.
realm.run_as_master(['./hist', 'make'])
realm.run_kadminl('addpol -history 2 pol')
realm.run_kadminl('modprinc -policy pol user')
realm.run_kadminl('cpw -pw pw2 user')
# Swap the keys, simulating older kadmin having chosen the second entry.
realm.run_as_master(['./hist', 'swap'])
# Make sure we can read the history entry.
output = realm.run_kadminl('cpw -pw %s user' % password('user'))
if 'Cannot reuse password' not in output:
    fail('Expected error not seen in output')

success('Password history tests')
