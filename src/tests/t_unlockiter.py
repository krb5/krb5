#!/usr/bin/python
from k5test import *

# Default KDB iteration is locked.  Expect write lock failure unless
# unlocked iteration is explicitly requested.
realm = K5Realm()
realm.run(['./unlockiter'], expected_code=1)
realm.run(['./unlockiter', '-u'])
realm.run(['./unlockiter', '-l'], expected_code=1)

# Set default to unlocked iteration.  Only explicitly requested locked
# iteration should block the write lock.
realm = K5Realm(krb5_conf={'dbmodules': {'db': {'unlockiter': 'true'}}})
realm.run(['./unlockiter'])
realm.run(['./unlockiter', '-u'])
realm.run(['./unlockiter', '-l'], expected_code=1)

success('Unlocked iteration unit tests')
