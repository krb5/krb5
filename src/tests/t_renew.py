#!/usr/bin/python
from k5test import *

realm = K5Realm(create_host=False, get_creds=False)

# Configure the realm to allow renewable tickets and acquire some.
realm.run_kadminl('modprinc -maxrenewlife "2 days" user')
realm.run_kadminl('modprinc -maxrenewlife "2 days" %s' % realm.krbtgt_princ)
realm.kinit(realm.user_princ, password('user'), flags=['-r', '2d'])

# Renew twice, to test that renewed tickets are renewable.
realm.kinit(realm.user_princ, flags=['-R'])
realm.kinit(realm.user_princ, flags=['-R'])
realm.klist(realm.user_princ)

success('Renewing credentials')
