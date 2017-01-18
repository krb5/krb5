#!/usr/bin/python
from k5test import *

# Test that the kdcpreauth client_keyblock() callback matches the key
# indicated by the etype info, and returns NULL if no key was selected.
testpreauth = os.path.join(buildtop, 'plugins', 'preauth', 'test', 'test.so')
conf = {'plugins': {'kdcpreauth': {'module': 'test:' + testpreauth},
                    'clpreauth': {'module': 'test:' + testpreauth}}}
realm = K5Realm(create_host=False, get_creds=False, krb5_conf=conf)
realm.run([kadminl, 'modprinc', '+requires_preauth', realm.user_princ])
realm.run([kadminl, 'setstr', realm.user_princ, 'teststring', 'testval'])
realm.run([kadminl, 'addprinc', '-nokey', '+requires_preauth', 'nokeyuser'])
realm.kinit(realm.user_princ, password('user'), expected_msg='testval')
realm.kinit('nokeyuser', password('user'), expected_code=1,
            expected_msg='no key')

# Exercise KDC_ERR_MORE_PREAUTH_DATA_REQUIRED and secure cookies.
realm.run([kadminl, 'setstr', realm.user_princ, '2rt', 'secondtrip'])
realm.kinit(realm.user_princ, password('user'), expected_msg='2rt: secondtrip')

success('Pre-authentication framework tests')
