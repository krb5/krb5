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

# Test that multiple stepwise initial creds operations can be
# performed with the same krb5_context, with proper tracking of
# clpreauth module request handles.
realm.run([kadminl, 'addprinc', '-pw', 'pw', 'u1'])
realm.run([kadminl, 'addprinc', '+requires_preauth', '-pw', 'pw', 'u2'])
realm.run([kadminl, 'addprinc', '+requires_preauth', '-pw', 'pw', 'u3'])
realm.run([kadminl, 'setstr', 'u2', '2rt', 'extra'])
out = realm.run(['./icinterleave', 'pw', 'u1', 'u2', 'u3'])
if out != ('step 1\nstep 2\nstep 3\nstep 1\nfinish 1\nstep 2\nno attr\n'
           'step 3\nno attr\nstep 2\n2rt: extra\nstep 3\nfinish 3\nstep 2\n'
           'finish 2\n'):
    fail('unexpected output from icinterleave')

success('Pre-authentication framework tests')
