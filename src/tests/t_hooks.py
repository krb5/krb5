#!/usr/bin/python
from k5test import *

# Test that the hooks are working correctly.
realm = K5Realm(create_host=False)
realm.run(['./hooks', realm.user_princ, password('user')])
realm.stop()

success('send and recv hook tests')
