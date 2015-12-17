#!/usr/bin/python
from k5test import *

realm = K5Realm()

# Sanity check
realm.kinit(realm.user_princ, password=password('user'))
realm.klist(realm.user_princ)
realm.run([kvno, realm.host_princ])

# Test kinit with PAC
realm.kinit(realm.user_princ, flags=['--request-pac'], password=password('user'))
realm.klist(realm.user_princ)

# Test kinit without PAC
realm.kinit(realm.user_princ, flags=['--no-request-pac'], password=password('user'))
realm.klist(realm.user_princ)

success('kinit tests')
