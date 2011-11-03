#!/usr/bin/python
from k5test import *

realm = K5Realm(create_kdb=False)
realm.run_as_master(['./t_stringattr'])
success('String attribute unit tests')
