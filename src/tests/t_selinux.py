#!/usr/bin/python

from k5test import *

# Make a TGS request with an expired ticket.
realm = K5Realm()
realm.run([kvno, realm.host_princ])
kdc_logfile = os.path.join(realm.testdir, 'kdc.log')
out = realm.run(['ls', '-Z', kdc_logfile])
print out
fail('XXX stopping for test')
