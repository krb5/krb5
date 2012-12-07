#!/usr/bin/python
from k5test import *

# We should have a comprehensive suite of KDC host referral tests
# here, based on the tests in the kdc_realm subdir.  For now, we just
# have a regression test for #7483.

# A KDC should not return a host referral to its own realm.
krb5_conf = {'master': {'domain_realm': {'y': 'KRBTEST.COM'}}}
kdc_conf = {'master': {'realms': {'$realm': {'host_based_services': 'x'}}}}
realm = K5Realm(krb5_conf=krb5_conf, kdc_conf=kdc_conf, create_host=False)
tracefile = os.path.join(realm.testdir, 'trace')
realm.run_as_client(['env', 'KRB5_TRACE=' + tracefile, kvno, '-u', 'x/z.y@'],
                    expected_code=1)
f = open(tracefile, 'r')
trace = f.read()
f.close()
if 'back to same realm' in trace:
    fail('KDC returned referral to service realm')

success('KDC host referral tests')
