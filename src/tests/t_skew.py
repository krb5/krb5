#!/usr/bin/python
from k5test import *

# Create a realm with the KDC one hour in the past.
realm = K5Realm(start_kdc=False)
realm.start_kdc(['-T', '-3600'])

# kinit (no preauth) should work, and should set a clock skew allowing
# kvno to work, with or without FAST.
realm.kinit(realm.user_princ, password('user'))
realm.run_as_client([kvno, realm.host_princ])
realm.kinit(realm.user_princ, password('user'), flags=['-T', realm.ccache])
realm.run_as_client([kvno, realm.host_princ])
realm.run_as_client([kdestroy])

# kinit (with preauth) should work, with or without FAST.
realm.run_kadminl('modprinc +requires_preauth user')
realm.kinit(realm.user_princ, password('user'))
realm.run_as_client([kvno, realm.host_princ])
realm.kinit(realm.user_princ, password('user'), flags=['-T', realm.ccache])
realm.run_as_client([kvno, realm.host_princ])
realm.run_as_client([kdestroy])

realm.stop()

# Repeat the above tests with kdc_timesync disabled.
conf = {'all': {'libdefaults': {'kdc_timesync': '0'}}}
realm = K5Realm(start_kdc=False, krb5_conf=conf)
realm.start_kdc(['-T', '-3600'])

# kinit (no preauth) should work, but kvno should not.  kinit with
# FAST should also fail since the armor AP-REQ won't be valid.
realm.kinit(realm.user_princ, password('user'))
realm.run_as_client([kvno, realm.host_princ], expected_code=1)
realm.kinit(realm.user_princ, password('user'), flags=['-T', realm.ccache],
            expected_code=1)

# kinit (with preauth) should fail, with or without FAST.
realm.run_kadminl('modprinc +requires_preauth user')
realm.kinit(realm.user_princ, password('user'), expected_code=1)
realm.kinit(realm.user_princ, password('user'), flags=['-T', realm.ccache],
            expected_code=1)

success('Clock skew tests')
