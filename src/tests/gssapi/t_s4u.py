#!/usr/bin/python
from k5test import *

realm = K5Realm(create_host=False, get_creds=False)
usercache = 'FILE:' + os.path.join(realm.testdir, 'usercache')
storagecache = 'FILE:' + os.path.join(realm.testdir, 'save')

# Create two service principals with keys in the default keytab.
service1 = 'service/1@%s' % realm.realm
realm.addprinc(service1)
realm.extract_keytab(service1, realm.keytab)
service2 = 'service/2@%s' % realm.realm
realm.addprinc(service2)
realm.extract_keytab(service2, realm.keytab)

puser = 'p:' + realm.user_princ
pservice1 = 'p:' + service1
pservice2 = 'p:' + service2

# Get forwardable creds for service1 in the default cache.
realm.kinit(service1, None, ['-f', '-k'])

# Try krb5 -> S4U2Proxy with forwardable user creds.  This should fail
# at the S4U2Proxy step since the DB2 back end currently has no
# support for allowing it.
realm.kinit(realm.user_princ, password('user'), ['-f', '-c', usercache])
output = realm.run_as_server(['./t_s4u2proxy_krb5', usercache, storagecache,
                              '-', pservice1, pservice2], expected_code=1)
if ('auth1: ' + realm.user_princ not in output or
    'NOT_ALLOWED_TO_DELEGATE' not in output):
    fail('krb5 -> s4u2proxy')

# Again with SPNEGO.  Bug #7045 prevents us from checking the error
# message, but we can at least exercise the code.
output = realm.run_as_server(['./t_s4u2proxy_krb5', '--spnego', usercache,
                              storagecache, '-', pservice1, pservice2],
                             expected_code=1)
if ('auth1: ' + realm.user_princ not in output):
    fail('krb5 -> s4u2proxy (SPNEGO)')

# Try krb5 -> S4U2Proxy without forwardable user creds.  This should
# result in no delegated credential being created by
# accept_sec_context.
realm.kinit(realm.user_princ, password('user'), ['-c', usercache])
output = realm.run_as_server(['./t_s4u2proxy_krb5', usercache, storagecache,
                              pservice1, pservice1, pservice2])
if 'no credential delegated' not in output:
    fail('krb5 -> no delegated cred')

# Try S4U2Self.  Ask for an S4U2Proxy step; this won't happen because
# service/1 isn't allowed to get a forwardable S4U2Self ticket.
output = realm.run_as_server(['./t_s4u', puser, pservice2])
if ('Warning: no delegated cred handle' not in output or
    'Source name:\t' + realm.user_princ not in output):
    fail('s4u2self')
output = realm.run_as_server(['./t_s4u', '--spnego', puser, pservice2])
if ('Warning: no delegated cred handle' not in output or
    'Source name:\t' + realm.user_princ not in output):
    fail('s4u2self (SPNEGO)')

# Correct that problem and try again.  As above, the S4U2Proxy step
# won't actually succeed since we don't support that in DB2.
realm.run_kadminl('modprinc +ok_to_auth_as_delegate ' + service1)
output = realm.run_as_server(['./t_s4u', puser, pservice2], expected_code=1)
if 'NOT_ALLOWED_TO_DELEGATE' not in output:
    fail('s4u2self')

# Again with SPNEGO.  This uses SPNEGO for the initial authentication,
# but still uses krb5 for S4U2Proxy (the delegated cred is returned as
# a krb5 cred, not a SPNEGO cred, and t_s4u uses the delegated cred
# directly rather than saving and reacquiring it) so bug #7045 does
# not apply and we can verify the error message.
output = realm.run_as_server(['./t_s4u', '--spnego', puser, pservice2],
                             expected_code=1)
if 'NOT_ALLOWED_TO_DELEGATE' not in output:
    fail('s4u2self')

success('S4U test cases')
