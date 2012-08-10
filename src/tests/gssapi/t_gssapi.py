#!/usr/bin/python
from k5test import *

# Test krb5 negotiation under SPNEGO for all enctype configurations.
for realm in multipass_realms():
    realm.run_as_client(['./t_spnego', realm.host_princ, realm.keytab])

### Test acceptor name behavior.

realm = K5Realm()

# Create some host-based principals and put most of them into the
# keytab.  Rename one principal so that the keytab name matches the
# key but not the client name.
realm.run_kadminl('addprinc -randkey service1/abraham')
realm.run_kadminl('addprinc -randkey service1/barack')
realm.run_kadminl('addprinc -randkey service2/calvin')
realm.run_kadminl('addprinc -randkey service2/dwight')
realm.run_kadminl('addprinc -randkey host/-nomatch-')
realm.run_kadminl('xst service1/abraham')
realm.run_kadminl('xst service1/barack')
realm.run_kadminl('xst service2/calvin')
realm.run_kadminl('renprinc -force service1/abraham service1/andrew')

# Test with no acceptor name, including client/keytab principal
# mismatch (non-fatal) and missing keytab entry (fatal).
output = realm.run_as_client(['./t_accname', 'service1/andrew'])
if 'service1/abraham' not in output:
    fail('Expected service1/abraham in t_accname output')
output = realm.run_as_client(['./t_accname', 'service1/barack'])
if 'service1/barack' not in output:
    fail('Expected service1/barack in t_accname output')
output = realm.run_as_client(['./t_accname', 'service2/calvin'])
if 'service2/calvin' not in output:
    fail('Expected service1/barack in t_accname output')
output = realm.run_as_client(['./t_accname', 'service2/dwight'],
                             expected_code=1)
if 'Wrong principal in request' not in output:
    fail('Expected error message not seen in t_accname output')

# Test with acceptor name containing service only, including
# client/keytab hostname mismatch (non-fatal) and service name
# mismatch (fatal).
output = realm.run_as_client(['./t_accname', 'service1/andrew', 'service1'])
if 'service1/abraham' not in output:
    fail('Expected service1/abraham in t_accname output')
output = realm.run_as_client(['./t_accname', 'service1/andrew', 'service2'],
                             expected_code=1)
if 'Wrong principal in request' not in output:
    fail('Expected error message not seen in t_accname output')
output = realm.run_as_client(['./t_accname', 'service2/calvin', 'service2'])
if 'service2/calvin' not in output:
    fail('Expected service2/calvin in t_accname output')
output = realm.run_as_client(['./t_accname', 'service2/calvin', 'service1'],
                             expected_code=1)
if 'Wrong principal in request' not in output:
    fail('Expected error message not seen in t_accname output')

# Test with acceptor name containing service and host.  Use the
# client's un-canonicalized hostname as acceptor input to mirror what
# many servers do.
output = realm.run_as_client(['./t_accname', realm.host_princ,
                              'host@%s' % socket.gethostname()])
if realm.host_princ not in output:
    fail('Expected %s in t_accname output' % realm.host_princ)
output = realm.run_as_client(['./t_accname', 'host/-nomatch-',
                              'host@%s' % socket.gethostname()],
                             expected_code=1)
if 'Wrong principal in request' not in output:
    fail('Expected error message not seen in t_accname output')

# Test krb5_gss_import_cred.
realm.run_as_client(['./t_imp_cred', 'service1/barack'])
realm.run_as_client(['./t_imp_cred', 'service1/barack', 'service1/barack'])
realm.run_as_client(['./t_imp_cred', 'service1/andrew', 'service1/abraham'])
output = realm.run_as_client(['./t_imp_cred', 'service2/dwight'],
                             expected_code=1)
if 'Wrong principal in request' not in output:
    fail('Expected error message not seen in t_imp_cred output')

# Test credential store extension.
tmpccname = 'FILE:' + os.path.join(realm.testdir, 'def_cache')
realm.env_client['KRB5CCNAME'] = tmpccname
storagecache = 'FILE:' + os.path.join(realm.testdir, 'user_store')
servicekeytab = os.path.join(realm.testdir, 'kt')
service_cs = 'service/cs@%s' % realm.realm
realm.addprinc(service_cs)
realm.extract_keytab(service_cs, servicekeytab)
realm.kinit(service_cs, None, ['-k', '-t', servicekeytab])
output = realm.run_as_client(['./t_credstore', service_cs, '--cred_store',
                              'ccache', storagecache, 'keytab', servicekeytab])
if 'Cred Store Success' not in output:
    fail('Expected test to succeed')

# Verify that we can't acquire acceptor creds without a keytab.
os.remove(realm.keytab)
output = realm.run_as_client(['./t_accname', 'abc'], expected_code=1)
if ('gss_acquire_cred: Keytab' not in output or
    'nonexistent or empty' not in output):
    fail('Expected error message not seen for nonexistent keytab')

realm.stop()

# Re-run the last acceptor name test with ignore_acceptor_hostname set
# and the principal for the mismatching hostname in the keytab.
ignore_conf = { 'all' : { 'libdefaults' : {
            'ignore_acceptor_hostname' : 'true' } } }
realm = K5Realm(krb5_conf=ignore_conf)
realm.run_kadminl('addprinc -randkey host/-nomatch-')
realm.run_kadminl('xst host/-nomatch-')
output = realm.run_as_client(['./t_accname', 'host/-nomatch-',
                              'host@%s' % socket.gethostname()])
if 'host/-nomatch-' not in output:
    fail('Expected host/-nomatch- in t_accname output')

realm.stop()

### Test gss_inquire_cred behavior.

realm = K5Realm()

# Test deferred resolution of the default ccache for initiator creds.
output = realm.run_as_client(['./t_inq_cred'])
if realm.user_princ not in output:
    fail('Expected %s in t_inq_cred output' % realm.user_princ)
output = realm.run_as_client(['./t_inq_cred', '-k'])
if realm.user_princ not in output:
    fail('Expected %s in t_inq_cred output' % realm.user_princ)
output = realm.run_as_client(['./t_inq_cred', '-s'])
if realm.user_princ not in output:
    fail('Expected %s in t_inq_cred output' % realm.user_princ)

# Test picking a name from the keytab for acceptor creds.
output = realm.run_as_client(['./t_inq_cred', '-a'])
if realm.host_princ not in output:
    fail('Expected %s in t_inq_cred output' % realm.host_princ)
output = realm.run_as_client(['./t_inq_cred', '-k', '-a'])
if realm.host_princ not in output:
    fail('Expected %s in t_inq_cred output' % realm.host_princ)
output = realm.run_as_client(['./t_inq_cred', '-s', '-a'])
if realm.host_princ not in output:
    fail('Expected %s in t_inq_cred output' % realm.host_princ)

# Test client keytab initiation (non-deferred) with a specified name.
realm.extract_keytab(realm.user_princ, realm.client_keytab)
os.remove(realm.ccache)
output = realm.run_as_client(['./t_inq_cred', '-k'])
if realm.user_princ not in output:
    fail('Expected %s in t_inq_cred output' % realm.user_princ)

# Test deferred client keytab initiation and GSS_C_BOTH cred usage.
os.remove(realm.client_keytab)
os.remove(realm.ccache)
shutil.copyfile(realm.keytab, realm.client_keytab)
output = realm.run_as_client(['./t_inq_cred', '-k', '-b'])
if realm.host_princ not in output:
    fail('Expected %s in t_inq_cred output' % realm.host_princ)

success('GSSAPI tests')
