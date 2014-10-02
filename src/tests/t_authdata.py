#!/usr/bin/python
from k5test import *

# Load the sample KDC authdata module.
greet_path = os.path.join(buildtop, 'plugins', 'authdata', 'greet_server',
                          'greet_server.so')
conf = {'plugins': {'kdcauthdata': {'module': 'greet:' + greet_path}}}
realm = K5Realm(krb5_conf=conf)

# With no requested authdata, we expect to see SIGNTICKET (512) in an
# if-relevant container and the greet authdata in a kdc-issued
# container.
out = realm.run(['./adata', realm.host_princ])
if '?512: ' not in out or '^-42: Hello' not in out:
    fail('expected authdata not seen for basic request')

# Requested authdata is copied into the ticket, with KDC-only types
# filtered out.  (128 is win2k-pac, which should be filtered.)
out = realm.run(['./adata', realm.host_princ, '-5', 'test1', '?-6', 'test2',
                 '128', 'fakepac', '?128', 'ifrelfakepac',
                 '^-8', 'fakekdcissued', '?^-8', 'ifrelfakekdcissued'])
if ' -5: test1' not in out or '?-6: test2' not in out:
    fail('expected authdata not seen for request with authdata')
if 'fake' in out:
    fail('KDC-only authdata not filtered for request with authdata')

out = realm.run(['./adata', realm.host_princ, '!-1', 'mandatoryforkdc'],
                expected_code=1)
if 'KDC policy rejects request' not in out:
    fail('Wrong error seen for mandatory-for-kdc failure')

# The no_auth_data_required server flag should suppress SIGNTICKET,
# but not module or request authdata.
realm.run([kadminl, 'ank', '-randkey', '+no_auth_data_required', 'noauth'])
realm.extract_keytab('noauth', realm.keytab)
out = realm.run(['./adata', 'noauth', '-2', 'test'])
if '^-42: Hello' not in out or ' -2: test' not in out:
    fail('expected authdata not seen for no_auth_data_required request')
if '512: ' in out:
    fail('SIGNTICKET authdata seen for no_auth_data_required request')

# Cross-realm TGT requests should also suppress SIGNTICKET, but not
# module or request authdata.
realm.addprinc('krbtgt/XREALM')
realm.extract_keytab('krbtgt/XREALM', realm.keytab)
out = realm.run(['./adata', 'krbtgt/XREALM', '-3', 'test'])
if '^-42: Hello' not in out or ' -3: test' not in out:
    fail('expected authdata not seen for cross-realm TGT request')
if '512: ' in out:
    fail('SIGNTICKET authdata seen in cross-realm TGT')

realm.stop()

if not os.path.exists(os.path.join(plugins, 'preauth', 'pkinit.so')):
    skipped('anonymous ticket authdata tests', 'PKINIT not built')
else:
    # Set up a realm with PKINIT support and get anonymous tickets.
    certs = os.path.join(srctop, 'tests', 'dejagnu', 'pkinit-certs')
    ca_pem = os.path.join(certs, 'ca.pem')
    kdc_pem = os.path.join(certs, 'kdc.pem')
    privkey_pem = os.path.join(certs, 'privkey.pem')
    pkinit_conf = {'realms': {'$realm': {
                'pkinit_anchors': 'FILE:%s' % ca_pem,
                'pkinit_identity': 'FILE:%s,%s' % (kdc_pem, privkey_pem)}}}
    conf.update(pkinit_conf)
    realm = K5Realm(krb5_conf=conf, get_creds=False)
    realm.addprinc('WELLKNOWN/ANONYMOUS')
    realm.kinit('@%s' % realm.realm, flags=['-n'])

    # SIGNTICKET and module authdata should be suppressed for
    # anonymous tickets, but not request authdata.
    out = realm.run(['./adata', realm.host_princ, '-4', 'test'])
    if ' -4: test' not in out:
        fail('expected authdata not seen for anonymous request')
    if '512: ' in out or '-42: ' in out:
        fail('SIGNTICKET or greet authdata seen for anonymous request')

# KDB authdata is not tested here; we would need a test KDB module to
# generate authdata, and also some additions to the test harness.  The
# current rules we would want to test are:
#
# * The no_auth_data_required server flag suppresses KDB authdata in
#   TGS requests.
# * KDB authdata is also suppressed in TGS requests if the TGT
#   contains no authdata and the request is not cross-realm or S4U.
# * For AS requests, KDB authdata is suppressed if negative
#   KRB5_PADATA_PAC_REQUEST padata is present in the request.
# * KDB authdata is suppressed for anonymous tickets.

success('Authorization data tests')
