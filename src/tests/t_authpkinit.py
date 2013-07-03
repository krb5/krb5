#!/usr/bin/python
from k5test import *

# Skip this test if pkinit wasn't built.
if not os.path.exists(os.path.join(plugins, 'preauth', 'pkinit.so')):
    success('Warning: not testing pkinit because it is not built')
    exit(0)

# Check if soft-pkcs11.so is available.
have_soft_pkcs11 = False
try:
    import ctypes
    lib = ctypes.LibraryLoader(ctypes.CDLL).LoadLibrary('soft-pkcs11.so')
    del lib
    have_soft_pkcs11 = True
except:
    have_soft_pkcs11 = False

# Construct a krb5.conf fragment configuring pkinit.
certs = os.path.join(srctop, 'tests', 'dejagnu', 'pkinit-certs')
ca_pem = os.path.join(certs, 'ca.pem')
kdc_pem = os.path.join(certs, 'kdc.pem')
user_pem = os.path.join(certs, 'user.pem')
privkey_pem = os.path.join(certs, 'privkey.pem')
privkey_enc_pem = os.path.join(certs, 'privkey-enc.pem')
user_p12 = os.path.join(certs, 'user.p12')
user_enc_p12 = os.path.join(certs, 'user-enc.p12')
path = os.path.join(os.getcwd(), 'testdir', 'tmp-pkinit-certs')
path_enc = os.path.join(os.getcwd(), 'testdir', 'tmp-pkinit-certs-enc')

pkinit_krb5_conf = {
    'realms': {'$realm': {
            'pkinit_anchors': 'FILE:%s' % ca_pem,
            'pkinit_identity': 'FILE:%s,%s' % (kdc_pem, privkey_pem)}}}
pkinit_kdc_conf = {
    'realms': {'$realm': {
            'default_principal_flags': '+preauth',
            'pkinit_eku_checking': 'none'}}}

file_identity = 'FILE:%s,%s' % (user_pem, privkey_pem)
file_enc_identity = 'FILE:%s,%s' % (user_pem, privkey_enc_pem)
dir_identity = 'DIR:%s' % path
dir_enc_identity = 'DIR:%s' % path_enc
dir_file_identity = 'FILE:%s,%s' % (os.path.join(path, 'user.crt'),
                                    os.path.join(path, 'user.key'))
dir_file_enc_identity = 'FILE:%s,%s' % (os.path.join(path_enc, 'user.crt'),
                                        os.path.join(path_enc, 'user.key'))
p12_identity = 'PKCS12:%s' % user_p12
p12_enc_identity = 'PKCS12:%s' % user_enc_p12
p11_identity = 'PKCS11:soft-pkcs11.so'
p11_token_identity = ('PKCS11:module_name=soft-pkcs11.so:'
                      'slotid=1:token=SoftToken (token)')

# Set up the DIR: identities.  They go away as a side-effect of reinitializing
# the realm testdir, so we don't have a specific cleanup method.
def setup_dir_identities(realm):
    os.mkdir(path)
    os.mkdir(path_enc)
    shutil.copy(privkey_pem, os.path.join(path, 'user.key'))
    shutil.copy(privkey_enc_pem, os.path.join(path_enc, 'user.key'))
    shutil.copy(user_pem, os.path.join(path, 'user.crt'))
    shutil.copy(user_pem, os.path.join(path_enc, 'user.crt'))

# Run the basic test - PKINIT with FILE: identity, with no password on the key.
realm = K5Realm(krb5_conf=pkinit_krb5_conf, kdc_conf=pkinit_kdc_conf,
                get_creds=False)
realm.run(['./responder',
           '-x',
           'pkinit={}',
           '-X',
           'X509_user_identity=%s' % file_identity,
           'user@%s' % realm.realm])
realm.kinit('user@%s' % realm.realm,
            flags=['-X', 'X509_user_identity=%s' % file_identity])
realm.klist('user@%s' % realm.realm)
realm.run([kvno, realm.host_princ])
realm.stop()

# Run the basic test - PKINIT with FILE: identity, with a password on the key,
# supplied by the prompter.
realm = K5Realm(krb5_conf=pkinit_krb5_conf, kdc_conf=pkinit_kdc_conf,
                get_creds=False)
# Expect failure if the responder does nothing, and we have no prompter.
realm.run(['./responder',
          '-x',
          'pkinit={"%s": 0}' % file_enc_identity,
          '-X',
          'X509_user_identity=%s' % file_enc_identity,
          'user@%s' % realm.realm],
          expected_code=2)
realm.kinit('user@%s' % realm.realm,
            flags=['-X', 'X509_user_identity=%s' % file_enc_identity],
            password='encrypted')
realm.klist('user@%s' % realm.realm)
realm.run([kvno, realm.host_princ])
realm.stop()

# Run the basic test - PKINIT with FILE: identity, with a password on the key,
# supplied by the responder.
realm = K5Realm(krb5_conf=pkinit_krb5_conf, kdc_conf=pkinit_kdc_conf,
                get_creds=False)
# Supply the response in raw form.
realm.run(['./responder',
           '-x',
           'pkinit={"%s": 0}' % file_enc_identity,
           '-r',
           'pkinit={"%s": "encrypted"}' % file_enc_identity,
           '-X',
           'X509_user_identity=%s' % file_enc_identity,
           'user@%s' % realm.realm])
# Supply the response through the convenience API.
realm.run(['./responder',
           '-X',
           'X509_user_identity=%s' % file_enc_identity,
           '-p',
           '%s=%s' % (file_enc_identity, 'encrypted'),
           'user@%s' % realm.realm])
realm.klist('user@%s' % realm.realm)
realm.run([kvno, realm.host_princ])
realm.stop()

# PKINIT with DIR: identity, with no password on the key.
realm = K5Realm(krb5_conf=pkinit_krb5_conf, kdc_conf=pkinit_kdc_conf,
                get_creds=False)
setup_dir_identities(realm)
realm.run(['./responder',
           '-x',
           'pkinit={}',
           '-X',
           'X509_user_identity=%s' % dir_identity,
           'user@%s' % realm.realm])
realm.kinit('user@%s' % realm.realm,
            flags=['-X', 'X509_user_identity=%s' % dir_identity])
realm.klist('user@%s' % realm.realm)
realm.run([kvno, realm.host_princ])
realm.stop()

# PKINIT with DIR: identity, with a password on the key, supplied by the
# prompter.
realm = K5Realm(krb5_conf=pkinit_krb5_conf, kdc_conf=pkinit_kdc_conf,
                get_creds=False)
setup_dir_identities(realm)
# Expect failure if the responder does nothing, and we have no prompter.
realm.run(['./responder',
           '-x',
           'pkinit={"%s": 0}' %
           dir_file_enc_identity,
           '-X',
           'X509_user_identity=%s' % dir_enc_identity,
           'user@%s' % realm.realm],
           expected_code=2)
realm.kinit('user@%s' % realm.realm,
            flags=['-X', 'X509_user_identity=%s' % dir_enc_identity],
            password='encrypted')
realm.klist('user@%s' % realm.realm)
realm.run([kvno, realm.host_princ])
realm.stop()

# PKINIT with DIR: identity, with a password on the key, supplied by the
# responder.
realm = K5Realm(krb5_conf=pkinit_krb5_conf, kdc_conf=pkinit_kdc_conf,
                get_creds=False)
setup_dir_identities(realm)
# Supply the response in raw form.
realm.run(['./responder',
           '-x',
           'pkinit={"%s": 0}' %
           dir_file_enc_identity,
           '-r',
           'pkinit={"%s": "encrypted"}' % dir_file_enc_identity,
           '-X',
           'X509_user_identity=%s' % dir_enc_identity,
           'user@%s' % realm.realm])
# Supply the response through the convenience API.
realm.run(['./responder',
           '-X',
           'X509_user_identity=%s' % dir_enc_identity,
           '-p',
           '%s=%s' % (dir_file_enc_identity, 'encrypted'),
           'user@%s' % realm.realm])
realm.klist('user@%s' % realm.realm)
realm.run([kvno, realm.host_princ])
realm.stop()

# PKINIT with PKCS12: identity, with no password on the bundle.
realm = K5Realm(krb5_conf=pkinit_krb5_conf, kdc_conf=pkinit_kdc_conf,
                get_creds=False)
realm.run(['./responder',
           '-x',
           'pkinit={}',
           '-X',
           'X509_user_identity=%s' % p12_identity,
           'user@%s' % realm.realm])
realm.kinit('user@%s' % realm.realm,
            flags=['-X', 'X509_user_identity=%s' % p12_identity])
realm.klist('user@%s' % realm.realm)
realm.run([kvno, realm.host_princ])
realm.stop()

# PKINIT with PKCS12: identity, with a password on the bundle, supplied by the
# prompter.
realm = K5Realm(krb5_conf=pkinit_krb5_conf, kdc_conf=pkinit_kdc_conf,
                get_creds=False)
# Expect failure if the responder does nothing, and we have no prompter.
realm.run(['./responder',
           '-x',
           'pkinit={"%s": 0}' % p12_enc_identity,
           '-X',
           'X509_user_identity=%s' % p12_enc_identity,
           'user@%s' % realm.realm],
           expected_code=2)
realm.kinit('user@%s' % realm.realm,
            flags=['-X', 'X509_user_identity=%s' % p12_enc_identity],
            password='encrypted')
realm.klist('user@%s' % realm.realm)
realm.run([kvno, realm.host_princ])
realm.stop()

# PKINIT with PKCS12: identity, with a password on the bundle, supplied by the
# responder.
realm = K5Realm(krb5_conf=pkinit_krb5_conf, kdc_conf=pkinit_kdc_conf,
                get_creds=False)
# Supply the response in raw form.
realm.run(['./responder',
           '-x',
           'pkinit={"%s": 0}' % p12_enc_identity,
           '-r',
           'pkinit={"%s": "encrypted"}' % p12_enc_identity,
           '-X',
           'X509_user_identity=%s' % p12_enc_identity,
           'user@%s' % realm.realm])
# Supply the response through the convenience API.
realm.run(['./responder',
           '-X',
           'X509_user_identity=%s' % p12_enc_identity,
           '-p',
           '%s=%s' % (p12_enc_identity, 'encrypted'),
           'user@%s' % realm.realm])
realm.klist('user@%s' % realm.realm)
realm.run([kvno, realm.host_princ])
realm.stop()

if have_soft_pkcs11:
    os.environ['SOFTPKCS11RC'] = os.path.join(os.getcwd(), 'testdir',
                                              'soft-pkcs11.rc')

    # PKINIT with PKCS11: identity, with a PIN supplied by the prompter.
    realm = K5Realm(krb5_conf=pkinit_krb5_conf, kdc_conf=pkinit_kdc_conf,
                    get_creds=False)
    conf = open(os.environ['SOFTPKCS11RC'], 'w')
    conf.write("%s\t%s\t%s\t%s\n" % ('user', 'user token', user_pem,
                                     privkey_enc_pem))
    conf.close()
    # Expect failure if the responder does nothing, and there's no prompter
    realm.run(['./responder',
               '-x',
               'pkinit={"%s": 0}' % p11_token_identity,
               '-X',
               'X509_user_identity=%s' % p11_identity,
               'user@%s' % realm.realm],
               expected_code=2)
    realm.kinit('user@%s' % realm.realm,
                flags=['-X', 'X509_user_identity=%s' % p11_identity],
                password='encrypted')
    realm.klist('user@%s' % realm.realm)
    realm.run([kvno, realm.host_princ])
    realm.stop()

    # PKINIT with PKCS11: identity, with a PIN supplied by the responder.
    realm = K5Realm(krb5_conf=pkinit_krb5_conf, kdc_conf=pkinit_kdc_conf,
                    get_creds=False)
    conf = open(os.environ['SOFTPKCS11RC'], 'w')
    conf.write("%s\t%s\t%s\t%s\n" % ('user', 'user token', user_pem,
                                     privkey_enc_pem))
    conf.close()
    # Supply the response in raw form.
    realm.run(['./responder',
               '-x',
               'pkinit={"%s": 0}' % p11_token_identity,
               '-r',
               'pkinit={"%s": "encrypted"}' %
               p11_token_identity,
               '-X',
               'X509_user_identity=%s' % p11_identity,
               'user@%s' % realm.realm])
    # Supply the response through the convenience API.
    realm.run(['./responder',
               '-X',
               'X509_user_identity=%s' % p11_identity,
               '-p',
               '%s=%s' % (p11_token_identity, 'encrypted'),
               'user@%s' % realm.realm])
    realm.klist('user@%s' % realm.realm)
    realm.run([kvno, realm.host_princ])
    realm.stop()
else:
    output('soft-pkcs11.so not found: skipping tests with PKCS11 identities\n')

success('Authenticated PKINIT')
