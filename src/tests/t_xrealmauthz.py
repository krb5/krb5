#!/usr/bin/env python3

from k5test import *
import os

# Define realm names for testing topology.
REALM1 = 'REALM1.COM'
REALM2 = 'REALM2.COM'
REALM3 = 'REALM3.COM'

# Name the cross-realm TGS for incoming authentications as seen by REALM1.
cross_tgt_name = 'krbtgt/REALM1.COM@REALM2.COM'

# Define capaths configuration to allow authentication from REALM3 via REALM2.
capaths_config = {
    'capaths': {
        REALM3: {REALM1: [REALM2]},  # REALM3 -> REALM2 -> REALM1
        REALM2: {REALM1: '.'}        # Direct path from REALM2 to REALM1
    }
}

# Restart realm's KDC with xrealmauthz_enforcing set to true, false,
# or not set at all if enforcing is None.  Clear the log and look for
# the expected startup message.
def set_enforcing_mode(realm, enforcing):
    if enforcing is None:
        kdc_conf = {}
    else:
        kdc_conf = {'kdcdefaults': {'xrealmauthz_enforcing': str(enforcing)}}
    expected_msg = 'enabled' if enforcing else 'disabled'

    realm.stop_kdc()
    realm_env = realm.special_env('enforce_config', True, kdc_conf=kdc_conf)

    # Clear the KDC log before starting.
    kdc_log = os.path.join(realm.testdir, 'kdc.log')
    with open(kdc_log, 'w') as f:
        f.truncate(0)

    realm.start_kdc(env=realm_env)

    # Check for module initialization message.
    with open(kdc_log, 'r') as f:
        log_content = f.read()
        expected_init_msg = 'loaded (enforcing mode: %s,' % expected_msg
        if expected_init_msg not in log_content:
            fail('could not find module init log message')


# Return true if a "would deny" message is present in the KDC log file.
def check_would_deny_log(realm):
    kdc_log = os.path.join(realm.testdir, 'kdc.log')
    with open(kdc_log, 'r') as f:
        log_content = f.read()
        return 'would deny' in log_content


# Clear the KDC log file.
def clear_kdc_log(realm):
    kdc_log = os.path.join(realm.testdir, 'kdc.log')
    with open(kdc_log, 'w') as f:
        f.truncate(0)


# Return a descriptive string for an enforcing mode.
def enforcing_str(enforcing):
    if enforcing is None:
        return 'default mode'
    elif enforcing:
        return 'enforcing explicitly enabled'
    else:
        return 'enforcing explicitly disabled'


# Test unauthorized cross-realm access with the given enforcing mode.
def test_denied(src_realm, dst_realm, client_princ, service_princ,
                enforcing=None):
    src_realm.kinit(client_princ, password('user'))
    if enforcing is False:
        clear_kdc_log(dst_realm)
        src_realm.run([kvno, service_princ])
        if not check_would_deny_log(dst_realm):
            fail('Expected "would deny" message in KDC log')
    else:
        # Both enforcing=True and enforcing=None should enforce.
        src_realm.run([kvno, service_princ], expected_code=1,
                      expected_msg='KDC policy rejects request')


# Verify that access is allowed when properly authorized.
def test_allowed(src_realm, client_princ, service_princ):
    src_realm.kinit(client_princ, password('user'))
    src_realm.run([kvno, service_princ])


# Test realm-based authorization with direct trust.
def test_direct_realm_authz(r1, r2, enforcing=None):
    mark('direct realm authorization (%s)' % enforcing_str(enforcing))

    # Verify that access is denied without authorization.
    test_denied(r2, r1, r2.user_princ, r1.host_princ, enforcing)

    # Add realm authorization and verify that access is allowed.
    r1.run([kadminl, 'setstr', cross_tgt_name, 'xr:@' + r2.realm, '""'])
    test_allowed(r2, r2.user_princ, r1.host_princ)

    # Remove authorization and verify denial/logging again.
    r1.run([kadminl, 'delstr', cross_tgt_name, 'xr:@' + r2.realm])
    test_denied(r2, r1, r2.user_princ, r1.host_princ, enforcing)


# Test principal-specific authorization with direct trust
def test_direct_principal_authz(r1, r2, enforcing=None):
    mark('direct princ authorization (%s)' % enforcing_str(enforcing))

    # Create test principals.
    authorized_princ = 'authz_test@' + r2.realm
    unauthorized_princ = 'unauth_test@' + r2.realm
    r2.addprinc(authorized_princ, password('user'))
    r2.addprinc(unauthorized_princ, password('user'))

    # Add principal authorization and verify that only
    # authorized_princ has access.
    r1.run([kadminl, 'setstr', cross_tgt_name, 'xr:authz_test', '""'])
    test_allowed(r2, authorized_princ, r1.host_princ)
    test_denied(r2, r1, unauthorized_princ, r1.host_princ, enforcing)

    # Remove authorization and verify that authorized_princ is denied.
    r1.run([kadminl, 'delstr', cross_tgt_name, 'xr:authz_test'])
    test_denied(r2, r1, authorized_princ, r1.host_princ, enforcing)

    # Clean up.
    r2.run([kadminl, 'delprinc', '-force', authorized_princ])
    r2.run([kadminl, 'delprinc', '-force', unauthorized_princ])


# Test realm-based authorization with transitive trust.
def test_transitive_realm_authz(r1, r2, r3, enforcing=None):
    mark('transitive realm authorization (%s)' + enforcing_str(enforcing))

    # Verify that access is denied/logged without authorization.
    test_denied(r3, r1, r3.user_princ, r1.host_princ, enforcing)

    # Add realm authorization and verify that access is allowed.
    r1.run([kadminl, 'setstr', cross_tgt_name, 'xr:@' + r3.realm, '""'])
    test_allowed(r3, r3.user_princ, r1.host_princ)

    # Remove authorization and verify denial/logging again.
    r1.run([kadminl, 'delstr', cross_tgt_name, 'xr:@' + r3.realm])
    test_denied(r3, r1, r3.user_princ, r1.host_princ, enforcing)


# Test principal-specific authorization with transitive trust.
def test_transitive_principal_authz(r1, r2, r3, enforcing=None):
    mark('transitive princ authorization (%s)' % enforcing_str(enforcing))

    # Create test principals.
    authorized_princ = 'authz_test@' + r3.realm
    unauthorized_princ = 'unauth_test@' + r3.realm
    r3.addprinc(authorized_princ, password('user'))
    r3.addprinc(unauthorized_princ, password('user'))

    # Add principal authorization and verify that only
    # authorized_princ has access.
    r1.run([kadminl, 'setstr', cross_tgt_name, 'xr:' + authorized_princ, '""'])
    test_allowed(r3, authorized_princ, r1.host_princ)
    test_denied(r3, r1, unauthorized_princ, r1.host_princ, enforcing)

    # Remove authorization and verify that authorized_princ is denied.
    r1.run([kadminl, 'delstr', cross_tgt_name, 'xr:' + authorized_princ])
    test_denied(r3, r1, authorized_princ, r1.host_princ, enforcing)

    # Clean up.
    r3.run([kadminl, 'delprinc', '-force', authorized_princ])
    r3.run([kadminl, 'delprinc', '-force', unauthorized_princ])


# Test pre-approved realms configuration.
def test_allowed_realms(r1, r2, r3, enforcing=None):
    mark('pre-approved realms (%s)' % enforcing_str(enforcing))

    # Configure a single allowed realm.
    conf = {'kdcdefaults': {'xrealmauthz_allowed_realms': [REALM2]}}
    if enforcing is not None:
        conf['kdcdefaults']['xrealmauthz_enforcing'] = str(enforcing)
    r1.stop_kdc()
    realm_env = r1.special_env('allowed_realms', True, kdc_conf=conf)
    r1.start_kdc(env=realm_env)

    # Verify that REALM2 has full access, but REALM3 still goes
    # through normal authorization and is denied.
    test_allowed(r2, r2.user_princ, r1.host_princ)
    test_denied(r3, r1, r3.user_princ, r1.host_princ, enforcing)

    # Configure multiple allowed realms.
    conf = {'kdcdefaults': {'xrealmauthz_allowed_realms': [REALM2, REALM3]}}
    if enforcing is not None:
        conf['kdcdefaults']['xrealmauthz_enforcing'] = str(enforcing)
    r1.stop_kdc()
    realm_env = r1.special_env('multi_allowed', True, kdc_conf=conf)
    r1.start_kdc(env=realm_env)

    # Verify that both realms have full access.
    test_allowed(r2, r2.user_princ, r1.host_princ)
    test_allowed(r3, r3.user_princ, r1.host_princ)


# Configure realm1 with the xrealmauthz module enabled.
plugin_path = os.path.join(buildtop, 'plugins', 'kdcpolicy', 'xrealmauthz',
                           'xrealmauthz.so')
realm1_kdc_conf = {'plugins': {'kdcpolicy':
                               {'module': 'xrealmauthz:' + plugin_path}}}

# Set up three realms for all tests.
# REALM1 <- REALM2 <- REALM3 for transitive tests
# REALM1 <- REALM2 direct trust is used for direct tests
mark('creating realms')
realms = cross_realms(3, xtgts=((1, 0), (2, 1)),
                      args=({'realm': REALM1, 'krb5_conf': capaths_config,
                             'kdc_conf': realm1_kdc_conf},
                            {'realm': REALM2, 'krb5_conf': capaths_config},
                            {'realm': REALM3, 'krb5_conf': capaths_config}))
r1, r2, r3 = realms

test_direct_realm_authz(r1, r2)
test_direct_principal_authz(r1, r2)
test_transitive_realm_authz(r1, r2, r3)
test_transitive_principal_authz(r1, r2, r3)

test_allowed_realms(r1, r2, r3)
test_allowed_realms(r1, r2, r3, enforcing=True)
test_allowed_realms(r1, r2, r3, enforcing=False)

set_enforcing_mode(r1, True)
test_direct_realm_authz(r1, r2, enforcing=True)
test_direct_principal_authz(r1, r2, enforcing=True)
test_transitive_realm_authz(r1, r2, r3, enforcing=True)
test_transitive_principal_authz(r1, r2, r3, enforcing=True)

set_enforcing_mode(r1, False)
test_direct_realm_authz(r1, r2, enforcing=False)
test_direct_principal_authz(r1, r2, enforcing=False)
test_transitive_realm_authz(r1, r2, r3, enforcing=False)
test_transitive_principal_authz(r1, r2, r3, enforcing=False)

success('Cross-realm authorization tests completed successfully')
