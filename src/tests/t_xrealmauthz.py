#!/usr/bin/env python3

from k5test import *
import os

# Define realm names for testing topology
REALM1 = 'REALM1.COM'
REALM2 = 'REALM2.COM'
REALM3 = 'REALM3.COM'

# Define capaths configuration to ensure correct realm traversal
capaths_config = {
    'capaths': {
        REALM3: {
            REALM1: [REALM2]  # REALM3 -> REALM2 -> REALM1
        },
        REALM2: {
            REALM1: '.'  # Direct path from REALM2 to REALM1
        }
    }
}

def cleanup():
    """Clean up test directories"""
    testdir = os.path.join(os.getcwd(), 'testdir')
    if os.path.exists(testdir):
        shutil.rmtree(testdir)

def set_enforcing_mode(realm, enforcing):
    """Configure a realm's KDC with specific enforcing mode
    realm - the realm to configure
    enforcing = None -> no kdcdefaults entry
    enforcing = True -> explicitly set to true
    enforcing = False -> explicitly set to false"""

    if enforcing is None:
        mode_kdc_conf = {}
        expected_msg = "enabled"  # Default mode is enforcing
    else:
        mode_kdc_conf = {
            'kdcdefaults': {
                'xrealmauthz_enforcing': 'true' if enforcing else 'false'
            }
        }
        expected_msg = "enabled" if enforcing else "disabled"

    realm.stop_kdc()
    realm_env = realm.special_env('enforce_config', True, kdc_conf=mode_kdc_conf)

    # Clear the KDC log before starting
    kdc_log = os.path.join(realm.testdir, 'kdc.log')
    with open(kdc_log, 'w') as f:
        f.truncate(0)

    realm.start_kdc(env=realm_env)

    # Check for plugin init message
    with open(kdc_log, 'r') as f:
        log_content = f.read()
        expected_init_msg = f"xrealmauthz cross-realm authorization plugin loaded (enforcing mode: {expected_msg},"
        if expected_init_msg not in log_content:
            fail(f'Expected plugin init message with enforcing mode {expected_msg}')

# Helper functions for common operations
def check_would_deny_log(realm):
    """Check KDC log for 'would deny' message and return True if found"""
    kdc_log = os.path.join(realm.testdir, 'kdc.log')
    with open(kdc_log, 'r') as f:
        log_content = f.read()
        return 'would deny' in log_content

def clear_kdc_log(realm):
    """Clear the KDC log file"""
    kdc_log = os.path.join(realm.testdir, 'kdc.log')
    with open(kdc_log, 'w') as f:
        f.truncate(0)

def _get_enforcing_mode_str(enforcing):
    """Helper to get descriptive string for enforcing mode"""
    if enforcing is None:
        return "default mode"
    elif enforcing:
        return "enforcing explicitly enabled"
    else:
        return "enforcing explicitly disabled"

def verify_cross_realm_access(src_realm, dst_realm, client_princ, service_princ,
                            enforcing=None):
    """Verify cross-realm access behavior based on enforcing mode
    Returns True if access was allowed"""
    env = src_realm.env.copy()
    env['KRB5_TRACE'] = '/dev/stderr'

    src_realm.kinit(client_princ, password('user'))

    if enforcing is False:
        clear_kdc_log(dst_realm)
        try:
            src_realm.run([kvno, service_princ], env=env)
            if not check_would_deny_log(dst_realm):
                fail('Expected "would deny" message in KDC log')
            return True
        except Exception as e:
            fail(f'Expected success in non-enforcing mode but got: {str(e)}')
    else:
        # Both enforcing=True and enforcing=None should enforce
        try:
            src_realm.run([kvno, service_princ], env=env, expected_code=1,
                       expected_msg='KDC policy rejects request')
            return False
        except Exception as e:
            fail(f'Expected denial but got: {str(e)}')

def verify_authorized_access(src_realm, dst_realm, client_princ, service_princ):
    """Verify access is allowed when properly authorized"""
    env = src_realm.env.copy()
    env['KRB5_TRACE'] = '/dev/stderr'
    src_realm.kinit(client_princ, password('user'))
    src_realm.run([kvno, service_princ], env=env)

def verify_direct_realm_authz(r1, r2, enforcing=None):
    """Test realm-based authorization with direct trust"""
    env = r2.env.copy()
    env['KRB5_TRACE'] = '/dev/stderr'

    print(f"\nTesting direct realm-based authorization ({_get_enforcing_mode_str(enforcing)}):")

    # Step 1: Verify access is denied/logged without authorization
    verify_cross_realm_access(r2, r1, r2.user_princ, r1.host_princ, enforcing)

    # Step 2: Add realm authorization
    r1.run([kadminl, 'setstr', f'krbtgt/{r1.realm}@{r2.realm}',
            f'xr:@{r2.realm}', '""'])

    # Step 3: Verify access is allowed with authorization
    verify_authorized_access(r2, r1, r2.user_princ, r1.host_princ)

    # Step 4: Remove authorization and verify denial/logging again
    r1.run([kadminl, 'delstr', f'krbtgt/{r1.realm}@{r2.realm}',
            f'xr:@{r2.realm}'])
    verify_cross_realm_access(r2, r1, r2.user_princ, r1.host_princ, enforcing)

def verify_direct_principal_authz(r1, r2, enforcing=None):
    """Test principal-specific authorization with direct trust"""
    env = r2.env.copy()
    env['KRB5_TRACE'] = '/dev/stderr'

    print(f"\nTesting direct principal-specific authorization ({_get_enforcing_mode_str(enforcing)}):")

    # Create test principals
    authorized_princ = 'authz_test'
    unauthorized_princ = 'unauth_test'

    r2.addprinc(authorized_princ, password('user'))
    r2.addprinc(unauthorized_princ, password('user'))

    # Add principal authorization
    r1.run([kadminl, 'setstr', f'krbtgt/{r1.realm}@{r2.realm}',
            f'xr:{authorized_princ}', '""'])

    # Verify authorized principal has access
    verify_authorized_access(r2, r1,
                           authorized_princ + '@' + r2.realm,
                           r1.host_princ)

    # Verify unauthorized principal is denied/logged
    verify_cross_realm_access(r2, r1,
                            unauthorized_princ + '@' + r2.realm,
                            r1.host_princ, enforcing)

    # Remove authorization
    r1.run([kadminl, 'delstr', f'krbtgt/{r1.realm}@{r2.realm}',
            f'xr:{authorized_princ}'])

    # Verify previously authorized principal is now denied/logged
    verify_cross_realm_access(r2, r1,
                            authorized_princ + '@' + r2.realm,
                            r1.host_princ, enforcing)

    # Cleanup
    r2.run([kadminl, 'delprinc', '-force', authorized_princ])
    r2.run([kadminl, 'delprinc', '-force', unauthorized_princ])

def verify_transitive_realm_authz(r1, r2, r3, enforcing=None):
    """Test realm-based authorization with transitive trust"""
    env = r3.env.copy()
    env['KRB5_TRACE'] = '/dev/stderr'

    print(f"\nTesting transitive realm-based authorization ({_get_enforcing_mode_str(enforcing)}):")

    # Step 1: Verify access is denied/logged without authorization
    verify_cross_realm_access(r3, r1, r3.user_princ, r1.host_princ, enforcing)

    # Step 2: Add realm authorization
    r1.run([kadminl, 'setstr', f'krbtgt/{r1.realm}@{r2.realm}',
            f'xr:@{r3.realm}', '""'])

    # Step 3: Verify access is allowed with authorization
    verify_authorized_access(r3, r1, r3.user_princ, r1.host_princ)

    # Step 4: Remove authorization and verify denial/logging again
    r1.run([kadminl, 'delstr', f'krbtgt/{r1.realm}@{r2.realm}',
            f'xr:@{r3.realm}'])
    verify_cross_realm_access(r3, r1, r3.user_princ, r1.host_princ, enforcing)

def verify_transitive_principal_authz(r1, r2, r3, enforcing=None):
    """Test principal-specific authorization with transitive trust"""
    env = r3.env.copy()
    env['KRB5_TRACE'] = '/dev/stderr'

    print(f"\nTesting transitive principal-specific authorization ({_get_enforcing_mode_str(enforcing)}):")

    # Create test principals
    authorized_princ = 'authz_test'
    unauthorized_princ = 'unauth_test'

    r3.addprinc(authorized_princ, password('user'))
    r3.addprinc(unauthorized_princ, password('user'))

    # Add principal authorization using fully qualified name
    full_princ = f"{authorized_princ}@{r3.realm}"
    r1.run([kadminl, 'setstr', f'krbtgt/{r1.realm}@{r2.realm}',
            f'xr:{full_princ}', '""'])

    # Verify authorized principal has access
    verify_authorized_access(r3, r1,
                           authorized_princ + '@' + r3.realm,
                           r1.host_princ)

    # Verify unauthorized principal is denied/logged
    verify_cross_realm_access(r3, r1,
                            unauthorized_princ + '@' + r3.realm,
                            r1.host_princ, enforcing)

    # Remove authorization
    r1.run([kadminl, 'delstr', f'krbtgt/{r1.realm}@{r2.realm}',
            f'xr:{full_princ}'])

    # Verify previously authorized principal is now denied/logged
    verify_cross_realm_access(r3, r1,
                            authorized_princ + '@' + r3.realm,
                            r1.host_princ, enforcing)

    # Cleanup
    r3.run([kadminl, 'delprinc', '-force', authorized_princ])
    r3.run([kadminl, 'delprinc', '-force', unauthorized_princ])

def verify_allowed_realms(r1, r2, r3, enforcing=None):
    """Test pre-approved realms configuration"""

    print(f"\nTesting pre-approved realms ({_get_enforcing_mode_str(enforcing)}):")

    # Test single allowed realm
    allowed_realms_conf = {
        'kdcdefaults': {
            'xrealmauthz_allowed_realms': [REALM2]
        }
    }

    if enforcing is not None:
        allowed_realms_conf['kdcdefaults']['xrealmauthz_enforcing'] = 'true' if enforcing is True else 'false'

    r1.stop_kdc()
    realm_env = r1.special_env('allowed_realms', True, kdc_conf=allowed_realms_conf)
    r1.start_kdc(env=realm_env)

    # Verify REALM2 has immediate access
    verify_authorized_access(r2, r1, r2.user_princ, r1.host_princ)

    # Verify REALM3 still goes through normal authorization and is denied
    verify_cross_realm_access(r3, r1, r3.user_princ, r1.host_princ, enforcing)

    # Test multiple allowed realms
    multi_realm_conf = {
        'kdcdefaults': {
            'xrealmauthz_allowed_realms': [REALM2, REALM3]
        }
    }

    if enforcing is not None:
        allowed_realms_conf['kdcdefaults']['xrealmauthz_enforcing'] = 'true' if enforcing is True else 'false'

    r1.stop_kdc()
    realm_env = r1.special_env('multi_allowed', True, kdc_conf=multi_realm_conf)
    r1.start_kdc(env=realm_env)

    # Verify both realms have immediate access
    verify_authorized_access(r2, r1, r2.user_princ, r1.host_princ)
    verify_authorized_access(r3, r1, r3.user_princ, r1.host_princ)

def main():
    """Main test sequence"""
    try:
        cleanup()

        plugin_filename = 'xrealmauthz.so'
        paths_to_check = [
            os.path.join(os.getcwd(), plugin_filename), # Current directory
            os.path.join(os.getcwd(), '../build', os.environ.get('ID_EXEC',''), plugin_filename), # Standalone build
            os.path.abspath(os.path.join(buildtop, 'plugins', # MIT krb5 source tree
                                        'kdcpolicy', 'xrealmauthz', plugin_filename))
        ]

        for path in paths_to_check:
            print(path)
            if os.path.exists(path):
                plugin_path = path
                break
        else:
            fail('Plugin file not found in any of the expected locations')

        print('Using plugin at:', plugin_path)

        try:
            testdir = os.path.join(os.getcwd(), 'testdir')
            os.makedirs(testdir, exist_ok=True)
            if not os.path.exists(testdir):
                print(f"Failed to create testdir - path doesn't exist after makedirs!")

            for i in range(1, 4):
                realm_dir = os.path.join(testdir, str(i))
                os.makedirs(realm_dir, exist_ok=True)
                if not os.path.exists(realm_dir):
                    print(f"Failed to create realm dir - path doesn't exist after makedirs!")

        except Exception as e:
            print(f"Error creating directories: {str(e)}")
            print(f"Current working directory: {os.getcwd()}")
            print(f"Current user: {os.getuid()}")
            print(f"Directory permissions of parent: {oct(os.stat(os.getcwd()).st_mode)}")

        # Create test directory structure
        testdir = os.path.join(os.getcwd(), 'testdir')
        os.makedirs(testdir, exist_ok=True)
        for i in range(1, 4):
            realm_dir = os.path.join(testdir, str(i))
            os.makedirs(realm_dir, exist_ok=True)

        # Configure realm1 with the plugin
        realm1_kdc_conf = {
            'plugins': {
                'kdcpolicy': {
                    'module': 'xrealmauthz:' + plugin_path
                }
            }
        }

        # Set up three realms for all tests
        # REALM1 <- REALM2 <- REALM3 for transitive tests
        # REALM1 <- REALM2 direct trust is used for direct tests
        mark('creating realms')
        realms = cross_realms(3,
                            xtgts=((1,0), (2,1)),  # Realm2->Realm1, Realm3->Realm2
                            args=({'realm': REALM1,
                                  'kdc_conf': realm1_kdc_conf,
                                  'krb5_conf': capaths_config,
                                  'testdir': os.path.join(testdir, '1')},
                                 {'realm': REALM2,
                                  'krb5_conf': capaths_config,
                                  'testdir': os.path.join(testdir, '2')},
                                 {'realm': REALM3,
                                  'krb5_conf': capaths_config,
                                  'testdir': os.path.join(testdir, '3')}))
        r1, r2, r3 = realms

        mark('testing with enforcing enabled via default')
        verify_direct_realm_authz(r1, r2)
        verify_direct_principal_authz(r1, r2)
        verify_transitive_realm_authz(r1, r2, r3)
        verify_transitive_principal_authz(r1, r2, r3)

        mark('testing pre-approved realms')
        verify_allowed_realms(r1, r2, r3)

        mark('testing pre-approved realms with enforcing=true')
        verify_allowed_realms(r1, r2, r3, enforcing=True)

        mark('testing pre-approved realms with enforcing=false')
        verify_allowed_realms(r1, r2, r3, enforcing=False)

        mark('testing with enforcing=true (explicit configuration)')
        set_enforcing_mode(r1, True)
        verify_direct_realm_authz(r1, r2, enforcing=True)
        verify_direct_principal_authz(r1, r2, enforcing=True)
        verify_transitive_realm_authz(r1, r2, r3, enforcing=True)
        verify_transitive_principal_authz(r1, r2, r3, enforcing=True)

        mark('testing with enforcing=false (monitoring/logging mode)')
        set_enforcing_mode(r1, False)
        verify_direct_realm_authz(r1, r2, enforcing=False)
        verify_direct_principal_authz(r1, r2, enforcing=False)
        verify_transitive_realm_authz(r1, r2, r3, enforcing=False)
        verify_transitive_principal_authz(r1, r2, r3, enforcing=False)

        # Clean up
        for realm in realms:
            realm.stop()

        success('Cross-realm authorization tests completed successfully')

    except Exception as e:
        fail(f'Test failed: {str(e)}')
    finally:
        cleanup()

if __name__ == '__main__':
    main()
