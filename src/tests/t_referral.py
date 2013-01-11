#!/usr/bin/python
from k5test import *

# Create a realm where the KDC has a [domain_realm] mapping for 'd'
# and clients will not try to use DNS to look up KDC addresses.  The
# KDC believes it has a cross-realm TGT for REFREALM, but we won't
# actually create REFREALM.
nodns = {'libdefaults': {'dns_lookup_kdc': 'false'}}
drealm = {'domain_realm': {'d': 'REFREALM'}}
realm = K5Realm(krb5_conf=nodns, kdc_conf=drealm, create_host=False)
realm.addprinc('krbtgt/REFREALM')

# Get credentials for a/x.d and check whether the KDC returned a referral.
def test(realm, nametype, expected_ref, msg):
    out = realm.run(['./gcred', nametype, 'a/x.d'], expected_code=1)
    if ((expected_ref and 'Cannot find KDC for realm "REFREALM"' not in out) or
        (not expected_ref and 'not found in Kerberos database' not in out)):
        fail(msg)

# Create a modified KDC environment and restart the KDC.
def restart_kdc(realm, kdc_conf):
    env = realm.special_env('extravars', True, kdc_conf=kdc_conf)
    realm.stop_kdc()
    realm.start_kdc(env=env)

# With no KDC configuration besides [domain_realm], we should get a
# referral for a NT-SRV-HST or NT-SRV-INST server name, but not an
# NT-UNKNOWN or NT-PRINCIPAL server name.
test(realm, 'srv-hst', True, 'srv-hst, no variables')
test(realm, 'srv-inst', True, 'srv-inst, no variables')
test(realm, 'principal', False, 'principal, no variables')
test(realm, 'unknown', False, 'unknown, no variables')

# With host_based_services matching the first server name component
# ("a"), we should get a referral for an NT-UNKNOWN server name.
# host_based_services can appear in either [kdcdefaults] or the realm
# section, with the realm values supplementing the kdcdefaults values.
# NT-SRV-HST server names should be unaffected by host_based_services,
# and NT-PRINCIPAL server names shouldn't get a referral regardless.
restart_kdc(realm, {'kdcdefaults': {'host_based_services': '*'}})
test(realm, 'unknown', True, 'unknown, kdcdefaults hostbased *')
test(realm, 'principal', False, 'principal, kdcdefaults hostbased *')
restart_kdc(realm, {'kdcdefaults': {'host_based_services': ['b', 'a,c']}})
test(realm, 'unknown', True, 'unknown, kdcdefaults hostbased b and a,c')
restart_kdc(realm, {'realms': {'$realm': {'host_based_services': 'a b c'}}})
test(realm, 'unknown', True, 'unknown, realm hostbased a b c')
restart_kdc(realm, {'kdcdefaults': {'host_based_services': 'a'},
                    'realms': {'$realm': {'host_based_services': 'b c'}}})
test(realm, 'unknown', True, 'unknown, kdcdefaults hostbased a (w/ realm)')
restart_kdc(realm, {'kdcdefaults': {'host_based_services': 'b,c'},
                    'realms': {'$realm': {'host_based_services': 'a,b'}}})
test(realm, 'unknown', True, 'unknown, realm hostbased a,b (w/ kdcdefaults)')
restart_kdc(realm, {'kdcdefaults': {'host_based_services': 'b,c'}})
test(realm, 'unknown', False, 'unknown, kdcdefaults hostbased b,c')
test(realm, 'srv-hst', True, 'srv-hst, kdcdefaults hostbased b,c')

# With no_host_referrals matching the first server name component, we
# should not get a referral even for NT-SRV-HOST server names
restart_kdc(realm, {'kdcdefaults': {'no_host_referral': '*'}})
test(realm, 'srv-hst', False, 'srv-hst, kdcdefaults nohost *')
restart_kdc(realm, {'kdcdefaults': {'no_host_referral': ['b', 'a,c']}})
test(realm, 'srv-hst', False, 'srv-hst, kdcdefaults nohost b and a,c')
restart_kdc(realm, {'realms': {'$realm': {'no_host_referral': 'a b c'}}})
test(realm, 'srv-hst', False, 'srv-hst, realm nohost a b c')
restart_kdc(realm, {'kdcdefaults': {'no_host_referral': 'a'},
                    'realms': {'$realm': {'no_host_referral': 'b c'}}})
test(realm, 'srv-hst', False, 'srv-hst, kdcdefaults nohost a (w/ realm)')
restart_kdc(realm, {'kdcdefaults': {'no_host_referral': 'b,c'},
                    'realms': {'$realm': {'no_host_referral': 'a,b'}}})
test(realm, 'srv-hst', False, 'srv-hst, realm nohost a,b (w/ kdcdefaults)')
restart_kdc(realm, {'kdcdefaults': {'no_host_referral': 'b,c'}})
test(realm, 'srv-hst', True, 'srv-hst, kdcdefaults nohost b,c')

# no_host_referrals should override host_based_services for NT-UNKNWON
# server names.
restart_kdc(realm, {'kdcdefaults': {'no_host_referral': '*',
                                    'host_based_services': '*'}})
test(realm, 'unknown', False, 'srv-hst, kdcdefaults nohost * hostbased *')

# Regression test for #7483: a KDC should not return a host referral
# to its own realm.
drealm = {'domain_realm': {'d': 'KRBTEST.COM'}}
realm.stop()
realm = K5Realm(kdc_conf=drealm, create_host=False)
tracefile = os.path.join(realm.testdir, 'trace')
realm.run(['env', 'KRB5_TRACE=' + tracefile, './gcred', 'srv-hst', 'a/x.d@'],
          expected_code=1)
f = open(tracefile, 'r')
trace = f.read()
f.close()
if 'back to same realm' in trace:
    fail('KDC returned referral to service realm')

success('KDC host referral tests')
