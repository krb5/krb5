#!/usr/bin/python
from k5test import *

# Create a pair of realms, where KRBTEST1.COM can authenticate to
# REFREALM and has a domain-realm mapping for 'd' pointing to it.
drealm = {'domain_realm': {'d': 'REFREALM'}}
realm, refrealm = cross_realms(2, xtgts=((0,1),),
                               args=({'kdc_conf': drealm},
                                     {'realm': 'REFREALM',
                                      'create_user': False}),
                               create_host=False)
realm.addprinc('krbtgt/REFREALM')
refrealm.addprinc('a/x.d')

savefile = os.path.join(realm.testdir, 'ccache.copy')
os.rename(realm.ccache, savefile)

# Get credentials and check that we got a referral to REFREALM.
def testref(realm, nametype):
    shutil.copyfile(savefile, realm.ccache)
    realm.run(['./gcred', nametype, 'a/x.d'])
    realm.klist(realm.user_princ, 'a/x.d@REFREALM')

# Get credentials and check that we get an error, not a referral.
def testfail(realm, nametype):
    shutil.copyfile(savefile, realm.ccache)
    out = realm.run(['./gcred', nametype, 'a/x.d'], expected_code=1)
    if 'not found in Kerberos database' not in out:
        fail('unexpected error')

# Create a modified KDC environment and restart the KDC.
def restart_kdc(realm, kdc_conf):
    env = realm.special_env('extravars', True, kdc_conf=kdc_conf)
    realm.stop_kdc()
    realm.start_kdc(env=env)

# With no KDC configuration besides [domain_realm], we should get a
# referral for a NT-SRV-HST or NT-SRV-INST server name, but not an
# NT-UNKNOWN or NT-PRINCIPAL server name.
testref(realm, 'srv-hst')
testref(realm, 'srv-inst')
testfail(realm, 'principal')
testfail(realm, 'unknown')

# With host_based_services matching the first server name component
# ("a"), we should get a referral for an NT-UNKNOWN server name.
# host_based_services can appear in either [kdcdefaults] or the realm
# section, with the realm values supplementing the kdcdefaults values.
# NT-SRV-HST server names should be unaffected by host_based_services,
# and NT-PRINCIPAL server names shouldn't get a referral regardless.
restart_kdc(realm, {'kdcdefaults': {'host_based_services': '*'}})
testref(realm, 'unknown')
testfail(realm, 'principal')
restart_kdc(realm, {'kdcdefaults': {'host_based_services': ['b', 'a,c']}})
testref(realm, 'unknown')
restart_kdc(realm, {'realms': {'$realm': {'host_based_services': 'a b c'}}})
testref(realm, 'unknown')
restart_kdc(realm, {'kdcdefaults': {'host_based_services': 'a'},
                    'realms': {'$realm': {'host_based_services': 'b c'}}})
testref(realm, 'unknown')
restart_kdc(realm, {'kdcdefaults': {'host_based_services': 'b,c'},
                    'realms': {'$realm': {'host_based_services': 'a,b'}}})
testref(realm, 'unknown')
restart_kdc(realm, {'kdcdefaults': {'host_based_services': 'b,c'}})
testfail(realm, 'unknown')
testref(realm, 'srv-hst')

# With no_host_referrals matching the first server name component, we
# should not get a referral even for NT-SRV-HOST server names
restart_kdc(realm, {'kdcdefaults': {'no_host_referral': '*'}})
testfail(realm, 'srv-hst')
restart_kdc(realm, {'kdcdefaults': {'no_host_referral': ['b', 'a,c']}})
testfail(realm, 'srv-hst')
restart_kdc(realm, {'realms': {'$realm': {'no_host_referral': 'a b c'}}})
testfail(realm, 'srv-hst')
restart_kdc(realm, {'kdcdefaults': {'no_host_referral': 'a'},
                    'realms': {'$realm': {'no_host_referral': 'b c'}}})
testfail(realm, 'srv-hst')
restart_kdc(realm, {'kdcdefaults': {'no_host_referral': 'b,c'},
                    'realms': {'$realm': {'no_host_referral': 'a,b'}}})
testfail(realm, 'srv-hst')
restart_kdc(realm, {'kdcdefaults': {'no_host_referral': 'b,c'}})
testref(realm, 'srv-hst')

# no_host_referrals should override host_based_services for NT-UNKNWON
# server names.
restart_kdc(realm, {'kdcdefaults': {'no_host_referral': '*',
                                    'host_based_services': '*'}})
testfail(realm, 'unknown')

realm.stop()
refrealm.stop()

# Regression test for #7483: a KDC should not return a host referral
# to its own realm.
drealm = {'domain_realm': {'d': 'KRBTEST.COM'}}
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
