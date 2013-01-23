#!/usr/bin/python

import os

from k5test import *

# Read lines from kpropd output until we are synchronized.  Error if
# full_expected is true and we didn't see a full propagation or vice
# versa.
def wait_for_prop(kpropd, full_expected):
    output('*** Waiting for sync from kpropd\n')
    full_seen = False
    while True:
        line = kpropd.stdout.readline()
        if line == '':
            fail('kpropd process exited unexpectedly')
        output('kpropd: ' + line)

        if 'KDC is synchronized' in line or 'Incremental updates:' in line:
            output('*** Sync complete\n')
            if full_expected and not full_seen:
                fail('Expected full dump but saw only incremental')
            if full_seen and not full_expected:
                fail('Expected incremental prop but saw full dump')
            return

        if 'load process for full propagation completed' in line:
            full_seen = True
            # kpropd's child process has finished a DB load; make the parent
            # do another iprop request.  This will be unnecessary if kpropd
            # is simplified to use a single process.
            kpropd.send_signal(signal.SIGUSR1)

        # Detect some failure conditions.
        if 'Still waiting for full resync' in line:
            fail('kadmind gave consecutive full resyncs')
        if 'Rejected connection' in line:
            fail('kpropd rejected kprop connection')
        if 'get updates failed' in line:
            fail('iprop_get_updates failed')
        if 'permission denied' in line:
            fail('kadmind denied update')
        if 'error from master' in line or 'error returned from master' in line:
            fail('kadmind reported error')
        if 'invalid return' in line:
            fail('kadmind returned invalid result')


# Verify the iprop log last serial number against an expected value,
# on either the master or slave.
def check_serial(realm, expected, env=None):
    out = realm.run([kproplog, '-h'], env=env)
    if 'Last serial # : ' not in out:
        fail('Unexpected serial number')


conf = {
    'realms': {'$realm': {
            'iprop_enable': 'true',
            'iprop_logfile' : '$testdir/db.ulog'}}}

conf_slave = {
    'realms': {'$realm': {
            'iprop_slave_poll': '600',
            'iprop_logfile' : '$testdir/db.slave.ulog'}},
    'dbmodules': {'db': {'database_name': '$testdir/db.slave'}}}

realm = K5Realm(kdc_conf=conf, create_user=False, start_kadmind=True)
slave = realm.special_env('slave', True, kdc_conf=conf_slave)

ulog = os.path.join(realm.testdir, 'db.ulog')
if not os.path.exists(ulog):
    fail('update log not created: ' + ulog)

# Create the principal used to authenticate kpropd to kadmind.
kiprop_princ = 'kiprop/' + hostname
realm.addprinc(kiprop_princ)
realm.extract_keytab(kiprop_princ, realm.keytab)

# Create the slave db.
dumpfile = os.path.join(realm.testdir, 'dump')
realm.run([kdb5_util, 'dump', dumpfile])
realm.run([kdb5_util, 'load', dumpfile], slave)
realm.run([kdb5_util, 'stash', '-P', 'master'], slave)

# Make some changes to the master db.
realm.addprinc('wakawaka')
# Add a principal enough to make realloc likely, but not enough to grow
# basic ulog entry size.
c = 'chocolate-flavored-school-bus'
cs = c + '/'
longname = cs + cs + cs + cs + cs + cs + cs + cs + cs + cs + cs + cs + c
realm.addprinc(longname)
realm.addprinc('w')
realm.run_kadminl('modprinc -allow_tix w')
realm.run_kadminl('modprinc +allow_tix w')

check_serial(realm, '7')

# Set up the kpropd acl file.
acl_file = os.path.join(realm.testdir, 'kpropd-acl')
acl = open(acl_file, 'w')
acl.write(realm.host_princ + '\n')
acl.close()

# Start kpropd and get a full dump from master.
kpropd = realm.start_kpropd(slave, ['-d'])
wait_for_prop(kpropd, True)
out = realm.run_kadminl('listprincs', slave)
if longname not in out or 'wakawaka' not in out or 'w@' not in out:
    fail('Slave does not have all principals from master')

# Make a change and check that it propagates incrementally.
realm.run_kadminl('modprinc -allow_tix w')
check_serial(realm, '8')
kpropd.send_signal(signal.SIGUSR1)
wait_for_prop(kpropd, False)
check_serial(realm, '8', slave)
out = realm.run_kadminl('getprinc w', slave)
if 'Attributes: DISALLOW_ALL_TIX' not in out:
    fail('Slave does not have modification from master')

# Make another change and check that it propagates incrementally.
realm.run_kadminl('modprinc +allow_tix w')
check_serial(realm, '9')
kpropd.send_signal(signal.SIGUSR1)
wait_for_prop(kpropd, False)
check_serial(realm, '9', slave)
out = realm.run_kadminl('getprinc w', slave)
if 'Attributes:\n' not in out:
    fail('Slave does not have modification from master')

# Reset the ulog on the slave side to force a full resync to the slave.
realm.run([kproplog, '-R'], slave)
check_serial(realm, 'None', slave)
kpropd.send_signal(signal.SIGUSR1)
wait_for_prop(kpropd, True)
check_serial(realm, '9', slave)

# Make another change and check that it propagates incrementally.
realm.run_kadminl('modprinc +allow_tix w')
check_serial(realm, '10')
kpropd.send_signal(signal.SIGUSR1)
wait_for_prop(kpropd, False)
check_serial(realm, '10', slave)
out = realm.run_kadminl('getprinc w', slave)
if 'Attributes:\n' not in out:
    fail('Slave has different state from master')

# Create a policy and check that it propagates via full resync.
realm.run_kadminl('addpol -minclasses 2 testpol')
check_serial(realm, 'None')
kpropd.send_signal(signal.SIGUSR1)
wait_for_prop(kpropd, True)
check_serial(realm, 'None', slave)
out = realm.run_kadminl('getpol testpol', slave)
if 'Minimum number of password character classes: 2' not in out:
    fail('Slave does not have policy from master')

# Modify the policy and test that it also propagates via full resync.
realm.run_kadminl('modpol -minlength 17 testpol')
check_serial(realm, 'None')
kpropd.send_signal(signal.SIGUSR1)
wait_for_prop(kpropd, True)
check_serial(realm, 'None', slave)
out = realm.run_kadminl('getpol testpol', slave)
if 'Minimum password length: 17' not in out:
    fail('Slave does not have policy change from master')

# Delete the policy and test that it propagates via full resync.
realm.run_kadminl('delpol -force testpol')
check_serial(realm, 'None')
kpropd.send_signal(signal.SIGUSR1)
wait_for_prop(kpropd, True)
check_serial(realm, 'None', slave)
out = realm.run_kadminl('getpol testpol', slave)
if 'Policy does not exist' not in out:
    fail('Slave did not get policy deletion from master')

# Reset the ulog on the master side to force a full resync to all slaves.
# XXX Note that we only have one slave in this test, so we can't really
# test this.
realm.run([kproplog, '-R'])
check_serial(realm, 'None')
kpropd.send_signal(signal.SIGUSR1)
wait_for_prop(kpropd, True)
check_serial(realm, 'None', slave)

success('iprop tests')
