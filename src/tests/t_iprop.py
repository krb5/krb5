#!/usr/bin/python

import os
import time

from k5test import *

def wait_for_prop(realm):
    # Make kpropd go if it's sleeping.
    realm.prod_kpropd()

    # Read lines from kpropd output until we are synchronized.
    output('*** Waiting for sync from kpropd\n')
    while True:
        line = realm.read_from_kpropd()
        if line == '':
            fail('kpropd process exited unexpectedly')
        output('kpropd: ' + line)

        if 'KDC is synchronized' in line or 'Got incremental updates' in line:
            output('*** Sync complete\n')
            return

        if 'load process for full propagation completed' in line:
            # kpropd's child process has finished a DB load; make the parent
            # do another iprop request.  This will be unnecessary if kpropd
            # is simplified to use a single process.
            realm.prod_kpropd()

        # Detect some failure conditions.
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


iprop_kdc_conf = {
    'all' : { 'libdefaults' : { 'default_realm' : 'KRBTEST.COM'},
              'realms' : { '$realm' : {
                'iprop_enable' : 'true',
                'iprop_slave_poll' : '1'
                }}},
    'master' : { 'realms' : { '$realm' : {
                'iprop_logfile' : '$testdir/db.ulog'
                }}},
    'slave' : { 'realms' : { '$realm' : {
                'iprop_logfile' : '$testdir/slave-db.ulog'
                }}}
}

realm = K5Realm(kdc_conf=iprop_kdc_conf, create_user=False, start_kadmind=True)

ulog = os.path.join(realm.testdir, 'db.ulog')
if not os.path.exists(ulog):
    fail('update log not created: ' + ulog)

# Create the principal used to authenticate kpropd to kadmind.
kiprop_princ = 'kiprop/' + hostname
realm.addprinc(kiprop_princ)
realm.extract_keytab(kiprop_princ, realm.keytab)

# Create the slave db.
dumpfile = os.path.join(realm.testdir, 'dump')
realm.run_as_master([kdb5_util, 'dump', dumpfile])
realm.run_as_slave([kdb5_util, 'load', dumpfile])
realm.run_as_slave([kdb5_util, 'stash', '-P', 'master'])

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

out = realm.run_as_master([kproplog, '-h'])
if 'Last serial # : 7' not in out:
    fail('Update log on master has incorrect last serial number')

# Set up the kpropd acl file.
acl_file = os.path.join(realm.testdir, 'kpropd-acl')
acl = open(acl_file, 'w')
acl.write(realm.host_princ + '\n')
acl.close()

realm.start_kpropd(['-d'])
realm.run_kadminl('modprinc -allow_tix w')
out = realm.run_as_master([kproplog, '-h'])
if 'Last serial # : 8' not in out:
    fail('Update log on master has incorrect last serial number')

# Check that iprop happened.
wait_for_prop(realm)
out = realm.run_as_slave([kproplog, '-h'])
if 'Last serial # : 8' not in out:
    fail('Update log on slave has incorrect last serial number')

# Make another change.
realm.run_kadminl('modprinc +allow_tix w')
out = realm.run_as_master([kproplog, '-h'])
if 'Last serial # : 9' not in out:
    fail('Update log on master has incorrect last serial number')

# Check that we're at sno 9 on the slave side too.
wait_for_prop(realm)
out = realm.run_as_slave([kproplog, '-h'])
if 'Last serial # : 9' not in out:
    fail('Update log on slave has incorrect last serial number')

# Reset the ulog on the slave side to force a full resync to the slave.
realm.run_as_slave([kproplog, '-R'])
out = realm.run_as_slave([kproplog, '-h'])
if 'Last serial # : None' not in out:
    fail('Reset of update log on slave failed')
wait_for_prop(realm)
# Check that a full resync happened.
out = realm.run_as_slave([kproplog, '-h'])
if 'Last serial # : 9' not in out:
    fail('Update log on slave has incorrect last serial number')

# Make another change.
realm.run_kadminl('modprinc +allow_tix w')
out = realm.run_as_master([kproplog, '-h'])
if 'Last serial # : 10' not in out:
    fail('Update log on master has incorrect last serial number')

wait_for_prop(realm)
out = realm.run_as_slave([kproplog, '-h'])
if 'Last serial # : 10' not in out:
    fail('Update log on slave has incorrect last serial number')

# Reset the ulog on the master side to force a full resync to all slaves.
# XXX Note that we only have one slave in this test, so we can't really
# test this.
realm.run_as_master([kproplog, '-R'])
out = realm.run_as_master([kproplog, '-h'])
if 'Last serial # : None' not in out:
    fail('Reset of update log on master failed')
realm.run_kadminl('modprinc -allow_tix w')
out = realm.run_as_master([kproplog, '-h'])
if 'Last serial # : 1' not in out:
    fail('Update log on master has incorrect last serial number')
wait_for_prop(realm)
# Check that a full resync happened.
out = realm.run_as_slave([kproplog, '-h'])
if 'Last serial # : 1' not in out:
    fail('Update log on slave has incorrect last serial number')

success('iprop tests')
