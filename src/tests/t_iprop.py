#!/usr/bin/python

import os
import time

from k5test import *

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

realm.start_kpropd()
realm.run_kadminl('modprinc -allow_tix w')
out = realm.run_as_master([kproplog, '-h'])
if 'Last serial # : 8' not in out:
    fail('Update log on master has incorrect last serial number')

# We need to give iprop (really, a full resync here and maybe an
# incremental) a chance to happen.
#
# Sometimes we need to wait a long time because kpropd's do_iprop()
# can race with kadmind and fail to kadm5 init, which leads -apparently-
# to some backoff effect.
output('Sleeping for 3 seconds\n')
time.sleep(3)

# Now check that iprop happened.  Note that we depend on timing here,
# thus the above sleep, but there's no way to wait synchronously or force
# iprop to happen (since iprop here is a pull system) and then wait for
# it synchronously.
out = realm.run_as_slave([kproplog, '-h'])
if 'Last serial # : 8' not in out:
    fail('Update log on slave has incorrect last serial number')

# Make another change.
realm.run_kadminl('modprinc +allow_tix w')
out = realm.run_as_master([kproplog, '-h'])
if 'Last serial # : 9' not in out:
    fail('Update log on master has incorrect last serial number')

# Check that we're at sno 9 on the slave side too.
output('Sleeping for 3 seconds\n')
time.sleep(3)
out = realm.run_as_slave([kproplog, '-h'])
if 'Last serial # : 9' not in out:
    fail('Update log on slave has incorrect last serial number')

# Reset the ulog on the slave side to force a full resync to the slave.
realm.run_as_slave([kproplog, '-R'])
out = realm.run_as_slave([kproplog, '-h'])
if 'Last serial # : None' not in out:
    fail('Reset of update log on slave failed')
output('Sleeping for 3 seconds\n')
time.sleep(3)
# Check that a full resync happened.
out = realm.run_as_slave([kproplog, '-h'])
if 'Last serial # : 9' not in out:
    fail('Update log on slave has incorrect last serial number')

# Make another change.
realm.run_kadminl('modprinc +allow_tix w')
out = realm.run_as_master([kproplog, '-h'])
if 'Last serial # : 10' not in out:
    fail('Update log on master has incorrect last serial number')

output('Sleeping for 3 seconds\n')
time.sleep(3)
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
output('Sleeping for 3 seconds\n')
time.sleep(3)
# Check that a full resync happened.
out = realm.run_as_slave([kproplog, '-h'])
if 'Last serial # : 1' not in out:
    fail('Update log on slave has incorrect last serial number')

success('iprop tests')
