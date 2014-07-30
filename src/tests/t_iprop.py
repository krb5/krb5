#!/usr/bin/python

import os
import re

from k5test import *

# Read lines from kpropd output until we are synchronized.  Error if
# full_expected is true and we didn't see a full propagation or vice
# versa.
def wait_for_prop(kpropd, full_expected, expected_old, expected_new):
    output('*** Waiting for sync from kpropd\n')
    full_seen = sleep_seen = prodded_after_dump = False
    old_sno = new_sno = -1
    while True:
        line = kpropd.stdout.readline()
        if line == '':
            fail('kpropd process exited unexpectedly')
        output('kpropd: ' + line)

        m = re.match(r'Calling iprop_get_updates_1 \(sno=(\d+) ', line)
        if m:
            if not full_seen:
                old_sno = int(m.group(1))
            # Also record this as the new sno, in case we get back
            # UPDATE_NIL.
            new_sno = int(m.group(1))

        m = re.match(r'Got incremental updates \(sno=(\d+) ', line)
        if m:
            new_sno = int(m.group(1))

        if 'KDC is synchronized' in line or 'Incremental updates:' in line:
            break

        # After a full resync request, these lines could appear in
        # either order.
        if 'Waiting for' in line:
            sleep_seen = True
        if 'load process for full propagation completed' in line:
            full_seen = True
        if sleep_seen and full_seen and not prodded_after_dump:
            # Prod the kpropd parent into getting incrementals after
            # it finishes a DB load.  This will be unnecessary if
            # kpropd is simplified to use a single process.
            kpropd.send_signal(signal.SIGUSR1)
            prodded_after_dump = True

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

    if full_expected and not full_seen:
        fail('Expected full dump but saw only incremental')
    if full_seen and not full_expected:
        fail('Expected incremental prop but saw full dump')
    if old_sno != expected_old:
         fail('Expected old serial %d from kpropd sync' % expected_old)
    if new_sno != expected_new:
         fail('Expected new serial %d from kpropd sync' % expected_new)

    # Wait until kpropd is sleeping before continuing, to avoid races.
    # (This is imperfect since there's there is a short window between
    # the fprintf and the sleep; kpropd will need design changes to
    # fix that.)
    while True:
        line = kpropd.stdout.readline()
        output('kpropd: ' + line)
        if 'Waiting for' in line:
            break
    output('*** Sync complete\n')

# Verify the output of kproplog against the expected number of
# entries, first and last serial number, and a list of principal names
# for the update entrires.
def check_ulog(num, first, last, entries, env=None):
    out = realm.run([kproplog], env=env)
    if 'Number of entries : ' + str(num) + '\n' not in out:
        fail('Expected %d entries' % num)
    if last:
        firststr = first and str(first) or 'None'
        if 'First serial # : ' + firststr + '\n' not in out:
            fail('Expected first serial number %d' % first)
    laststr = last and str(last) or 'None'
    if 'Last serial # : ' + laststr + '\n' not in out:
        fail('Expected last serial number %d' % last)
    assert(len(entries) == num)
    ser = first - 1
    entindex = 0
    for line in out.splitlines():
        m = re.match(r'\tUpdate serial # : (\d+)$', line)
        if m:
            ser = ser + 1
            if m.group(1) != str(ser):
                fail('Expected serial number %d in update entry' % ser)
        m = re.match(r'\tUpdate principal : (.*)$', line)
        if m:
            eprinc = entries[ser - first]
            if m.group(1) != eprinc:
                fail('Expected princ %s in update entry %d' % (eprinc, ser))

# slave1 will receive updates from master, and slave2 will receive
# updates from slave1.  Because of the awkward way iprop and kprop
# port configuration currently works, we need separate config files
# for the slave and master sides of slave1, but they use the same DB
# and ulog file.
conf = {'realms': {'$realm': {'iprop_enable': 'true',
                              'iprop_logfile': '$testdir/db.ulog'}}}
conf_slave1 = {'realms': {'$realm': {'iprop_slave_poll': '600',
                                     'iprop_logfile': '$testdir/ulog.slave1'}},
               'dbmodules': {'db': {'database_name': '$testdir/db.slave1'}}}
conf_slave1m = {'realms': {'$realm': {'iprop_logfile': '$testdir/ulog.slave1',
                                      'iprop_port': '$port8'}},
               'dbmodules': {'db': {'database_name': '$testdir/db.slave1'}}}
conf_slave2 = {'realms': {'$realm': {'iprop_slave_poll': '600',
                                     'iprop_logfile': '$testdir/ulog.slave2',
                                     'iprop_port': '$port8'}},
               'dbmodules': {'db': {'database_name': '$testdir/db.slave2'}}}

realm = K5Realm(kdc_conf=conf, create_user=False, start_kadmind=True)
slave1 = realm.special_env('slave1', True, kdc_conf=conf_slave1)
slave1m = realm.special_env('slave1m', True, kdc_conf=conf_slave1m)
slave2 = realm.special_env('slave2', True, kdc_conf=conf_slave2)

# Define some principal names.  pr3 is long enough to cause internal
# reallocs, but not long enough to grow the basic ulog entry size.
pr1 = 'wakawaka@' + realm.realm
pr2 = 'w@' + realm.realm
c = 'chocolate-flavored-school-bus'
cs = c + '/'
pr3 = (cs + cs + cs + cs + cs + cs + cs + cs + cs + cs + cs + cs + c +
       '@' + realm.realm)

# Create the kpropd ACL file.
acl_file = os.path.join(realm.testdir, 'kpropd-acl')
acl = open(acl_file, 'w')
acl.write(realm.host_princ + '\n')
acl.close()

ulog = os.path.join(realm.testdir, 'db.ulog')
if not os.path.exists(ulog):
    fail('update log not created: ' + ulog)

# Create the principal used to authenticate kpropd to kadmind.
kiprop_princ = 'kiprop/' + hostname
realm.extract_keytab(kiprop_princ, realm.keytab)

# Create the initial slave1 and slave2 databases.
dumpfile = os.path.join(realm.testdir, 'dump')
realm.run([kdb5_util, 'dump', dumpfile])
realm.run([kdb5_util, 'load', dumpfile], slave1)
realm.run([kdb5_util, 'load', dumpfile], slave2)

# Reinitialize the master ulog so we know exactly what to expect in
# it.
realm.run([kproplog, '-R'])
check_ulog(0, 0, 0, [])

# Make some changes to the master DB.
realm.addprinc(pr1)
realm.addprinc(pr3)
realm.addprinc(pr2)
realm.run_kadminl('modprinc -allow_tix ' + pr2)
realm.run_kadminl('modprinc +allow_tix ' + pr2)
check_ulog(5, 1, 5, [pr1, pr3, pr2, pr2, pr2])

# Start kpropd for slave1 and get a full dump from master.
kpropd1 = realm.start_kpropd(slave1, ['-d'])
wait_for_prop(kpropd1, True, 0, 5)
out = realm.run_kadminl('listprincs', slave1)
if pr1 not in out or pr2 not in out or pr3 not in out:
    fail('slave1 does not have all principals from master')
check_ulog(0, 0, 5, [], slave1)

# Make a change and check that it propagates incrementally.
realm.run_kadminl('modprinc -allow_tix ' + pr2)
check_ulog(6, 1, 6, [pr1, pr3, pr2, pr2, pr2, pr2])
kpropd1.send_signal(signal.SIGUSR1)
wait_for_prop(kpropd1, False, 5, 6)
check_ulog(1, 6, 6, [pr2], slave1)
out = realm.run_kadminl('getprinc ' + pr2, slave1)
if 'Attributes: DISALLOW_ALL_TIX' not in out:
    fail('slave1 does not have modification from master')

# Start kadmind -proponly for slave1.  (Use the slave1m environment
# which defines iprop_port to $port8.)
slave1_out_dump_path = os.path.join(realm.testdir, 'dump.slave1.out')
slave2_in_dump_path = os.path.join(realm.testdir, 'dump.slave2.in')
slave2_kprop_port = str(realm.portbase + 9)
slave1m['KPROP_PORT'] = slave2_kprop_port
realm.start_server([kadmind, '-nofork', '-proponly', '-W', '-p', kdb5_util,
                    '-K', kprop, '-F', slave1_out_dump_path], 'starting...',
                   slave1m)

# Start kpropd for slave2.  The -A option isn't needed since we're
# talking to the same host as master (we specify it anyway to exercise
# the code), but slave2 defines iprop_port to $port8 so it will talk
# to slave1.  Get a full dump from slave1.
kpropd2 = realm.start_server([kpropd, '-d', '-D', '-P', slave2_kprop_port,
                              '-f', slave2_in_dump_path, '-p', kdb5_util,
                              '-a', acl_file, '-A', hostname], 'ready', slave2)
wait_for_prop(kpropd2, True, 0, 6)
check_ulog(0, 0, 6, [], slave2)
out = realm.run_kadminl('listprincs', slave1)
if pr1 not in out or pr2 not in out or pr3 not in out:
    fail('slave2 does not have all principals from slave1')

# Make another change and check that it propagates incrementally to
# both slaves.
realm.run_kadminl('modprinc -maxrenewlife "22 hours" ' + pr1)
check_ulog(7, 1, 7, [pr1, pr3, pr2, pr2, pr2, pr2, pr1])
kpropd1.send_signal(signal.SIGUSR1)
wait_for_prop(kpropd1, False, 6, 7)
check_ulog(2, 6, 7, [pr2, pr1], slave1)
out = realm.run_kadminl('getprinc ' + pr1, slave1)
if 'Maximum renewable life: 0 days 22:00:00\n' not in out:
    fail('slave1 does not have modification from master')
kpropd2.send_signal(signal.SIGUSR1)
wait_for_prop(kpropd2, False, 6, 7)
check_ulog(1, 7, 7, [pr1], slave2)
out = realm.run_kadminl('getprinc ' + pr1, slave2)
if 'Maximum renewable life: 0 days 22:00:00\n' not in out:
    fail('slave2 does not have modification from slave1')

# Reset the ulog on slave1 to force a full resync from master.  The
# resync will use the old dump file and then propagate changes.
# slave2 should still be in sync with slave1 after the resync, so make
# sure it doesn't take a full resync.
realm.run([kproplog, '-R'], slave1)
check_ulog(0, 0, 0, [], slave1)
kpropd1.send_signal(signal.SIGUSR1)
wait_for_prop(kpropd1, True, 0, 7)
check_ulog(2, 6, 7, [pr2, pr1], slave1)
kpropd2.send_signal(signal.SIGUSR1)
wait_for_prop(kpropd2, False, 7, 7)
check_ulog(1, 7, 7, [pr1], slave2)

# Make another change and check that it propagates incrementally to
# both slaves.
realm.run_kadminl('modprinc +allow_tix w')
check_ulog(8, 1, 8, [pr1, pr3, pr2, pr2, pr2, pr2, pr1, pr2])
kpropd1.send_signal(signal.SIGUSR1)
wait_for_prop(kpropd1, False, 7, 8)
check_ulog(3, 6, 8, [pr2, pr1, pr2], slave1)
out = realm.run_kadminl('getprinc ' + pr2, slave1)
if 'Attributes:\n' not in out:
    fail('slave1 does not have modification from master')
kpropd2.send_signal(signal.SIGUSR1)
wait_for_prop(kpropd2, False, 7, 8)
check_ulog(2, 7, 8, [pr1, pr2], slave2)
out = realm.run_kadminl('getprinc ' + pr2, slave2)
if 'Attributes:\n' not in out:
    fail('slave2 does not have modification from slave1')

# Create a policy and check that it propagates via full resync.
realm.run_kadminl('addpol -minclasses 2 testpol')
check_ulog(0, 0, 0, [])
kpropd1.send_signal(signal.SIGUSR1)
wait_for_prop(kpropd1, True, 8, 0)
check_ulog(0, 0, 0, [], slave1)
out = realm.run_kadminl('getpol testpol', slave1)
if 'Minimum number of password character classes: 2' not in out:
    fail('slave1 does not have policy from master')
kpropd2.send_signal(signal.SIGUSR1)
wait_for_prop(kpropd2, True, 8, 0)
check_ulog(0, 0, 0, [], slave2)
out = realm.run_kadminl('getpol testpol', slave2)
if 'Minimum number of password character classes: 2' not in out:
    fail('slave2 does not have policy from slave1')

# Modify the policy and test that it also propagates via full resync.
realm.run_kadminl('modpol -minlength 17 testpol')
check_ulog(0, 0, 0, [])
kpropd1.send_signal(signal.SIGUSR1)
wait_for_prop(kpropd1, True, 0, 0)
check_ulog(0, 0, 0, [], slave1)
out = realm.run_kadminl('getpol testpol', slave1)
if 'Minimum password length: 17' not in out:
    fail('slave1 does not have policy change from master')
kpropd2.send_signal(signal.SIGUSR1)
wait_for_prop(kpropd2, True, 0, 0)
check_ulog(0, 0, 0, [], slave2)
out = realm.run_kadminl('getpol testpol', slave2)
if 'Minimum password length: 17' not in out:
    fail('slave2 does not have policy change from slave1')

# Delete the policy and test that it propagates via full resync.
realm.run_kadminl('delpol -force testpol')
check_ulog(0, 0, 0, [])
kpropd1.send_signal(signal.SIGUSR1)
wait_for_prop(kpropd1, True, 0, 0)
check_ulog(0, 0, 0, [], slave1)
out = realm.run_kadminl('getpol testpol', slave1)
if 'Policy does not exist' not in out:
    fail('slave1 did not get policy deletion from master')
kpropd2.send_signal(signal.SIGUSR1)
wait_for_prop(kpropd2, True, 0, 0)
check_ulog(0, 0, 0, [], slave2)
out = realm.run_kadminl('getpol testpol', slave2)
if 'Policy does not exist' not in out:
    fail('slave2 did not get policy deletion from slave1')

# Modify a principal on the master and test that it propagates via
# full resync.  (The master's ulog does not remember the timestamp it
# had at serial number 0, so it does not know that an incremental
# propagation is possible.)
realm.run_kadminl('modprinc -maxlife "10 minutes" ' + pr1)
check_ulog(1, 1, 1, [pr1])
kpropd1.send_signal(signal.SIGUSR1)
wait_for_prop(kpropd1, True, 0, 1)
check_ulog(0, 0, 1, [], slave1)
out = realm.run_kadminl('getprinc ' + pr1, slave1)
if 'Maximum ticket life: 0 days 00:10:00' not in out:
    fail('slave1 does not have modification from master')
kpropd2.send_signal(signal.SIGUSR1)
wait_for_prop(kpropd2, True, 0, 1)
check_ulog(0, 0, 1, [], slave2)
out = realm.run_kadminl('getprinc ' + pr1, slave2)
if 'Maximum ticket life: 0 days 00:10:00' not in out:
    fail('slave2 does not have modification from slave1')

# Delete a principal and test that it propagates incrementally to
# slave1.  slave2 needs another full resync because slave1 no longer
# has serial number 1 in its ulog after processing its first
# incremental update.
realm.run_kadminl('delprinc -force ' + pr3)
check_ulog(2, 1, 2, [pr1, pr3])
kpropd1.send_signal(signal.SIGUSR1)
wait_for_prop(kpropd1, False, 1, 2)
check_ulog(1, 2, 2, [pr3], slave1)
out = realm.run_kadminl('getprinc ' + pr3, slave1)
if 'Principal does not exist' not in out:
    fail('slave1 does not have principal deletion from master')
kpropd2.send_signal(signal.SIGUSR1)
wait_for_prop(kpropd2, True, 1, 2)
check_ulog(0, 0, 2, [], slave2)
out = realm.run_kadminl('getprinc ' + pr3, slave2)
if 'Principal does not exist' not in out:
    fail('slave2 does not have principal deletion from slave1')

# Reset the ulog on the master to force a full resync.
realm.run([kproplog, '-R'])
check_ulog(0, 0, 0, [])
kpropd1.send_signal(signal.SIGUSR1)
wait_for_prop(kpropd1, True, 2, 0)
check_ulog(0, 0, 0, [], slave1)
kpropd2.send_signal(signal.SIGUSR1)
wait_for_prop(kpropd2, True, 2, 0)
check_ulog(0, 0, 0, [], slave2)

success('iprop tests')
