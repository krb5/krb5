#!/usr/bin/python
from k5test import *

conf_slave = {'dbmodules': {'db': {'database_name': '$testdir/db.slave'}}}

# kprop/kpropd are the only users of krb5_auth_con_initivector, so run
# this test over all enctypes to exercise mkpriv cipher state.
for realm in multipass_realms(create_user=False):
    slave = realm.special_env('slave', True, kdc_conf=conf_slave)

    # Set up the kpropd acl file.
    acl_file = os.path.join(realm.testdir, 'kpropd-acl')
    acl = open(acl_file, 'w')
    acl.write(realm.host_princ + '\n')
    acl.close()

    # Create the slave db.
    dumpfile = os.path.join(realm.testdir, 'dump')
    realm.run([kdb5_util, 'dump', dumpfile])
    realm.run([kdb5_util, 'load', dumpfile], slave)
    realm.run([kdb5_util, 'stash', '-P', 'master'], slave)

    # Make some changes to the master db.
    realm.addprinc('wakawaka')

    # Start kpropd.
    kpropd = realm.start_kpropd(slave, ['-d', '-t'])

    realm.run([kdb5_util, 'dump', dumpfile])
    realm.run([kprop, '-f', dumpfile, '-P', str(realm.kprop_port()), hostname])
    output('*** kpropd output follows\n')
    while True:
        line = kpropd.stdout.readline()
        if line == '':
            break
        output('kpropd: ' + line)
        if 'Rejected connection' in line:
            fail('kpropd rejected connection from kprop')

            out = realm.run_kadminl('listprincs', slave)
            if 'wakawaka' not in out:
                fail('Slave does not have all principals from master')

success('kprop tests')
