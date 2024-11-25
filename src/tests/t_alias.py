from k5test import *

for realm in multidb_realms(create_kdb=True, create_host=True):
    # Test that KDB drivers support aliases
    keytab = realm.keytab + '.' + realm._kdc_conf['dbmodules']['db']['db_library']
    localhost_princ = 'nfs/localhost'
    realm.run([kadminl,
               'addprinc', '-nokey', '-x', 'alias='+realm.host_princ,
               realm.nfs_princ])
    # Add alias without realm. The string alias=principal will be written as it is
    # to the database and will have to be normalized by the KDB in get_principal()
    realm.run([kadminl,
               'addprinc', '-nokey',
               '-x', 'alias='+realm.host_princ.rpartition('@')[0],
               localhost_princ])
    realm.run([kadminl, 'getprinc', realm.nfs_princ])
    realm.run([kadminl, 'getprinc', localhost_princ])
    realm.run([kadminl, 'getprinc', realm.host_princ])
    realm.run([kadminl, 'ktadd', '-norandkey', '-k', keytab, realm.nfs_princ])
    realm.run([kadminl, 'ktadd', '-norandkey', '-k', keytab, localhost_princ])
    realm.run([klist, '-kt', keytab, '-eK'])
    realm.run([kinit, '-kt', keytab, realm.nfs_princ])
    realm.klist(realm.nfs_princ)
    realm.run([kinit, '-kt', keytab, localhost_princ])
    realm.klist(localhost_princ + '@' + realm.realm)
    realm.stop()

success('define alias to existing principal')
