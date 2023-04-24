from k5test import *

realm = K5Realm(create_host=False)

mark('Fallback to primary KDC')

# Create a replica database and start a KDC.
conf_rep = {'dbmodules': {'db': {'database_name': '$testdir/db.replica2'}},
            'realms': {'$realm': {'kdc_listen': '$port9',
                                  'kdc_tcp_listen': '$port9'}}}
replica = realm.special_env('replica', True, kdc_conf=conf_rep)
dumpfile = os.path.join(realm.testdir, 'dump')
realm.run([kdb5_util, 'dump', dumpfile])
realm.run([kdb5_util, 'load', dumpfile], env=replica)
replica_kdc = realm.start_server([krb5kdc, '-n'], 'starting...', env=replica)

# Change the password on the primary.
realm.run([kadminl, 'cpw', '-pw', 'new', realm.user_princ])

conf_fallback = {'realms': {'$realm': {'kdc': '$hostname:$port9',
                                       'primary_kdc': '$hostname:$port0'}}}
fallback = realm.special_env('fallback', False, krb5_conf=conf_fallback)
msgs = ('Retrying AS request with primary KDC',)
realm.kinit(realm.user_princ, 'new', env=fallback, expected_trace=msgs)

stop_daemon(replica_kdc)

success('sendto_kdc')
