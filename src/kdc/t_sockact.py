from k5test import *

if not which('systemd-socket-activate'):
    skip_rest('socket activation tests', 'systemd-socket-activate not found')

kdc_conf = {'realms': {'$realm': {
    'kdc_listen': '$testdir/sock1 $testdir/sock2'}}}
realm = K5Realm(kdc_conf=kdc_conf, start_kdc=False)

# systemd-socket-activate will only pass through environment variables
# we tell it.  Tell it everything in the realm environment.
envargs = []
for v in realm.env:
    envargs.append('-E')
    envargs.append(v)
realm.start_server(['systemd-socket-activate', *envargs,
                    '-l', os.path.join(realm.testdir, 'sock1'),
                    krb5kdc, '-n'], 'Listening on')

cconf1 = {'realms': {'$realm': {'kdc': '$testdir/sock1'}}}
env1 = realm.special_env('sock1', False, krb5_conf=cconf1)
realm.kinit(realm.user_princ, password('user'), env=env1)

cconf2 = {'realms': {'$realm': {'kdc': '$testdir/sock2'}}}
env2 = realm.special_env('sock2', False, krb5_conf=cconf2)
realm.kinit(realm.user_princ, password('user'), env=env2)

success('systemd socket activation tests')
