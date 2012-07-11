#!/usr/bin/python
from k5test import *

realm = K5Realm(create_host=False)

realm.addprinc('alice', password('alice'))
realm.addprinc('bob', password('bob'))

ccdir = os.path.join(realm.testdir, 'cc')
dccname = 'DIR:%s' % ccdir
duser = 'DIR::%s/tkt1' % ccdir
dalice = 'DIR::%s/tkt2' % ccdir
dbob = 'DIR::%s/tkt3' % ccdir
realm.kinit('user', password('user'), flags=['-c', duser])
realm.kinit('alice', password('alice'), flags=['-c', dalice])
realm.kinit('bob', password('bob'), flags=['-c', dbob])

def cursor_test(testname, args, expected):
    outlines = realm.run_as_client(['./t_cccursor'] + args).splitlines()
    outlines.sort()
    expected.sort()
    if outlines != expected:
        fail('Output not expected for %s\n' % testname +
             'Expected output:\n\n' + '\n'.join(expected) + '\n\n' +
             'Actual output:\n\n' + '\n'.join(outlines))

fccname = 'FILE:%s' % realm.ccache
cursor_test('file-default', [], [fccname])
cursor_test('file-default2', [realm.ccache], [fccname])
cursor_test('file-default3', [fccname], [fccname])

cursor_test('dir', [dccname], [duser, dalice, dbob])

mfoo = 'MEMORY:foo'
mbar = 'MEMORY:bar'
cursor_test('filemem', [fccname, mfoo, mbar], [fccname, mfoo, mbar])
cursor_test('dirmem', [dccname, mfoo], [duser, dalice, dbob, mfoo])

# Test krb5_cccol_have_content.
realm.run_as_client(['./t_cccursor', dccname, 'CONTENT'])
realm.run_as_client(['./t_cccursor', fccname, 'CONTENT'])
realm.run_as_client(['./t_cccursor', realm.ccache, 'CONTENT'])
realm.run_as_client(['./t_cccursor', mfoo, 'CONTENT'], expected_code=1)

# Make sure FILE doesn't yield a nonexistent default cache.
realm.run_as_client([kdestroy])
cursor_test('noexist', [], [])
realm.run_as_client(['./t_cccursor', fccname, 'CONTENT'], expected_code=1)

success('Renewing credentials')
