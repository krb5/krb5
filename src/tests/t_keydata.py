#!/usr/bin/python
from k5test import *

realm = K5Realm(create_user=False, create_host=False)

# Create a principal with no keys.
out = realm.run_kadminl('addprinc -nokey user')
if 'created.' not in out:
    fail('addprinc -nokey')
out = realm.run_kadminl('getprinc user')
if 'Number of keys: 0' not in out:
    fail('getprinc (addprinc -nokey)')

# Change its password and check the resulting kvno.
out = realm.run_kadminl('cpw -pw password user')
if 'changed.' not in out:
    fail('cpw -pw')
out = realm.run_kadminl('getprinc user')
if 'vno 1' not in out:
    fail('getprinc (cpw -pw)')

# Delete all of its keys.
out = realm.run_kadminl('purgekeys -all user')
if 'All keys' not in out or 'removed.' not in out:
    fail('purgekeys')
out = realm.run_kadminl('getprinc user')
if 'Number of keys: 0' not in out:
    fail('getprinc (purgekeys)')

# Randomize its keys and check the resulting kvno.
out = realm.run_kadminl('cpw -randkey user')
if 'randomized.' not in out:
    fail('cpw -randkey')
out = realm.run_kadminl('getprinc user')
if 'vno 1' not in out:
    fail('getprinc (cpw -randkey)')

# Return true if patype appears to have been received in a hint list
# from a KDC error message, based on the trace file fname.
def preauth_type_received(fname, patype):
    f = open(fname, 'r')
    found = False
    for line in f:
        if 'Processing preauth types:' in line:
            ind = line.find('types:')
            patypes = line[ind + 6:].strip().split(', ')
            if str(patype) in patypes:
                found = True
    f.close()
    return found

# Make sure the KDC doesn't offer encrypted timestamp for a principal
# with no keys.
tracefile = os.path.join(realm.testdir, 'trace')
realm.run_kadminl('purgekeys -all user')
realm.run_kadminl('modprinc +requires_preauth user')
realm.run(['env', 'KRB5_TRACE=' + tracefile, kinit, 'user'], expected_code=1)
if preauth_type_received(tracefile, 2):
    fail('encrypted timestamp')

# Make sure it doesn't offer encrypted challenge either.
realm.run_kadminl('addprinc -pw fast armor')
realm.kinit('armor', 'fast')
os.remove(tracefile)
realm.run(['env', 'KRB5_TRACE=' + tracefile, kinit, '-T', realm.ccache,
           'user'], expected_code=1)
if preauth_type_received(tracefile, 138):
    fail('encrypted challenge')

success('Key data tests')
