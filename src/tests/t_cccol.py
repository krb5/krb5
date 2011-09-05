# Copyright (C) 2011 by the Massachusetts Institute of Technology.
# All rights reserved.

# Export of this software from the United States of America may
#   require a specific license from the United States Government.
#   It is the responsibility of any person or organization contemplating
#   export to obtain such a license before exporting.
#
# WITHIN THAT CONSTRAINT, permission to use, copy, modify, and
# distribute this software and its documentation for any purpose and
# without fee is hereby granted, provided that the above copyright
# notice appear in all copies and that both that copyright notice and
# this permission notice appear in supporting documentation, and that
# the name of M.I.T. not be used in advertising or publicity pertaining
# to distribution of the software without specific, written prior
# permission.  Furthermore if you modify this software you must label
# your software as modified software and not distribute it in such a
# fashion that it might be confused with the original M.I.T. software.
# M.I.T. makes no representations about the suitability of
# this software for any purpose.  It is provided "as is" without express
# or implied warranty.

#!/usr/bin/python
from k5test import *

realm = K5Realm(start_kadmind=False, create_user=False, create_host=False)

# Make a directory collection and use it for client commands in both realms.
ccdir = os.path.join(realm.testdir, 'cc')
ccname = 'DIR:' + ccdir
os.mkdir(ccdir)
realm.env_client['KRB5CCNAME'] = ccname

realm.addprinc('alice', password('alice'))
realm.addprinc('bob', password('bob'))
realm.addprinc('carol', password('carol'))

realm.kinit('alice', password('alice'))
output = realm.run_as_client([klist])
if 'Default principal: alice@' not in output:
    fail('Initial kinit failed to get credentials for alice.')
realm.run_as_client([kdestroy])
output = realm.run_as_client([klist], expected_code=1)
if 'No credentials cache found' not in output:
    fail('Initial kdestroy failed to destroy primary cache.')
output = realm.run_as_client([klist, '-l'], expected_code=1)
if not output.endswith('---\n') or output.count('\n') != 2:
    fail('Initial kdestroy failed to empty cache collection.')

realm.kinit('alice', password('alice'))
realm.kinit('carol', password('carol'))
output = realm.run_as_client([klist, '-l'])
if '---\ncarol@' not in output or '\nalice@' not in output:
    fail('klist -l did not show expected output after two kinits.')
realm.kinit('alice', password('alice'))
output = realm.run_as_client([klist, '-l'])
if '---\nalice@' not in output or output.count('\n') != 4:
    fail('klist -l did not show expected output after re-kinit for alice.')
realm.kinit('bob', password('bob'))
output = realm.run_as_client([klist, '-A'])
if 'bob@' not in output.splitlines()[1] or 'alice@' not in output or \
        'carol' not in output or output.count('Default principal:') != 3:
    fail('klist -A did not show expected output after kinit for bob.')
realm.run_as_client([kswitch, '-p', 'carol'])
output = realm.run_as_client([klist, '-l'])
if '---\ncarol@' not in output or output.count('\n') != 5:
    fail('klist -l did not show expected output after kswitch to carol.')
realm.run_as_client([kdestroy])
output = realm.run_as_client([klist, '-l'])
if 'carol@' in output or 'bob@' not in output or output.count('\n') != 4:
    fail('kdestroy failed to remove only primary ccache.')
realm.run_as_client([kdestroy, '-A'])
output = realm.run_as_client([klist, '-l'], expected_code=1)
if not output.endswith('---\n') or output.count('\n') != 2:
    fail('kdestroy -a failed to empty cache collection.')

success('Credential cache collection tests.')
