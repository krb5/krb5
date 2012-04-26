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

realm = K5Realm(start_kadmind=True, create_host=False, get_creds=False)

realm.prep_kadmin()

output = realm.run_kadmin('getstrs user')
if '(No string attributes.)' not in output:
    fail('Empty attribute query')

output = realm.run_kadmin('setstr user attr1 value1')
if 'Attribute set for principal' not in output:
    fail('Setting attr1')
output = realm.run_kadmin('setstr user attr2 value2')
if 'Attribute set for principal' not in output:
    fail('Setting attr2')
output = realm.run_kadmin('delstr user attr1')
if 'Attribute removed from principal' not in output:
    fail('Deleting attr1')
output = realm.run_kadmin('setstr user attr3 value3')
if 'Attribute set for principal' not in output:
    fail('Setting attr3')

output = realm.run_kadmin('getstrs user')
if 'attr2: value2' not in output or 'attr3: value3' not in output or \
        'attr1:' in output:
    fail('Final attribute query')

success('KDB string attributes')
