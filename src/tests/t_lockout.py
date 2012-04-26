# Copyright (C) 2010 by the Massachusetts Institute of Technology.
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

realm = K5Realm(create_host=False)

realm.run_kadminl('addpol -maxfailure 2 -failurecountinterval 5m lockout')
realm.run_kadminl('modprinc +requires_preauth -policy lockout user')

# kinit twice with the wrong password.
output = realm.run_as_client([kinit, realm.user_princ], input='wrong\n',
                             expected_code=1)
if 'Password incorrect while getting initial credentials' not in output:
    fail('Expected error message not seen in kinit output')
output = realm.run_as_client([kinit, realm.user_princ], input='wrong\n',
                             expected_code=1)
if 'Password incorrect while getting initial credentials' not in output:
    fail('Expected error message not seen in kinit output')

# Now the account should be locked out.
output = realm.run_as_client([kinit, realm.user_princ], expected_code=1)
if 'Clients credentials have been revoked while getting initial credentials' \
        not in output:
    fail('Expected lockout error message not seen in kinit output')

# Check that modprinc -unlock allows a further attempt.
output = realm.run_kadminl('modprinc -unlock user')
realm.kinit(realm.user_princ, password('user'))

success('Account lockout')

