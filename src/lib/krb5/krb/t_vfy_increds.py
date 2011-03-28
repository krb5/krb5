#!/usr/bin/python

# Copyright (C) 2011 by the Massachusetts Institute of Technology.
# All rights reserved.
#
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

from k5test import *

realm = K5Realm(start_kadmind=False)

# Verify the default.
realm.run_as_server(['./t_vfy_increds'])

# Verify after updating the keytab (so the keytab contains an outdated
# version 1 key followed by an up-to-date version 2 key).
realm.run_kadminl('ktadd ' + realm.host_princ)
realm.run_as_server(['./t_vfy_increds'])

# Bump the host key without updating the keytab and make sure that
# verification fails as we expect it to.
realm.run_kadminl('change_password -randkey ' + realm.host_princ)
realm.run_as_server(['./t_vfy_increds'], expected_code=1)

# Remove the keytab and verify again.  This should succeed because
# verify_ap_req_nofail is not set.
os.remove(realm.keytab)
realm.run_as_server(['./t_vfy_increds'])

# Try with verify_ap_req_nofail set and no keytab.  This should fail.
realm.stop()
conf = { 'server' : { 'libdefaults' : { 'verify_ap_req_nofail' : 'true' } } }
realm = K5Realm(start_kadmind=False, krb5_conf=conf)
os.remove(realm.keytab)
realm.run_as_server(['./t_vfy_increds'], expected_code=1)

success('krb5_verify_init_creds tests.')
