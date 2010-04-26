# Copyright (C) 2010 by the Massachusetts Institute of Technology.
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

#!/usr/bin/python
from k5test import *

appdir = os.path.join(buildtop, 'appl', 'gss-sample')
gss_client = os.path.join(appdir, 'gss-client')
gss_server = os.path.join(appdir, 'gss-server')

# Run a gss-server process and a gss-client process, with additional
# gss-client flags given by options.  Verify that gss-client displayed
# the expected output for a successful negotiation, and that we
# obtained credentials for the host service.
def server_client_test(realm, options):
    portstr = str(realm.server_port())
    server = realm.start_server([gss_server, '-port', portstr, 'host'],
                                'starting...')
    output = realm.run_as_client([gss_client, '-port', portstr] + options +
                                 [hostname, 'host', 'testmsg'])
    if 'Signature verified.' not in output:
        fail('Expected message not seen in gss-client output')
    stop_daemon(server)
    realm.klist(realm.user_princ, realm.host_princ)

# Make up a filename to hold user's initial credentials.
def ccache_savefile(realm):
    return os.path.join(realm.testdir, 'ccache.copy')

# Move user's initial credentials into the save file.
def ccache_save(realm):
    os.rename(realm.ccache, ccache_savefile(realm))

# Copy user's initial credentials from the save file into the ccache.
def ccache_restore(realm):
    shutil.copyfile(ccache_savefile(realm), realm.ccache)

# Perform a regular (TGS path) test of the server and client.
def tgs_test(realm, options):
    ccache_restore(realm)
    server_client_test(realm, options)

# Perform a test of the server and client with initial credentials
# obtained through gss_acquire_cred_with_password().
def as_test(realm, options):
    os.remove(realm.ccache)
    server_client_test(realm, options + ['-user', realm.user_princ,
                                         '-pass', password('user')])

for realm in multipass_realms():
    ccache_save(realm)

    tgs_test(realm, ['-krb5'])
    tgs_test(realm, ['-spnego'])
    tgs_test(realm, ['-iakerb'])

    as_test(realm, ['-krb5'])
    as_test(realm, ['-spnego'])
    as_test(realm, ['-iakerb'])

success('GSS sample application')
