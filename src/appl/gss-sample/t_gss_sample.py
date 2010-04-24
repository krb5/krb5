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

for realm in multipass_realms():
    portstr = str(realm.server_port())
    server = realm.start_server([gss_server, '-port', portstr, 'host'],
                                'starting...')
    output = realm.run_as_client([gss_client, '-port', portstr,
                                  hostname, 'host', 'testmsg'])
    if 'Signature verified.' not in output:
        fail('Expected message not seen in gss-client output')
    stop_daemon(server)

success('GSS sample application')
