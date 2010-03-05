#!/usr/bin/python
from k5test import *

for realm in multipass_realms():
    realm.run_as_client(['./t_spnego', realm.host_princ, realm.keytab])

success('GSSAPI test programs (SPNEGO only).')
