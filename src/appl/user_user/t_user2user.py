from k5test import *

# If uuserver is not compiled under -DDEBUG, then set to 0
debug_compiled=1

for realm in multipass_realms():
    # Verify that -allow_svr denies regular TGS requests, but allows
    # user-to-user TGS requests.
    realm.run([kadminl, 'modprinc', '-allow_svr', realm.user_princ])
    realm.run([kvno, realm.user_princ], expected_code=1,
               expected_msg='Server principal valid for user2user only')

    if debug_compiled == 0:
        realm.start_in_inetd(['./uuserver', 'uuserver'], port=9999)
    else:
        srv_output = realm.start_server(['./uuserver', '9999'], 'Server started')

    msg = 'uu-client: server says "Hello, other end of connection."'
    realm.run(['./uuclient', hostname, 'testing message', '9999'],
              expected_msg=msg)


success('User-2-user test programs')
