# Author: Nathaniel McCallum <npmccallum@redhat.com>
#
# Copyright (c) 2013 Red Hat, Inc.
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.


#
# This script tests OTP, both UDP and Unix Sockets, with a variety of
# configuration. It requires pyrad to run, but exits gracefully if not found.
# It also deliberately shuts down the test daemons between tests in order to
# test how OTP handles the case of short daemon restarts.
#

from k5test import *

if not have_pyrad:
    skip_rest('OTP tests', 'Python pyrad module not found')

# Compose a single token configuration.
def otpconfig_1(toktype, username=None, indicators=None):
    val = '{"type": "%s"' % toktype
    if username is not None:
        val += ', "username": "%s"' % username
    if indicators is not None:
        qind = ['"%s"' % s for s in indicators]
        jsonlist = '[' + ', '.join(qind) + ']'
        val += ', "indicators":' + jsonlist
    val += '}'
    return val

# Compose a token configuration list suitable for the "otp" string
# attribute.
def otpconfig(toktype, username=None, indicators=None):
    return '[' + otpconfig_1(toktype, username, indicators) + ']'

conf = {'plugins': {'kdcpreauth': {'enable_only': 'otp'}},
        'otp': {'udp': {'server': '127.0.0.1:$port9',
                        'secret': '$testdir/radius.secret',
                        'strip_realm': 'true',
                        'indicator': ['indotp1', 'indotp2']},
                'unix': {'server': '$testdir/radius.socket',
                         'strip_realm': 'false'}}}

realm = K5Realm(kdc_conf=conf)
realm.run([kadminl, 'modprinc', '+requires_preauth', realm.user_princ])
flags = ['-T', realm.ccache]
socket_file = os.path.join(realm.testdir, 'radius.socket')
udp_addr = '127.0.0.1:' + str(realm.portbase + 9)

## Test UDP fail / custom username
mark('UDP fail / custom username')
daemon = start_mockradius(udp_addr, 'accept')
realm.run([kadminl, 'setstr', realm.user_princ, 'otp',
           otpconfig('udp', 'custom')])
realm.kinit(realm.user_princ, 'reject', flags=flags, expected_code=1)
check_mockradius(daemon, 'False custom reject')

## Test UDP success / standard username
mark('UDP success / standard username')
daemon = start_mockradius(udp_addr, 'accept')
realm.run([kadminl, 'setstr', realm.user_princ, 'otp', otpconfig('udp')])
realm.kinit(realm.user_princ, 'accept', flags=flags)
check_mockradius(daemon, 'True user accept')
realm.extract_keytab(realm.krbtgt_princ, realm.keytab)
realm.run(['./adata', realm.krbtgt_princ],
          expected_msg='+97: [indotp1, indotp2]')

# Repeat with an indicators override in the string attribute.
mark('auth indicator override')
daemon = start_mockradius(udp_addr, 'accept')
oconf = otpconfig('udp', indicators=['indtok1', 'indtok2'])
realm.run([kadminl, 'setstr', realm.user_princ, 'otp', oconf])
realm.kinit(realm.user_princ, 'accept', flags=flags)
check_mockradius(daemon, 'True user accept')
realm.extract_keytab(realm.krbtgt_princ, realm.keytab)
realm.run(['./adata', realm.krbtgt_princ],
          expected_msg='+97: [indtok1, indtok2]')

# Detect upstream pyrad bug
#   https://github.com/wichert/pyrad/pull/18
try:
    from pyrad import packet
    auth = packet.Packet.CreateAuthenticator()
    packet.Packet(authenticator=auth, secret=b'').ReplyPacket()
except AssertionError:
    skip_rest('OTP UNIX domain socket tests', 'pyrad assertion bug detected')

## Test Unix fail / custom username
mark('Unix socket fail / custom username')
daemon = start_mockradius(socket_file, 'accept')
realm.run([kadminl, 'setstr', realm.user_princ, 'otp',
           otpconfig('unix', 'custom')])
realm.kinit(realm.user_princ, 'reject', flags=flags, expected_code=1)
check_mockradius(daemon, 'False custom reject')

## Test Unix success / standard username
mark('Unix socket success / standard username')
daemon = start_mockradius(socket_file, 'accept')
realm.run([kadminl, 'setstr', realm.user_princ, 'otp', otpconfig('unix')])
realm.kinit(realm.user_princ, 'accept', flags=flags)
check_mockradius(daemon, 'True user@KRBTEST.COM accept')

## Regression test for #8708: test with the standard username and two
## tokens configured, with the first rejecting and the second
## accepting.  With the bug, the KDC incorrectly rejects the request
## and then performs invalid memory accesses, most likely crashing.
daemon1 = start_mockradius(udp_addr, 'accept1')
daemon2 = start_mockradius(socket_file, 'accept2')
oconf = '[' + otpconfig_1('udp') + ', ' + otpconfig_1('unix') + ']'
realm.run([kadminl, 'setstr', realm.user_princ, 'otp', oconf])
realm.kinit(realm.user_princ, 'accept2', flags=flags)
check_mockradius(daemon1, 'False user accept2')
check_mockradius(daemon2, 'True user@KRBTEST.COM accept2')

success('OTP tests')
