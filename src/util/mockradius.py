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

# This simple RADIUS daemon is intended to help test FAST OTP over UDP
# and Unix domain sockets.

import io
import os
import socket
import struct
import sys
from pyrad import packet, dictionary

# We could use a dictionary file, but since we need so few attributes,
# we'll just include them here.
radius_attributes = '''
ATTRIBUTE    User-Name    1    string
ATTRIBUTE    User-Password   2    octets
ATTRIBUTE    Service-Type    6    integer
ATTRIBUTE    NAS-Identifier  32    string
ATTRIBUTE    Message-Authenticator 80 octets
'''

MAX_PACKET_SIZE = 4096
DICTIONARY = dictionary.Dictionary(io.StringIO(radius_attributes))

addr = sys.argv[1]
expected_password = sys.argv[2]

# Get one request from addr (a Unix domain or UDP socket).
if addr.startswith('/'):
    # Use an empty secret for a Unix domain socket.
    secret = b''

    # Bind to the path, accept a stream connection, and close the
    # listener socket.
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    if os.path.exists(addr):
        os.remove(addr)
    sock.bind(addr)
    sock.listen(1)
    print('starting...', file=sys.stderr)
    conn = sock.accept()[0]
    sock.close()
    os.remove(addr)

    buf = b''
    remain = MAX_PACKET_SIZE
    while True:
        buf += conn.recv(remain)
        remain = MAX_PACKET_SIZE - len(buf)
        if len(buf) >= 4:
            remain = struct.unpack("!BBH", buf[0:4])[2] - len(buf)
            if remain <= 0:
                break
else:
    # Use a non-empty (but trivial) secret for a UDP socket.
    secret = b'otptest'

    # Bind to the UDP address and read a packet, remembering its
    # source address.  Keep the listener socket open.
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((addr.split(':')[0], int(addr.split(':')[1])))
    print('starting...', file=sys.stderr)
    buf, reply_addr = sock.recvfrom(MAX_PACKET_SIZE)

# Parse the packet and compose a reply.
pkt = packet.AuthPacket(secret=secret, dict=DICTIONARY, packet=buf)
passwords = [pkt.PwDecrypt(x) for x in pkt['User-Password']]
usernames = pkt['User-Name']
success = (passwords == [expected_password])
reply = pkt.CreateReply()
reply.code = packet.AccessAccept if success else packet.AccessReject
reply.add_message_authenticator()

if addr.startswith('/'):
    # Reply on the Unix domain stream socket.
    conn.send(reply.ReplyPacket())
    conn.close()
else:
    # Reply on the UDP listener socket at the packet source address.
    sock.sendto(reply.ReplyPacket(), reply_addr)
    sock.close()

# Send the result, username, and password to stdout for additional
# verification by the calling process.
print(success, usernames[0], passwords[0])
