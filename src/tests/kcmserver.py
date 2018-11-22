# This is a simple KCM test server, used to exercise the KCM ccache
# client code.  It will generally throw an uncaught exception if the
# client sends anything unexpected, so is unsuitable for production.
# (It also imposes no namespace or access constraints, and blocks
# while reading requests and writing responses.)

# This code knows nothing about how to marshal and unmarshal principal
# names and credentials as is required in the KCM protocol; instead,
# it just remembers the marshalled forms and replays them to the
# client when asked.  This works because marshalled creds and
# principal names are always the last part of marshalled request
# arguments, and because we don't need to implement remove_cred (which
# would need to know how to match a cred tag against previously stored
# credentials).

# The following code is useful for debugging if anything appears to be
# going wrong in the server, since daemon output is generally not
# visible in Python test scripts.
#
# import sys, traceback
# def ehook(etype, value, tb):
#     with open('/tmp/exception', 'w') as f:
#         traceback.print_exception(etype, value, tb, file=f)
# sys.excepthook = ehook

import select
import socket
import struct
import sys

caches = {}
cache_uuidmap = {}
defname = b'default'
next_unique = 1
next_uuid = 1

class KCMOpcodes(object):
    GEN_NEW = 3
    INITIALIZE = 4
    DESTROY = 5
    STORE = 6
    GET_PRINCIPAL = 8
    GET_CRED_UUID_LIST = 9
    GET_CRED_BY_UUID = 10
    REMOVE_CRED = 11
    GET_CACHE_UUID_LIST = 18
    GET_CACHE_BY_UUID = 19
    GET_DEFAULT_CACHE = 20
    SET_DEFAULT_CACHE = 21
    GET_KDC_OFFSET = 22
    SET_KDC_OFFSET = 23


class KRB5Errors(object):
    KRB5_CC_END = -1765328242
    KRB5_CC_NOSUPP = -1765328137
    KRB5_FCC_NOFILE = -1765328189


def make_uuid():
    global next_uuid
    uuid = bytes(12) + struct.pack('>L', next_uuid)
    next_uuid = next_uuid + 1
    return uuid


class Cache(object):
    def __init__(self, name):
        self.name = name
        self.princ = None
        self.uuid = make_uuid()
        self.cred_uuids = []
        self.creds = {}
        self.time_offset = 0


def get_cache(name):
    if name in caches:
        return caches[name]
    cache = Cache(name)
    caches[name] = cache
    cache_uuidmap[cache.uuid] = cache
    return cache


def unmarshal_name(argbytes):
    offset = argbytes.find(b'\0')
    return argbytes[0:offset], argbytes[offset+1:]


def op_gen_new(argbytes):
    # Does not actually check for uniqueness.
    global next_unique
    name = b'unique' + str(next_unique).encode('ascii')
    next_unique += 1
    return 0, name + b'\0'


def op_initialize(argbytes):
    name, princ = unmarshal_name(argbytes)
    cache = get_cache(name)
    cache.princ = princ
    cache.cred_uuids = []
    cache.creds = {}
    cache.time_offset = 0
    return 0, b''


def op_destroy(argbytes):
    name, rest = unmarshal_name(argbytes)
    cache = get_cache(name)
    del cache_uuidmap[cache.uuid]
    del caches[name]
    return 0, b''


def op_store(argbytes):
    name, cred = unmarshal_name(argbytes)
    cache = get_cache(name)
    uuid = make_uuid()
    cache.creds[uuid] = cred
    cache.cred_uuids.append(uuid)
    return 0, b''


def op_get_principal(argbytes):
    name, rest = unmarshal_name(argbytes)
    cache = get_cache(name)
    if cache.princ is None:
        return KRB5Errors.KRB5_FCC_NOFILE, b''
    return 0, cache.princ + b'\0'


def op_get_cred_uuid_list(argbytes):
    name, rest = unmarshal_name(argbytes)
    cache = get_cache(name)
    return 0, b''.join(cache.cred_uuids)


def op_get_cred_by_uuid(argbytes):
    name, uuid = unmarshal_name(argbytes)
    cache = get_cache(name)
    if uuid not in cache.creds:
        return KRB5Errors.KRB5_CC_END, b''
    return 0, cache.creds[uuid]


def op_remove_cred(argbytes):
    return KRB5Errors.KRB5_CC_NOSUPP, b''


def op_get_cache_uuid_list(argbytes):
    return 0, b''.join(cache_uuidmap.keys())


def op_get_cache_by_uuid(argbytes):
    uuid = argbytes
    if uuid not in cache_uuidmap:
        return KRB5Errors.KRB5_CC_END, b''
    return 0, cache_uuidmap[uuid].name + b'\0'


def op_get_default_cache(argbytes):
    return 0, defname + b'\0'


def op_set_default_cache(argbytes):
    global defname
    defname, rest = unmarshal_name(argbytes)
    return 0, b''


def op_get_kdc_offset(argbytes):
    name, rest = unmarshal_name(argbytes)
    cache = get_cache(name)
    return 0, struct.pack('>l', cache.time_offset)


def op_set_kdc_offset(argbytes):
    name, obytes = unmarshal_name(argbytes)
    cache = get_cache(name)
    cache.time_offset, = struct.unpack('>l', obytes)
    return 0, b''


ophandlers = {
    KCMOpcodes.GEN_NEW : op_gen_new,
    KCMOpcodes.INITIALIZE : op_initialize,
    KCMOpcodes.DESTROY : op_destroy,
    KCMOpcodes.STORE : op_store,
    KCMOpcodes.GET_PRINCIPAL : op_get_principal,
    KCMOpcodes.GET_CRED_UUID_LIST : op_get_cred_uuid_list,
    KCMOpcodes.GET_CRED_BY_UUID : op_get_cred_by_uuid,
    KCMOpcodes.REMOVE_CRED : op_remove_cred,
    KCMOpcodes.GET_CACHE_UUID_LIST : op_get_cache_uuid_list,
    KCMOpcodes.GET_CACHE_BY_UUID : op_get_cache_by_uuid,
    KCMOpcodes.GET_DEFAULT_CACHE : op_get_default_cache,
    KCMOpcodes.SET_DEFAULT_CACHE : op_set_default_cache,
    KCMOpcodes.GET_KDC_OFFSET : op_get_kdc_offset,
    KCMOpcodes.SET_KDC_OFFSET : op_set_kdc_offset
}

# Read and respond to a request from the socket s.
def service_request(s):
    lenbytes = b''
    while len(lenbytes) < 4:
        lenbytes += s.recv(4 - len(lenbytes))
        if lenbytes == b'':
                return False

    reqlen, = struct.unpack('>L', lenbytes)
    req = b''
    while len(req) < reqlen:
        req += s.recv(reqlen - len(req))

    majver, minver, op = struct.unpack('>BBH', req[:4])
    argbytes = req[4:]
    code, payload = ophandlers[op](argbytes)

    # The KCM response is the code (4 bytes) and the response payload.
    # The Heimdal IPC response is the length of the KCM response (4
    # bytes), a status code which is essentially always 0 (4 bytes),
    # and the KCM response.
    kcm_response = struct.pack('>l', code) + payload
    hipc_response = struct.pack('>LL', len(kcm_response), 0) + kcm_response
    s.sendall(hipc_response)
    return True


server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
server.bind(sys.argv[1])
server.listen(5)
select_input = [server,]
sys.stderr.write('starting...\n')
sys.stderr.flush()

while True:
    iready, oready, xready = select.select(select_input, [], [])
    for s in iready:
        if s == server:
            client, addr = server.accept()
            select_input.append(client)
        else:
            if not service_request(s):
                select_input.remove(s)
                s.close()
