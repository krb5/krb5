from datetime import datetime
import re

from k5test import *

# Test gss_export_cred and gss_import_cred for initiator creds,
# acceptor creds, and traditional delegated creds.  Also exercises the
# forward_lifetime cap on krb5_fwd_tgt_creds, which only kicks in
# during delegation.  t_s4u.py tests exporting and importing a
# synthesized S4U2Proxy delegated credential.

# Make up a filename to hold user's initial credentials.
def ccache_savefile(realm):
    return os.path.join(realm.testdir, 'ccache.copy')

# Move user's initial credentials into the save file.
def ccache_save(realm):
    os.rename(realm.ccache, ccache_savefile(realm))

# Copy user's initial credentials from the save file into the ccache.
def ccache_restore(realm):
    shutil.copyfile(ccache_savefile(realm), realm.ccache)

# Run t_export_cred with the saved ccache and verify that it stores a
# forwarded cred into the default ccache.
def check(realm, args):
    ccache_restore(realm)
    realm.run(['./t_export_cred'] + args)
    realm.run([klist, '-f'], expected_msg='Flags: Ff')

# Check a given set of arguments with no specified mech and with krb5
# and SPNEGO as the specified mech.
def check_mechs(realm, args):
    check(realm, args)
    check(realm, ['-k'] + args)
    check(realm, ['-s'] + args)

# Make a realm, get forwardable tickets, and save a copy for each test.
realm = K5Realm(get_creds=False)
realm.kinit(realm.user_princ, password('user'), ['-f'])
ccache_save(realm)

# Test with default initiator and acceptor cred.
tname = 'p:' + realm.host_princ
check_mechs(realm, [tname])

# Test with principal-named initiator and acceptor cred.
iname = 'p:' + realm.user_princ
check_mechs(realm, ['-i', iname, '-a', tname, tname])

# Test with host-based acceptor cred.
check_mechs(realm, ['-a', 'h:host', tname])

# Re-kinit with a renewable forwardable TGT so that the forward_lifetime
# cap's clearing of the renewable flag is observable.  Save a separate
# copy of this ccache for the cap tests below.
realm.kinit(realm.user_princ, password('user'),
            flags=['-f', '-l', '1h', '-r', '2h'])
realm.env['TZ'] = 'UTC'
cap_save = os.path.join(realm.testdir, 'ccache.cap.copy')
shutil.copyfile(realm.ccache, cap_save)


def fwd_check(label, env, expect_capped):
    shutil.copyfile(cap_save, realm.ccache)
    realm.run(['./t_export_cred', tname], env=env)
    out = realm.run([klist, '-f'])
    flags = re.findall(r'Flags: ([a-zA-Z]*)', out)[0]
    times = re.findall(r'\d\d/\d\d/\d\d \d\d:\d\d:\d\d', out)
    parsed = [datetime.strptime(t, '%m/%d/%y %H:%M:%S') for t in times]
    life = (parsed[1] - parsed[0]).total_seconds()
    if 'F' not in flags:
        fail('%s: forwarded ticket missing F flag (flags=%s)' % (label, flags))
    if expect_capped:
        if 'R' in flags:
            fail('%s: forwarded ticket unexpectedly renewable (flags=%s)' %
                 (label, flags))
        if abs(life - 300) > 10:
            fail('%s: expected ~300s lifetime, got %ds' % (label, life))
    else:
        if 'R' not in flags:
            fail('%s: forwarded ticket should be renewable (flags=%s)' %
                 (label, flags))


# Baseline: no cap configured -> forwarded TGT inherits the source's
# renewable flag and approximately full lifetime.
fwd_check('baseline', realm.env, expect_capped=False)

# Environment variable caps lifetime and clears renewable.
env = realm.env.copy()
env['KRB5_FORWARD_LIFETIME'] = '5m'
fwd_check('env var', env, expect_capped=True)

# [libdefaults] forward_lifetime caps similarly.
conf_env = realm.special_env('cap_conf', False,
                             krb5_conf={'libdefaults':
                                        {'forward_lifetime': '5m'}})
fwd_check('krb5.conf', conf_env, expect_capped=True)

# Environment variable overrides krb5.conf when both are set.
override_env = realm.special_env('cap_override', False,
                                 krb5_conf={'libdefaults':
                                            {'forward_lifetime': '1h'}})
override_env['KRB5_FORWARD_LIFETIME'] = '5m'
fwd_check('env overrides conf', override_env, expect_capped=True)

success('gss_export_cred/gss_import_cred and forward_lifetime cap tests')
