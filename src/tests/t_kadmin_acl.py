#!/usr/bin/python
from k5test import *

realm = K5Realm(create_host=False, create_user=False)

def make_client(name):
    global realm
    realm.addprinc(name, password(name))
    ccache = os.path.join(realm.testdir,
                          'kadmin_ccache_' + name.replace('/', '_'))
    realm.kinit(name, password(name),
                flags=['-S', 'kadmin/admin', '-c', ccache])
    return ccache

def kadmin_as(client, query):
    global realm
    return realm.run_as_client([kadmin, '-c', client, '-q', query])

def delprinc(name):
    global realm
    realm.run_kadminl('delprinc -force ' + name)

all_add = make_client('all_add')
all_changepw = make_client('all_changepw')
all_delete = make_client('all_delete')
all_inquire = make_client('all_inquire')
all_list = make_client('all_list')
all_modify = make_client('all_modify')
all_rename = make_client('all_rename')
some_add = make_client('some_add')
some_changepw = make_client('some_changepw')
some_delete = make_client('some_delete')
some_inquire = make_client('some_inquire')
some_modify = make_client('some_modify')
some_rename = make_client('some_rename')
restricted_add = make_client('restricted_add')
restricted_modify = make_client('restricted_modify')
restricted_rename = make_client('restricted_rename')
wctarget = make_client('wctarget')
admin = make_client('user/admin')
none = make_client('none')
restrictions = make_client('restrictions')

realm.run_kadminl('addpol -minlife "1 day" minlife')

f = open(os.path.join(realm.testdir, 'acl'), 'w')
f.write('''
all_add            a
all_changepw       c
all_delete         d
all_inquire        i
all_list           l
all_modify         im
all_rename         ad
some_add           a   selected
some_changepw      c   selected
some_delete        d   selected
some_inquire       i   selected
some_modify        im  selected
some_rename        d   from
some_rename        a   to
restricted_add     a   *         +preauth
restricted_modify  im  *         +preauth
restricted_rename  ad  *         +preauth

*/*                d   *2/*1
*/admin            a
wctarget           a   wild/*
restrictions       a   type1     -policy minlife
restrictions       a   type2     -clearpolicy
restrictions       a   type3     -maxlife 1h -maxrenewlife 2h
''')
f.close()

realm.start_kadmind()

# cpw can generate four different RPC calls depending on options.
realm.addprinc('selected', 'oldpw')
realm.addprinc('unselected', 'oldpw')
for pw in ('-pw newpw', '-randkey'):
    for ks in ('', '-e aes256-cts:normal'):
        args = pw + ' ' + ks
        out = kadmin_as(all_changepw, 'cpw %s unselected' % args)
        if ('Password for "unselected@KRBTEST.COM" changed.' not in out and
            'Key for "unselected@KRBTEST.COM" randomized.' not in out):
            fail('cpw success (acl)')
        out = kadmin_as(some_changepw, 'cpw %s selected' % args)
        if ('Password for "selected@KRBTEST.COM" changed.' not in out and
            'Key for "selected@KRBTEST.COM" randomized.' not in out):
            fail('cpw success (target)')
        out = kadmin_as(none, 'cpw %s selected' % args)
        if 'Operation requires ``change-password\'\' privilege' not in out:
            fail('cpw failure (no perms)')
        out = kadmin_as(some_changepw, 'cpw %s unselected' % args)
        if 'Operation requires ``change-password\'\' privilege' not in out:
            fail('cpw failure (target)')
        out = kadmin_as(none, 'cpw %s none' % args)
        if ('Password for "none@KRBTEST.COM" changed.' not in out and
            'Key for "none@KRBTEST.COM" randomized.' not in out):
            fail('cpw success (self exemption)')
        realm.run_kadminl('modprinc -policy minlife none')
        out = kadmin_as(none, 'cpw %s none' % args)
        if 'Current password\'s minimum life has not expired' not in out:
            fail('cpw failure (minimum life)')
        realm.run_kadminl('modprinc -clearpolicy none')
delprinc('selected')
delprinc('unselected')

out = kadmin_as(all_add, 'addpol policy')
realm.run_kadminl('delpol -force policy')
if 'Operation requires' in out:
    fail('addpol success (acl)')
out = kadmin_as(none, 'addpol policy')
if 'Operation requires ``add\'\' privilege' not in out:
    fail('addpol failure (no perms)')

# addprinc can generate two different RPC calls depending on options.
for ks in ('', '-e aes256-cts:normal'):
    args = '-pw pw ' + ks
    out = kadmin_as(all_add, 'addprinc %s unselected' % args)
    if 'Principal "unselected@KRBTEST.COM" created.' not in out:
        fail('addprinc success (acl)')
    delprinc('unselected')
    out = kadmin_as(some_add, 'addprinc %s selected' % args)
    if 'Principal "selected@KRBTEST.COM" created.' not in out:
        fail('addprinc success(target)')
    delprinc('selected')
    out = kadmin_as(restricted_add, 'addprinc %s unselected' % args)
    if 'Principal "unselected@KRBTEST.COM" created.' not in out:
        fail('addprinc success (restrictions) -- addprinc')
    out = realm.run_kadminl('getprinc unselected')
    if 'REQUIRES_PRE_AUTH' not in out:
        fail('addprinc success (restrictions) -- restriction check')
    delprinc('unselected')
    out = kadmin_as(none, 'addprinc %s selected' % args)
    if 'Operation requires ``add\'\' privilege' not in out:
        fail('addprinc failure (no perms)')
    out = kadmin_as(some_add, 'addprinc %s unselected' % args)
    if 'Operation requires ``add\'\' privilege' not in out:
        fail('addprinc failure (target)')

realm.addprinc('unselected', 'pw')
out = kadmin_as(all_delete, 'delprinc -force unselected')
if 'Principal "unselected@KRBTEST.COM" deleted.' not in out:
    fail('delprinc success (acl)')
realm.addprinc('selected', 'pw')
out = kadmin_as(some_delete, 'delprinc -force selected')
if 'Principal "selected@KRBTEST.COM" deleted.' not in out:
    fail('delprinc success (target)')
realm.addprinc('unselected', 'pw')
out = kadmin_as(none, 'delprinc -force unselected')
if 'Operation requires ``delete\'\' privilege' not in out:
    fail('delprinc failure (no perms)')
out = kadmin_as(some_delete, 'delprinc -force unselected')
if 'Operation requires ``delete\'\' privilege' not in out:
    fail('delprinc failure (no target)')

out = kadmin_as(all_inquire, 'getpol minlife')
if 'Policy: minlife' not in out:
    fail('getpol success (acl)')
out = kadmin_as(none, 'getpol minlife')
if 'Operation requires ``get\'\' privilege' not in out:
    fail('getpol failure (no perms)')
realm.run_kadminl('modprinc -policy minlife none')
out = kadmin_as(none, 'getpol minlife')
if 'Policy: minlife' not in out:
    fail('getpol success (self policy exemption)')
realm.run_kadminl('modprinc -clearpolicy none')

realm.addprinc('selected', 'pw')
realm.addprinc('unselected', 'pw')
out = kadmin_as(all_inquire, 'getprinc unselected')
if 'Principal: unselected@KRBTEST.COM' not in out:
    fail('getprinc success (acl)')
out = kadmin_as(some_inquire, 'getprinc selected')
if 'Principal: selected@KRBTEST.COM' not in out:
    fail('getprinc success (target)')
out = kadmin_as(none, 'getprinc selected')
if 'Operation requires ``get\'\' privilege' not in out:
    fail('getprinc failure (no perms)')
out = kadmin_as(some_inquire, 'getprinc unselected')
if 'Operation requires ``get\'\' privilege' not in out:
    fail('getprinc failure (target)')
out = kadmin_as(none, 'getprinc none')
if 'Principal: none@KRBTEST.COM' not in out:
    fail('getprinc success (self exemption)')
delprinc('selected')
delprinc('unselected')

out = kadmin_as(all_list, 'listprincs')
if 'K/M@KRBTEST.COM' not in out:
    fail('listprincs success (acl)')
out = kadmin_as(none, 'listprincs')
if 'Operation requires ``list\'\' privilege' not in out:
    fail('listprincs failure (no perms)')

realm.addprinc('selected', 'pw')
realm.addprinc('unselected', 'pw')
realm.run_kadminl('setstr selected key value')
realm.run_kadminl('setstr unselected key value')
out = kadmin_as(all_inquire, 'getstrs unselected')
if 'key: value' not in out:
    fail('getstrs success (acl)')
out = kadmin_as(some_inquire, 'getstrs selected')
if 'key: value' not in out:
    fail('getstrs success (target)')
out = kadmin_as(none, 'getstrs selected')
if 'Operation requires ``get\'\' privilege' not in out:
    fail('getstrs failure (no perms)')
out = kadmin_as(some_inquire, 'getstrs unselected')
if 'Operation requires ``get\'\' privilege' not in out:
    fail('getstrs failure (target)')
out = kadmin_as(none, 'getstrs none')
if '(No string attributes.)' not in out:
    fail('getstrs success (self exemption)')
delprinc('selected')
delprinc('unselected')

out = kadmin_as(all_modify, 'modpol -maxlife "1 hour" policy')
if 'Operation requires' in out:
    fail('modpol success (acl)')
out = kadmin_as(none, 'modpol -maxlife "1 hour" policy')
if 'Operation requires ``modify\'\' privilege' not in out:
    fail('modpol failure (no perms)')

realm.addprinc('selected', 'pw')
realm.addprinc('unselected', 'pw')
out = kadmin_as(all_modify, 'modprinc -maxlife "1 hour" unselected')
if 'Principal "unselected@KRBTEST.COM" modified.' not in out:
    fail('modprinc success (acl)')
out = kadmin_as(some_modify, 'modprinc -maxlife "1 hour" selected')
if 'Principal "selected@KRBTEST.COM" modified.' not in out:
    fail('modprinc success (target)')
out = kadmin_as(restricted_modify, 'modprinc -maxlife "1 hour" unselected')
if 'Principal "unselected@KRBTEST.COM" modified.' not in out:
    fail('modprinc success (restrictions) -- modprinc')
out = realm.run_kadminl('getprinc unselected')
if 'REQUIRES_PRE_AUTH' not in out:
    fail('addprinc success (restrictions) -- restriction check')
out = kadmin_as(all_inquire, 'modprinc -maxlife "1 hour" selected')
if 'Operation requires ``modify\'\' privilege' not in out:
    fail('addprinc failure (no perms)')
out = kadmin_as(some_modify, 'modprinc -maxlife "1 hour" unselected')
if 'Operation requires' not in out:
    fail('modprinc failure (target)')
delprinc('selected')
delprinc('unselected')

realm.addprinc('selected', 'pw')
realm.addprinc('unselected', 'pw')
out = kadmin_as(all_modify, 'purgekeys unselected')
if 'Old keys for principal "unselected@KRBTEST.COM" purged' not in out:
    fail('purgekeys success (acl)')
out = kadmin_as(some_modify, 'purgekeys selected')
if 'Old keys for principal "selected@KRBTEST.COM" purged' not in out:
    fail('purgekeys success (target)')
out = kadmin_as(none, 'purgekeys selected')
if 'Operation requires ``modify\'\' privilege' not in out:
    fail('purgekeys failure (no perms)')
out = kadmin_as(some_modify, 'purgekeys unselected')
if 'Operation requires ``modify\'\' privilege' not in out:
    fail('purgekeys failure (target)')
delprinc('selected')
delprinc('unselected')

realm.addprinc('from', 'pw')
out = kadmin_as(all_rename, 'renprinc -force from to')
if 'Principal "from@KRBTEST.COM" renamed to "to@KRBTEST.COM".' not in out:
    fail('renprinc success (acl)')
realm.run_kadminl('renprinc -force to from')
out = kadmin_as(some_rename, 'renprinc -force from to')
if 'Principal "from@KRBTEST.COM" renamed to "to@KRBTEST.COM".' not in out:
    fail('renprinc success (target)')
realm.run_kadminl('renprinc -force to from')
out = kadmin_as(all_add, 'renprinc -force from to')
if 'Operation requires ``delete\'\' privilege' not in out:
    fail('renprinc failure (no delete perms)')
out = kadmin_as(all_delete, 'renprinc -force from to')
if 'Operation requires ``add\'\' privilege' not in out:
    fail('renprinc failure (no add perms)')
out = kadmin_as(some_rename, 'renprinc -force from notto')
if 'Operation requires ``add\'\' privilege' not in out:
    fail('renprinc failure (new target)')
realm.run_kadminl('renprinc -force from notfrom')
out = kadmin_as(some_rename, 'renprinc -force notfrom to')
if 'Operation requires ``delete\'\' privilege' not in out:
    fail('renprinc failure (old target)')
out = kadmin_as(restricted_rename, 'renprinc -force notfrom to')
if 'Operation requires ``add\'\' privilege' not in out:
    fail('renprinc failure (restrictions)')
delprinc('notfrom')

realm.addprinc('selected', 'pw')
realm.addprinc('unselected', 'pw')
out = kadmin_as(all_modify, 'setstr unselected key value')
if 'Attribute set for principal "unselected@KRBTEST.COM".' not in out:
    fail('modprinc success (acl)')
out = kadmin_as(some_modify, 'setstr selected key value')
if 'Attribute set for principal "selected@KRBTEST.COM".' not in out:
    fail('modprinc success (target)')
out = kadmin_as(none, 'setstr selected key value')
if 'Operation requires ``modify\'\' privilege' not in out:
    fail('addprinc failure (no perms)')
out = kadmin_as(some_modify, 'setstr unselected key value')
if 'Operation requires' not in out:
    fail('modprinc failure (target)')
delprinc('selected')
delprinc('unselected')

out = kadmin_as(admin, 'addprinc -pw pw anytarget')
if 'Principal "anytarget@KRBTEST.COM" created.' not in out:
    fail('addprinc success (client wildcard)')
delprinc('anytarget')
out = kadmin_as(wctarget, 'addprinc -pw pw wild/card')
if 'Principal "wild/card@KRBTEST.COM" created.' not in out:
    fail('addprinc sucess (target wildcard)')
delprinc('wild/card')
out = kadmin_as(wctarget, 'addprinc -pw pw wild/card/extra')
if 'Operation requires' not in out:
    fail('addprinc failure (target wildcard extra component)')
realm.addprinc('admin/user', 'pw')
out = kadmin_as(admin, 'delprinc -force admin/user')
if 'Principal "admin/user@KRBTEST.COM" deleted.' not in out:
    fail('delprinc success (wildcard backreferences)')
out = kadmin_as(admin, 'delprinc -force none')
if 'Operation requires' not in out:
    fail('delprinc failure (wildcard backreferences not matched)')

kadmin_as(restrictions, 'addprinc -pw pw type1')
out = realm.run_kadminl('getprinc type1')
if 'Policy: minlife' not in out:
    fail('restriction (policy)')
delprinc('type1')
kadmin_as(restrictions, 'addprinc -pw pw -policy minlife type2')
out = realm.run_kadminl('getprinc type2')
if 'Policy: [none]' not in out:
    fail('restriction (clearpolicy)')
delprinc('type2')
kadmin_as(restrictions, 'addprinc -pw pw -maxlife "1 minute" type3')
out = realm.run_kadminl('getprinc type3')
if ('Maximum ticket life: 0 days 00:01:00' not in out or
    'Maximum renewable life: 0 days 02:00:00' not in out):
    fail('restriction (maxlife low, maxrenewlife unspec)')
delprinc('type3')
kadmin_as(restrictions, 'addprinc -pw pw -maxrenewlife "1 day" type3')
out = realm.run_kadminl('getprinc type3')
if 'Maximum renewable life: 0 days 02:00:00' not in out:
    fail('restriction (maxrenewlife high)')

success('kadmin ACL enforcement')
