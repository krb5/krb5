from k5test import *

mark('alias realm tests')

a_princs = {'krbtgt/A': {'keys': 'aes128-cts'},
            'krbtgt/B': {'keys': 'aes128-cts'},
            'user': {'keys': 'aes128-cts', 'flags': '+preauth'},
            'impersonator': {'keys': 'aes128-cts',
                             'flags': '+ok_to_auth_as_delegate'},
            'server': {'keys': 'aes128-cts'},
            'rba': {'keys': 'aes128-cts'}}

a_kconf = {'realms': {'$realm': {'database_module': 'test'}},
           'dbmodules': {'test': {'db_library': 'test',
                                  'princs': a_princs,
                                  'alias': {'krbtgt/NBA': 'krbtgt/A',
                                            'krbtgt/NBB': '@B',
                                            'user@A': 'user'},
                                  'rbcd': {'rba@A': 'impersonator@A'},
                                  'delegation': {'impersonator': 'server'}}}}

b_princs = {'krbtgt/B': {'keys': 'aes128-cts'},
            'krbtgt/A': {'keys': 'aes128-cts'},
            'rbb': {'keys': 'aes128-cts'}}
b_kconf = {'realms': {'$realm': {'database_module': 'test'}},
           'dbmodules': {'test': {'db_library': 'test',
                                  'princs': b_princs,
                                  'rbcd': {'rbb@B': 'impersonator@A'},
                                  'alias': {'krbtgt/NBA': '@A',
                                            'krbtgt/NBB': 'krbtgt/B',
                                            'impersonator@A': '@A'}}}}
ra, rb = cross_realms(2, xtgts=(),
                      args=({'realm': 'A', 'kdc_conf': a_kconf},
                            {'realm': 'B', 'kdc_conf': b_kconf}),
                      create_kdb=False)

ra.start_kdc()
rb.start_kdc()

realmsection = { 'NBA' : {'kdc' : '$hostname:%d' % ra.portbase},
                 'NBB' : {'kdc' : '$hostname:%d' % rb.portbase}}
realmscfg = {'realms': realmsection}
alias_realms = ra.special_env('realmscfg', False, krb5_conf=realmscfg)

ra.extract_keytab('user@A', ra.keytab)
ra.extract_keytab('user@NBA', ra.keytab)
ra.extract_keytab('user\@A@NBA', ra.keytab)

mark('as-req tests')

ra.kinit('user@A', None, ['-k', '-t', ra.keytab])

ra.kinit('user@A@NBA', None, ['-E', '-k', '-t', ra.keytab], env=alias_realms)
out = ra.run([klist, ])
if ('Default principal: %s' % 'user\@A@A') not in out:
    fail('')
if ('krbtgt/NBA@A') not in out:
    fail('')

ra.kinit('user@A@NBA', None, ['-C', '-E', '-k', '-t', ra.keytab], env=alias_realms)
out = ra.run([klist, ])
if ('Default principal: %s' % 'user@A') not in out:
    fail('')
if ('krbtgt/A@A') not in out:
    fail('')

ra.kinit('user@A', None, ['-S', 'krbtgt/NBA', '-k', '-t', ra.keytab], env=alias_realms)
out = ra.run([klist, ])
if ('Default principal: %s' % 'user@A') not in out:
    fail('')
if ('krbtgt/NBA@A') not in out:
    fail('')

ra.kinit('user@A', None, ['-C', '-S', 'krbtgt/NBA', '-k', '-t', ra.keytab], env=alias_realms)
out = ra.run([klist, ])
if ('Default principal: %s' % 'user@A') not in out:
    fail('')
if ('krbtgt/A@A') not in out:
    fail('')

ra.kinit('user@NBA', None, ['-k', '-t', ra.keytab], env=alias_realms, expected_code=1)

ra.kinit('user@NBA', None, ['-C', '-k', '-t', ra.keytab], env=alias_realms)
out = ra.run([klist, ])
if ('Default principal: %s' % 'user@A') not in out:
    fail('')
if ('krbtgt/A@A') not in out:
    fail('')

mark('tgs-req tests')

ra.kinit('user@A', None, ['-F', '-k', '-t', ra.keytab])
ra.run([kvno, 'krbtgt/NBA'])
out = ra.run([klist, ])
if 'Ticket server:' in out:
    fail('Unexpected canonicalization')
if 'krbtgt/NBA@A' not in out:
    fail('Unexpected missing ticket')

ra.kinit('user@A', None, ['-F', '-k', '-t', ra.keytab])
ra.run([kvno, '-C', 'krbtgt/NBA'], env=alias_realms)
out = ra.run([klist, ])
if ('Ticket server: %s' % 'krbtgt/A@A') not in out:
    fail('Unexpected no canonicalization')

ra.kinit('user@A', None, ['-F', '-k', '-t', ra.keytab])
ra.run([kvno, '-C', 'krbtgt/NBA@NBA'], env=alias_realms)
out = ra.run([klist, ])
if ('Ticket server: %s' % 'krbtgt/A@A') not in out:
    fail('Unexpected no canonicalization')

ra.run([kvno, 'rba@NBA'], env=alias_realms)
out = ra.run([klist, ])
if ('Ticket server: %s' % 'rba@A') not in out:
    fail('Unexpected no canonicalization')

ra.run([kvno, '-C', 'rba@NBA'], env=alias_realms)
out = ra.run([klist, ])
if ('Ticket server: %s' % 'rba@A') not in out:
    fail('Unexpected no canonicalization')

ra.run([kvno, 'rbb@NBB'], env=alias_realms)
out = ra.run([klist, ])
if ('Ticket server: %s' % 'rbb@B') not in out:
    fail('Unexpected no canonicalization')

ra.run([kvno, '-C', 'rbb@NBB'], env=alias_realms)
out = ra.run([klist, ])
if ('Ticket server: %s' % 'rbb@B') not in out:
    fail('Unexpected no canonicalization')

mark('S4U tests')

ra.extract_keytab('impersonator@A', ra.keytab)
ra.extract_keytab('impersonator@NBA', ra.keytab)
ra.kinit('impersonator@A', None, ['-f', '-k', '-t', ra.keytab])

ra.run(['./t_s4u', 'e:' + ra.user_princ + '@NBA', 'p:server'], env=alias_realms)
ra.run(['./t_s4u', 'e:' + ra.user_princ + '@NBA', 'p:rba'], env=alias_realms)

#ra.run(['./t_s4u', 'p:' + ra.user_princ, 'p:server@NBA'], env=alias_realms)
#ra.run(['./t_s4u', 'p:' + ra.user_princ, 'p:rba@NBA'], env=alias_realms)
#ra.run(['./t_s4u', 'p:' + ra.user_princ, 'e:rba@NBA@'], env=alias_realms)
#ra.run(['./t_s4u', 'p:' + ra.user_princ, 'e:rbb@NBB@'], env=alias_realms)

mark('accept tests')

ra.extract_keytab('rba@A', ra.keytab)
ra.extract_keytab('krbtgt/NBA@A', ra.keytab)

rb.extract_keytab('rbb@B', ra.keytab)
rb.extract_keytab('krbtgt/NBB@B', ra.keytab)

ra.run(['./t_accname', 'p:krbtgt/NBA@A'])
ra.run(['./t_accname', 'p:krbtgt/NBA@NBA'], env=alias_realms)
ra.run(['./t_accname', 'p:krbtgt/NBB@B'])
ra.run(['./t_accname', 'p:krbtgt/NBB@NBB'], env=alias_realms)

ra.run(['./t_accname', 'p:rba@A'])
ra.run(['./t_accname', 'p:rba@NBA'], env=alias_realms)
ra.run(['./t_accname', 'p:rbb@B'])
ra.run(['./t_accname', 'p:rbb@NBB'], env=alias_realms)

ra.stop()
rb.stop()

success('alias realm test cases')
