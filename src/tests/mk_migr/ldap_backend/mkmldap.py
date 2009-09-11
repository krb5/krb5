##############################################################################
###################### WARNING: DOES NOT WORK YET ############################
##############################################################################

import os, sys, shutil, socket, time, string
from subprocess import Popen, PIPE
from optparse import OptionParser
from time import strftime

class LDAPbackendSetup:
    def __init__(self, verbose_in, pw_in,  kdcPath_in, kdmdPath_in, kdbPath_in, ldapPath_in, kdmlPath_in, kdmPath_in, cltPath_in, sandir_in, confdir_in):
        self.npass = 0

        self.nfail = 0

        self.verbose = verbose_in
        self.pw = pw_in

        self.krb5kdc = kdcPath_in #1 krb5kdc
        self.kadmind = kdmdPath_in #2 kadmind
        self.kdb5_util = kdbPath_in #3a kdb5_util
        self.kdb5_ldap_util = ldapPath_in #3b kdb5_ldap_util
        self.kadminlocal = kdmlPath_in #4 kadmin.local
        self.kadmin = kdmPath_in #5 kadmin
        self.clients = cltPath_in+"/" #6 clients

        self.sandir = sandir_in
        self.confdir = confdir_in

        ########## SET UP Write Output File #####
        print "outfile path"
        print self.sandir
        print self.sandir+"/outfile"
        
        self.outfile = open(self.sandir+"/outfile", 'w')

        #''print os.environ'

    def _writeLine(self, astr, prt=False):
        self.outfile.write(astr.strip()+"\n")
        if prt:
            print astr.strip()

    def _writeHeader(self, astr, prt=True):
        self.outfile.write("\n========== "+astr.strip()+" ==========\n")
        if prt:
            print "========== "+astr.strip()+" =========="
    
    def _sysexit(self, fatal=False, finished=False):
        self._writeLine("++++++++++++++++++++++++++++++", True)
        if fatal:
            self._writeLine("++++ Test did NOT finish +++++", True)
            self._writeLine("++++ FATAL FAILURE! Stopped ++", True)
            self._writeLine("++++ See sandbox/outfile +++++", True)
            self._writeLine("++++++++++++++++++++++++++++++", True)
            sys.exit()
        elif not finished:
            self._writeLine("++++ Test did NOT finish +++++", True)
            self._writeLine("++++ FAIL Detected! keep going", True)
            self._writeLine("++++++++++++++++++++++++++++++", True)
        else: #finished
            self._writeLine("++++ MKM Test Finished +++++++", True)
            self._writeLine("++++++++++++++++++++++++++++++", True)
            self._writeLine("++++ Commands Passed: %s +++++" % self.npass, True)
            self._writeLine("++++ Commands Failed: %s +++++" % self.nfail, True)
            sys.exit()
        
    def _printig(self):
        self._writeLine("~.~.~Error should be ignored~.~.~.~")

    def _printerr(self, errm, stderr):
        self._writeLine("#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#")
        self._writeLine("-XX-FAILED: "+errm+". See stderr below:")
        [self._writeLine(line) for line in stderr.readlines() ]

    def _printout(self, cmd, pstdout):
        if self.verbose:
            self._writeLine("#######################################")
            #self._writeLine("---------------------------------------")
            self._writeLine("-command: "+cmd)
            self._writeLine("-----out: ")
            [self._writeLine(line) for line in pstdout.readlines()]

    def _eval(self, succeed, pwait, errm, pstderr, fatal=False, msg2="", finished=False):
        if int(pwait) != 0: # is bad
            self._printerr(errm, pstderr)
            if succeed==True: ## want good
                self.nfail += 1
                self._sysexit(fatal, finished)
            else: ## want bad
                self.npass += 1
                self._printig()
        else: # is good
            if not succeed: ## want bad
                if msg2 != "":
                    self._writeLine(msg2, True)
                self.nfail += 1
                self._sysexit(fatal, finished)
            else: ## want good
                self.npass += 1 

    def _metafunc(self, command,  errmsg, moreinfo="", isLocal=False, succeed=True, fatal=False):
        l = command
        if isLocal:
            pl = Popen(l.split(None,2), stdin=PIPE, stdout=PIPE, stderr=PIPE)
        else:
            pl = Popen(l.split(), stdin=PIPE, stdout=PIPE, stderr=PIPE)
        self._printout(l+moreinfo, pl.stdout)
        
        self._eval(succeed, pl.wait(), errmsg, pl.stderr, fatal)
    
    ###########################################

    # Start the KDC daemons
    def _startkdc(self):
        self._writeLine("\nstarting kdc daemons ...")
        l0 = self.krb5kdc
        errm = "error at starting krb5kdc"
        self._metafunc(l0, errm)
        # below has been changed
        
        #starting kadmind
        l0b = self.kadmind + ' -W -nofork' #the W is for during off strong random numbers
        errm = "error at starting kadmind, maybe it's already started"
        pl0b = Popen(l0b.split(), stdin=PIPE, stdout=PIPE, stderr=PIPE)
        self._writeLine( "kadmind -nofork")
        started = False
        while time.clock() < 3:
            l = pl0b.stderr.readline()
            if l.find("starting") > -1:
                self._writeLine( l.strip())          
                self.npass += 1
                started = True
                break  
        else:
            self.nfail += 1
            self._printerr("kadmind not starting, check to see if there are any previous kadmind running with cmd: 'ps -ef | grep kadmind' and then do 'sudo kill -9 [# on the left]'", pl0b.stderr)
            self._sysexit(fatal=True)
        if not started:
            self.nfail += 1
            self._sysexit()
        self._writeLine("end starting kdc daemons")
        
    # Kill the KDC daemons in case they are running
    def _killkdc(self, suc=True):
        l1 = 'pkill -9 -x krb5kdc'
        errm = "no krb5kdc killed"
        self._metafunc(l1, errm, succeed=suc)
        l2 = 'pkill -9 -x kadmind'
        errm = "no kadmind killed"
        self._metafunc(l2, errm, succeed=suc)

    # Destroys current database
    def _destroykdc(self, suc=True):
        l3 = self.kdb5_util+' destroy -f' #forced
        errm = "no kdb database destroyed"
        self._metafunc(l3, errm, succeed=suc)

    ''' Destroys current database
    I don't use this because 1. I don't know the specific kdc's to destroy, 2. the debconf setting up of slapd has destroyed old databases already
    def _destroykdc_ldap(self, suc=True):
        l3 = self.kdb5_ldap_util+' destroy -f' #forced
        errm = "no kdb database destroyed"
        self._metafunc(l3, errm, succeed=suc)
    '''

    # Create a new database with a new master key
    def _createdb(self, pw):
        l4 = self.kdb5_util+' -P '+pw+' create -s -W' #added W for svn version 22435 to avoid reading strong random numbers
        errm = "error when creating new database, _createdb()"
        self._metafunc(l4, errm, fatal=True)

    # Addprinc
    def _locAddprinc(self, passw, usern):
        l5 = self.kadminlocal+' -q addprinc -pw '+passw+' '+usern
        errm = "error when adding princ, _locAddprinc"
        self._metafunc(l5, errm, isLocal=True)

    # List princs
    def _locListprincs(self):
        l6 = self.kadminlocal+' -q listprincs'
        errm = "error when listing princs, _locListprincs"        
        self._metafunc(l6, errm, isLocal=True)

    #  Get princs
    def _locGetprinc(self, usern, extra=False, succeed=True):
        l7 = self.kadminlocal+' -q getprinc '+usern
        errm="error when getting princ, _locGetprinc"

        pl7 = Popen(l7.split(None,2), stdin=PIPE, stdout=PIPE, stderr=PIPE)
        if not extra:
            self._printout(l7, pl7.stdout)
        else:
            if self.verbose:
                self._writeLine("-command: "+l7)
                self._writeLine("-----out: ")
                for line in pl7.stdout.readlines():
                    if line.startswith("Princ") or line.startswith("MKey"):
                        self._writeLine(line)
        self._eval(succeed, pl7.wait(), errm, pl7.stderr)

    # Get princs and finds something in the output
    def _locGetprincFind(self, usern, findstr, succeed=True):
        l7b = self.kadminlocal+' -q getprinc ' +usern
        errm="error when getting princs, _locGetprinc, (regular output of getprincs is not printed here), will NOT continue to find string="+findstr
        pl7b = Popen(l7b.split(None, 2), stdin=PIPE, stdout=PIPE, stderr=PIPE)
        if self.verbose:
            self._writeLine("-command: "+l7b)
        if int(pl7b.wait()) != 0: # is bad
            self._printerr(errm, pl7b.stderr)
            if succeed: ## want good
                self.nfail += 1
                self._sysexit()
            else: ## want bad
                self.npass += 1
                self._printig()
        else: # is good
            if self.verbose:            
                self._writeLine( "-----out: ")
            boofound = False
            for outl in pl7b.stdout.readlines():
                self._writeLine(outl)
                if string.find(outl, findstr) > -1:
                    boofound = True
            if boofound:
                self._writeLine("----FOUND: "+findstr)
            else:
                self._writeLine("----NOT FOUND: "+findstr)
            if not succeed: ## want bad
                self.nfail += 1
                self._sysexit()
            else: ## want good
                self.npass += 1

    # Add policy
    def _locAddpol(self, maxtime, minlength, minclasses, history, policyname):
        rest = ""
        if maxtime != None:
            rest += '-maxlife '+maxtime+' '
        if minlength != None:
            rest += '-minlength '+minlength+' '
        if minclasses != None:
            rest += '-minclasses '+minclasses+' '
        if history != None:
            rest += '-history '+history+' '
        l8 = self.kadminlocal+' -q add_policy '+rest+policyname
        errm = "error when adding policy, _locAddpol"
        self._metafunc(l8, errm, isLocal=True)  

    #  Get pol
    def _locGetpol(self, poln):
        l8b = self.kadminlocal+' -q getpol '+poln
        errm="error when getting pol, _locGetpol"
        self._metafunc(l8b, errm, isLocal=True)

    # Modify Principal
    def _locModprinc(self, rest):
        l9 = self.kadminlocal+' -q modprinc '+rest
        errm = "error when modifing principal, _locModprinc"
        self._metafunc(l9, errm, isLocal=True)

    # List mkeys
    def _listmkeys(self):
        l10 = self.kdb5_util+' list_mkeys'
        errm = "error when listing mkeys, _listmkeys"
        self._metafunc(l10, errm)

    # Use mkeys
    def _usemkey(self, kvno, time, succeed=True):
        l11 = self.kdb5_util+' use_mkey '+kvno+' '+time
        pl11 = Popen(l11.split(), stdin=PIPE, stdout=PIPE, stderr=PIPE)
        self._printout(l11, pl11.stdout)
        self._eval(succeed, pl11.wait(), "error when using mkeys, _usemkey", pl11.stderr, msg2="-XX-ERROR: "+l11+" should have failed.")        

        
    # Change password (cpw)
    def _locCpw(self, passw, usern):
        l12 = self.kadminlocal+' -q cpw -pw '+passw+' '+usern
        errm = "error when changing password, _locCpw"
        self._metafunc(l12, errm, moreinfo="\n--------: newpw='"+passw+"'", isLocal=True)

    # Purge mkeys
    def _purgemkeys(self):
        l13 = self.kdb5_util+' purge_mkeys -f -v' #-f is forced, -v is verbose
        errm = "error when purging mkeys, _purgemkeys"
        self._metafunc(l13, errm)

    # Add mkey
    def _addmkey(self, passw, extra="", succeed=True):
        l14 = self.kdb5_util+' add_mkey '+extra
        pl14 = Popen(l14.split(), stdin=PIPE, stdout=PIPE, stderr=PIPE) 
        pl14.stdin.write(passw+'\n') #enter 1st time
        pl14.stdin.write(passw+'\n') #re-enter    
        self._printout(l14+' [with password='+passw+']', pl14.stdout)
        self._eval(succeed, pl14.wait(), "error when adding mkey, _addmkey", pl14.stderr)
        self._writeLine( "----end of adding mkey")

    # kinit user
    def _kinit(self, passw_in, usern, succeed=True):
        l15 = self.clients+'kinit/kinit '+usern
        pl15 = Popen(l15.split(), stdin=PIPE, stdout=PIPE, stderr=PIPE)
        pl15.stdin.write(passw_in+'\n')
        pl15.stdin.close()
        self._printout(l15, pl15.stdout)
        self._eval(succeed, pl15.wait(), "error when kinit user, _kinit", pl15.stderr)
        self._writeLine( "----end of kiniting user")

    # change password on client's side
    def _kpasswd(self, oldpw, newpw, usern, succeed=True):
        l16 = self.clients+'kpasswd/kpasswd '+usern
        pl16 = Popen(l16.split(), stdin=PIPE, stdout=PIPE, stderr=PIPE)
        pl16.stdin.write(oldpw+'\n')
        pl16.stdin.write(newpw+'\n')
        pl16.stdin.write(newpw+'\n')
        self._printout(l16+"\n--------: oldpw='"+oldpw+"' -> newpw='"+newpw+"'", pl16.stdout)
        self._eval(succeed, pl16.wait(), "error when changing password on client's side, _kpasswd", pl16.stderr)
        self._writeLine("----end of changing kpasswd")

    # klist on client's side
    def _klist(self):
        l17 = self.clients+'klist/klist'
        errm = "error when klist, _klist"
        self._metafunc(l17, errm)

    # Update principal encryption
    def _updatePrincEnc(self):
        l18 = self.kdb5_util+' update_princ_encryption -f -v'
        errm = "error when updating principal encryption, _updatePrincEnc"
        self._metafunc(l18, errm)

    # kdestroy
    def _kdestroy(self):
        l19 = self.clients+'kdestroy/kdestroy'
        errm = "error when kdestroy, _kdestroy"
        self._metafunc(l19, errm)

    # stash
    def _stash(self):
        l20 = self.kdb5_util+' stash'
        errm="error at stash, _stash"
        self._metafunc(l20, errm)

    # any shell command
    def _shell(self, command, succeed=True):
        l21 = command
        errm="error at executing this command in _shell(): "+l21
        pl21 = Popen(l21, shell=True, stdin=PIPE, stdout=PIPE, stderr=PIPE)
        self._printout(l21, pl21.stdout)
        self._eval(succeed, pl21.wait(), errm, pl21.stderr)
        #'self._printerr(errm, pl21.stderr)  Pointed out that kadmin had problems!'


    def _shelltest(self, command, succeed=True):
        l21 = command
        errm="error at executing this command in _shell(): "+l21
        pl21 = Popen(l21, shell=True, stdin=PIPE, stdout=PIPE, stderr=PIPE)
        first = pl21.communicate('a\na')[0]
        print "first:"
        print first
        print "end first"
              
        #self._printout(l21, pl21.stdout) self._printout(l21, first)        
        self._eval(succeed, pl21.wait(), errm, pl21.stderr)
        #self._printerr(errm, pl21.stderr)  #Pointed out that kadmin had problems!'


    # get_princ_records()
    def _get_princ_records(self, succeed=True):
        l22 = self.kadminlocal+" -q listprincs 2>/dev/null|grep -v '^Authenticating as'|fgrep '@'|sort"
        errm="error at listprincs in _get_princ_records() with this command: "+l22
        pl22 = Popen(l22, shell=True, stdin=PIPE, stdout=PIPE, stderr=PIPE)
        if int(pl22.wait()) != 0: # is bad
            self.printerr(errm, pl22.stderr)
            if succeed: ## want good
                self.nfail += 1
                self._sysexit()
            else: ## want badd
                self.npass += 1
                self._printig()
        else: # is good
            if not succeed: ## want bad
                self.nfail += 1
                self._sysexit()
            else: ## want good
                self.npass += 1
                self._writeLine( "\nget_princ_records() executing all listprincs command: "+l22+"\n------its results:")
                for princ in pl22.stdout.readlines():
                    self._locGetprinc(princ.strip(), extra=True)
                self._writeLine("END executing command: "+l22+"\n~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~")
        
######################################################
    def run(self):
        #############RUN###################
        passw=self.pw     
    	
        self._writeHeader("START MASTER KEY MIGRATION TEST")        

        # Set up database
        self._writeHeader("SET UP: database")
        self._killkdc("Either") #74 =1,2
        #self._destroykdc("Either") #77 =3
        #self._destroykdc_ldap("Either") #77 =3

        self._shell('sudo cat '+self.confdir+'/debconfile')
    	self._shell('sudo debconf-set-selections '+self.confdir+'/debconfile')
        self._shell('sudo dpkg-reconfigure --frontend=noninteractive slapd')
        self._shell('sudo ldapadd -x -D cn=admin,cn=config -w a -f /tmp/ldif_output/cn\=config/cn\=schema/cn\=\{6\}kerberos.ldif -H ldapi:///')
        self._shell('kdb5_ldap_util -D cn=admin,dc=example,dc=org -w a -H ldapi:/// create -P a -s') #self._createdb(passw) #81 =4
        self._shelltest('kdb5_ldap_util -D cn=admin,dc=example,dc=org -w a -H ldapi:/// stashsrvpw cn=admin,dc=example,dc=org')              
        #self._shell('krb5kdc') ## MUST KILL krb5kdc before first!
        self._writeHeader("+++++ START +++++")        
        
        #line 83-86 involves ktadd kadm5.keytab, which are out dated
        
        # add, get, and list princs
        self._writeHeader("SET UP: add/get/list princs")               
        self._locAddprinc(passw, 'kdc/admin') #87 =5
        self._locListprincs() #89 =6
        self._locGetprinc('K/M') #90 =7
        self._locAddprinc('test123', 'haoqili') #91 =8
        self._locGetprinc('haoqili') #92 =9
        self._locAddprinc(passw, 'haoqili/admin') #93 =10
        self._locAddprinc('foobar', 'test') #94 =11
        self._locGetprinc('test') #95 =12
        self._locListprincs() # I added =13
        myfqdn = socket.getfqdn()
        #self._shell(self.parentpath+"kadmin.local -q 'addprinc -randkey host/"+myfqdn+"'") #96
        self._shell(self.kadminlocal+" -q 'addprinc -randkey host/"+myfqdn+"'") #96 =14
        
        # create policies
        self._writeHeader("SET UP: create policies")
        
        #print "\n~~~~~~~~~ create policies ~~~~~~~~~~~"
        self._locAddpol('8days', None, None, None, 'testpolicy')#100 =15
        self._locAddpol('20days', '8', '3', None,  'testpolicy2')#101 
        self._locAddpol('90days', '2', '2', None,  'testpolicy3')#102
        #!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
        #!!!!!!!!!Changed to avoid problem in 'kpasswd all'!!!!!!!!!!!!!!!!!!!!
        #self._locAddpol('90days', '2', '2', '3', 'testpolicy4')#103
        self._locAddpol('90days', '2', '2', None, 'testpolicy4')#103
        #!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
            
        self._locModprinc('-policy testpolicy haoqili')#105
        self._locAddprinc(passw, 'foo')#106
        self._locModprinc('-policy testpolicy3 foo')#107 =21
        
        # create all princ with all fields
        self._writeHeader("SET UP: create all princ with all fields")
        #print "\n~~~~~~~~~ create all princ with all fields ~~~~~"
        self._locAddprinc(passw, 'all') #110 =22
        self._locModprinc('-expire "2029-12-30 7pm" all') #112
        self._locModprinc('-pwexpire 12/30/2029 all') #114
        #self._locModprinc('-expire "now+10years" all') #112
        #self._locModprinc('-pwexpire now+10years all') #114        
        self._locGetprinc('all') #115
        self._locModprinc('-maxlife 100days all') #116
        self._locGetprinc('all') #117
        self._locModprinc('-maxrenewlife 100days all') #118
        self._locGetprinc('all') #119
        self._locModprinc('+allow_postdated +allow_forwardable all') #120 =30
        self._locModprinc('+allow_proxiable +allow_dup_skey all') #121
        self._locModprinc('+requires_preauth +allow_svr +needchange all') #122
        self._locModprinc('-policy testpolicy4 all') #123 ###########
        self._locGetprinc('all') #124 =34
        
        # Testing stuff
        self._writeHeader("TEST: initial mkey list") #126
        self._writeLine("===== Listing mkeys at start of test") #I add
        self._listmkeys() #127 =35
        
        self._writeLine( "Testing krb5kdc list_mkeys Done ==============================================") #128

        self._writeLine("---------------\n xxxxxxxxxx \/\/\/ ERRORS (multiple) EXPECTED below xxxxxxxxxx")
        self._writeLine("\nERRORS (multiple) EXPECTED below") 
        self._writeLine("Testing bogus use_mkey (setting only mkey to future date, using non-existent kvno, so should return error) =======") #129, 130
        self._writeLine( "-> must have a mkey currently active (setting mkey to 2 days from now), should fail and return error") #132     
        self._usemkey('1', 'now+2days', False) #133-138 =36
        
        self._writeLine("-> must have a mkey currently active (setting mkey to 2019 the future), should fail and return error") #140
        self._usemkey('1', '5/30/2019', False) #141 =37
        self._writeLine("-> bogus kvno and setting mkey to 2 days from now, should fail and return error") #147
        self._usemkey('2', 'now+2days', False) #148 =38
        self._writeLine("-> bogus kvno, should fail and return error") #I add
        self._usemkey('2', 'now-2days', False) #I add =39
        self._writeLine( "^^^ABOVE^^ SHOULD HAVE *ALL* FAILED\n-----------------")

        self._writeLine( "Listing mkeys at end of test") #I add
        self._listmkeys() #155 =40
        self._writeLine("Testing bogus use_mkey (setting only mkey to future date) Done ===========================") #156
        
        
        self._writeLine("\nmake sure cpw [change password] works") #158
        # this changes the password of 'test' from 'foobar' in "add, get, and list princs" above
        self._locCpw('test1', 'test') #159 =41

        self._writeHeader("TEST: bogus purge_mkeys (should be no keys purged, no error returned")
        #print "\nTesting bogus purge_mkeys (should be no keys purged, no error returned) ===========================" #161
        self._purgemkeys() #162 =42
        self._writeLine("Testing bogus purge_mkeys (no error) Done ===========================") #163
        
        self._writeHeader( "add kvno 2") #164
        
        self._addmkey('abcde', '-s') #165-167 =43
        self._writeLine(".\nlist mkeys")
        self._listmkeys() #169 =44
        
        #start daemons
        #@@@@@@@@@@@@@@@@@@@@@@@@@@@############@@@@@@@@@@@@@@@@@@############
        self._startkdc() #172 =45 46
        self._writeLine("make sure kdc is up, by kinit test") #176
        self._kinit('test1', 'test') #177 =47
        
        self._writeLine("---------------\n\/\/\/ ERROR EXPECTED below.  Test passwd policy.:") #180
        self._kinit(passw, 'all', succeed=False) #181 =48
        self._writeLine("^^ABOVE^^ SHOULD HAVE FAILED\n-----------------")
        
        #change passwd on client's side
        
        #!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
        self._kpasswd(passw, 'Test123.', 'all')#184-188 =49 !!!!!!!!!!!!!!!!
        #!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!

        self._kinit('Test123.', 'all') #189 =50
        self._klist() #190 =51
        
        self._writeHeader("TEST: password history for principal 'all', new passwords must not be a previous password") #191
        self._kpasswd('Test123.', 'Foobar2!', 'all') #192-195 =52
        #!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
        '''
        self._writeLine("--------------\n\/\/\/ ERROR EXPECTED below") #197
        self._kpasswd('Foobar2!', passw, 'all', succeed=False) #199-202 =53
        self._writeLine("^^^ABOVE^^ SHOULD HAVE FAILED\n----------")
        '''
        #!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
        
        # this shouldn't change the mkvno for any princs (should be 1) #206
        #self._updatePrincEnc() #207
        # princs should still be protected by mkvno 1 #208
        self._writeLine("@@@@@@@@ Wait for other people to fix bug in code 6507 update_princ_encryption to use mkey instead of latest mkey @@@@@@@@@@@@@\n")
        self._locGetprincFind('test', 'MKey: vno 1') #209 =54
               
        self._purgemkeys() #210 =55   
        self._listmkeys() #211 =56
        self._usemkey('2', 'now-1day') #213 =57
        self._listmkeys() #214 =58
        #!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
        '''
        self._writeLine("-----------\n\/\/\/ ERROR EXPECTED below") #216
        self._kpasswd('Foobar2!', passw, 'all', succeed=False) #217-221 =59
        self._writeLine("^^^ABOVE^^ SHOULD HAVE FAILED\n--------") 
        '''
        #!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
        
        self._kpasswd('Foobar2!', 'Barfoo3.', 'all') #224-228 =60
        self._kinit('Barfoo3.', 'all') #229
        self._klist() #230 =62
        #!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
        '''    
        self._writeLine("-------------\n\/\/\/ ERROR EXPECTED below") #231
        self._kpasswd('Barfoo3.', 'Foobar2!', 'all',succeed=False) #233-235 =63
        self._writeLine("^^^ABOVE^^ SHOULD HAVE FAILED\n---------")
        '''
        #!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!

        self._writeLine("\nTest's key should be protected by mkvno 2" ) #239
        self._locCpw('foo', 'test') #240 =64
        self._locGetprincFind('test', 'MKey: vno 2') #241 =65
        self._kdestroy() #242 =66
        
        self._writeHeader("TEST: krb5kdc refetch of mkey")#243
        self._kinit('foo', 'test') #244 =67
        self._klist() #245 =68
        self._writeLine("END. Testing krb5kdc refetch of mkey list Done ==============================================\n")     #246
        
        self._updatePrincEnc() #247 =69
        self._get_princ_records() #248 =70 -83
        self._kdestroy() #249 =84
        self._kinit('foo', 'test') #250 =85
        self._purgemkeys() #252 =86
        
        #self._stash() #254 =87 #!!! Not necessary in ldap, done by 'create -s'
        self._shell(self.clients+'klist/klist' +" -ekt "+self.sandir+"/krb5kdc/.k5.EXAMPLE.ORG") #255=88

        self._locGetprinc('K/M') #256 =89
        self._purgemkeys() #257 =90
        self._locGetprinc('K/M') #258
        self._listmkeys() #259 =92
        self._kdestroy() #260
        self._kinit('foo', 'test') #261
        self._klist() #262 =95
        
        self._writeLine("\n Adding in Master Key Number 3")
        self._listmkeys() #265 =96
        self._addmkey('abcde') #266-268
        self._listmkeys() #270 =98
        self._locCpw('foo', 'all') #271
        self._locGetprinc('all') #272 =100
        self._usemkey('3', 'now') #273
        self._listmkeys() #274 =102
        self._locCpw('99acefghI0!', 'all') #275
        self._locGetprinc('all') #276 =104
        self._kdestroy() #277
        self._kinit('foo', 'test') #279 =106
        self._klist() #280
        self._shell(self.kadmin+" -p haoqili/admin -w "+passw+" -q 'listprincs'") #281 =108
        self._shell(self.kadmin+" -p haoqili/admin -w "+passw+" -q 'getprinc test'") #282 =109
        
        self._writeHeader("TEST: add_mkey with aes128 enctype") #283      
        self._addmkey('abcde', '-e aes128-cts-hmac-sha1-96') #284-287 =110
        #!!!!!!!!!!!!!!!!Start to have problems !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
        self._listmkeys() #288 =111
        '''$ kdb5_util list_mkeys
kdb5_util: Unable to decrypt latest master key with the provided master key
 while getting master key list
kdb5_util: Warning: proceeding without master key list
kdb5_util: master keylist not initialized'''#!!!!!!!!!!!!!!!!!!!!!!!
        #!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
        
        self._writeLine( "END. Testing add_mkey with aes128 enctype done ==============================================")#289     
        self._writeHeader("TEST: krb5kdc refetch of mkey list")
        #!!!!!!!!!!!!!!\/ errors \/ !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
        self._usemkey('4', 'now') #290 =112
        self._listmkeys() #291 =113
        #!!!!!!!!!!!!!!/\ errors /\ !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
        self._shell(self.kadmin+" -p haoqili/admin -w "+passw+" -q 'cpw -pw abcde test'") #292 =114
        self._shell(self.kadmin +" -p haoqili/admin -w "+passw+" -q 'getprinc test'") #293
        
        self._kdestroy() #294 =116
        
        self._writeLine("\nTesting krb5kdc refetch of mkey list =================================================") #295
        self._kinit('abcde', 'test') #296 =117
        self._klist() #297 =118
        self._writeLine("Testing krb5kdc refetch of mkey list Done :) =================================================\n") #298
        
        self._killkdc() #300 =119, 120
        self._startkdc() #301 =121 122
        
        # The lines below are commented out because krb5kdc could not be restarted.  For their error messages, see the outfile
        '''
        kdc.log:
        Aug 31 12:21:23 reach-my-dream krb5kdc[24273](info): AS_REQ (2 etypes {16 17}) 127.0.1.1: ISSUE: authtime 1251746483, etypes {rep=16 tkt=18 ses=16}, test@EXAMPLE.ORG for krbtgt/EXAMPLE.ORG@EXAMPLE.ORG
krb5kdc: Unable to decrypt latest master key with the provided master key
 - while fetching master keys list for realm EXAMPLE.ORG
        '''
        '''
        self._shell("kadmin -p haoqili/admin -w "+passw+" -q 'cpw -pw foo test'") #304 =123
        self._shell("kadmin -p haoqili/admin -w "+passw+" -q 'getprinc test'") #305 =124
        self._kdestroy() #307 =125

        self._writeLine("\nTesting krb5kdc refetch of mkey list =================================================") #308
        self._kinit('foo', 'test') #309 =126
        self._klist() #310 =127
        self._writeLine("Testing krb5kdc refetch of mkey list Done =================================================\n") #311
        
        self._updatePrincEnc() #313 =128
        self._locGetprinc('K/M') #314
        self._locGetprinc('all') #315 =130
        self._locGetprinc('haoqili') #316
        self._kdestroy() #317 =132
        self._kinit('foo', 'test') #318
        self._stash() #319 =134
        self._shell(self.clients+'klist/klist' +" -ekt "+self.sandir+"/krb5kdc/.k5.EXAMPLE.ORG") #320
        self._locGetprinc('K/M') #321 =136
        self._purgemkeys() #322
        self._locGetprinc('K/M') #323 =138
        self._locGetprinc('all') #324
        self._shell("kadmin -p haoqili/admin -w "+passw+" -q 'getprinc test'") #325 =140
        self._listmkeys() #326
        self._kdestroy() #327 =142
        self._kinit('foo', 'test') #328
        self._klist() #329 =144
        
        self._get_princ_records() #330 =145-158
        
        self._writeHeader("TEST: add_meky with DES-crc enctype")
        #print "\nTesting add_mkey with DES-crc enctype ==============================================" #331
        self._addmkey('abcde', '-e des-cbc-crc') #332-335 =159
        self._listmkeys() #336 =160
        self._writeLine( "END. Testing add_mkey with DES-crc enctype Done ==============================================") #337
        self._addmkey('abcde') #338-341 =161
        self._listmkeys() #342 =162
        self._writeLine( "current time: "+strftime("%Y-%m-%d %H:%M:%S") ) #343
        
        self._usemkey('5', 'now-1day') #344 =163
        self._writeLine("current time: "+strftime("%Y-%m-%d %H:%M:%S") )#345
        self._listmkeys() #346 =164
        self._usemkey('5', 'now') #347 =165
        self._writeLine("current time: "+strftime("%Y-%m-%d %H:%M:%S") )#348
        self._listmkeys() #349 =166
        self._usemkey('5', 'now+3days') #350 =167
        self._writeLine("current time: "+strftime("%Y-%m-%d %H:%M:%S") )#351
        self._listmkeys() #352 =168
        self._writeLine("current time: "+strftime("%Y-%m-%d %H:%M:%S") )#353
        self._usemkey('5', 'now+5sec') #354 =169
        self._listmkeys() #355 =170
        time.sleep(5) #356
        self._listmkeys() #357 =171
        self._writeLine("current time: "+strftime("%Y-%m-%d %H:%M:%S") )#358
        self._usemkey('4', 'now+5sec') #359 =172
        self._listmkeys() #360 =173
        time.sleep(5) #361
        self._listmkeys() #362 =174
        self._usemkey('5', 'now+3days') #363 =175

        self._writeLine("------------\n\/\/\/ ERROR EXPECTED below" )#364
        self._writeLine("should fail, because there must be one mkey currently active") #365
        self._usemkey('4', 'now+2days', False) #366 =176
        self._writeLine("^^^ABOVE^^ SHOULD HAVE FAILED\n---------------")

        self._listmkeys() #373 =177
        self._usemkey('4', '1/30/2009') #375 =178
        
        self._writeHeader("TEST: purge_mkeys (removing mkey 5)")
        #print "\nTesting purge_mkeys (removing mkey 5) ==============================================" #378
        self._purgemkeys() #379 =179
        #self._stash() #380 =180
        self._shell(self.clients+'klist/klist' +" -ekt "+self.sandir+"/krb5kdc/.k5.EXAMPLE.ORG") #381=181
        self._listmkeys() #382 =182
        self._shell("kadmin -p haoqili/admin -w "+passw+" -q 'getprinc K/M'") #383 =183
        self._writeLine("Testing purge_mkeys Done ==============================================") #384
        self._writeHeader("MASTER KEY MIGRATION TEST DONE. please consult 'outfile' in your sandbox for more info.  The sandbox is at: %s" % self.sandir) 
 # I added
        self._sysexit(finished=True)
        '''
####################################################
####################################################

class Launcher:
    #def __init__(self, path, sandP):
    #def __init__(self):
    def __init__(self, sandP):
        self._buildDir = os.environ["PWD"]
        self._confDir = '%s/tests/mk_migr/ldap_backend/input_conf' % self._buildDir
        
        #setting up sandbox
        if sandP != "":
            self._sandP = sandP 	
        else: #default
            self._sandP = '%s/tests/mk_migr/ldap_backend/sandbox' %self._buildDir

        print self._sandP
        print "sandP"
    	self._vars = {'sandir': self._sandP, 
            	      'localFQDN': socket.getfqdn()}

    def _prepSandbox(self, sandir):
        if os.path.exists(sandir):
            shutil.rmtree(sandir)
        print "------about to make sandbox, with the path of:"
        print sandir
        os.makedirs(sandir, 0777)
	os.mkdir(sandir+'/krb5kdc', 0777)
        print "------sandbox made"

    def _createFileFromTemplate(self, outpath, template, vars):
        fin = open(template, 'r')
        result = fin.read() % vars
        fin.close()
        fout = open(outpath, 'w')
        fout.write(result)
        fout.close()

    ####### Launcher RUN ################
    def runLauncher(self):
        # create sandbox file directory (and sandbox/krb5kdc) if it does not exit
        self._prepSandbox(self._sandP)

        # Export the 3 env lines
	src_path=os.environ["PWD"]
        os.environ["LD_LIBRARY_PATH"] = '%s/lib' % src_path

        str1 = '%s/krb5.conf' % self._sandP
        os.environ["KRB5_CONFIG"] = str1

        str2 = '%s/kdc.conf' % self._sandP
        os.environ["KRB5_KDC_PROFILE"] = str2

        str3 = '%s/kadm5.acl' % self._sandP   

        # Create adequate to the environment config files
        self._createFileFromTemplate(str1, '%s/%s' % (self._confDir, 'krb5_template_ldap.conf'), self._vars)
        self._createFileFromTemplate(str2, '%s/%s' % (self._confDir, 'kdc_template_ldap.conf'), self._vars)
        self._createFileFromTemplate(str3, '%s/%s' % (self._confDir, 'kadm5_template_ldap.acl'), self._vars)
        
        return (self._confDir, self._sandP)

####################################################
####################################################

def makeBool(aStr):
    if aStr == "True" or aStr == "T":
        return True
    if aStr == "False" or aStr == "F":
        return False
    else:
        print "did NOT execute due to invalid True False argument.  Please enter either 'True', 'T', 'False', or 'F'"
        sys.exit()

# # # # # # # # # # # # # # # # # # # # # # # # #

def processInputs(parser):
#def processInputs():
    
    # get inputs
    (options, args) = parser.parse_args()

    verbose = makeBool(options.opVerbose)
    pw = options.opPassword

    kdcPath = options.opKdcPath #1
    kdmdPath = options.opKdmdPath #2
    kdbPath = options.opKdbPath #3a
    ldapPath = options.opLdapPath #3b
    kdmlPath = options.opKdmlPath #4
    kdmPath = options.opKdmPath #5
    cltPath = options.opCltPath #6

    sandPath = options.opSandbox

    ########### Launch ###############
    
    print "\n############ Start Launcher #############"    
    myLaunch = Launcher(sandPath)
    (confDir, sandPath) = myLaunch.runLauncher()
    
    print ":D"
    print sandPath
    
    test = LDAPbackendSetup(verbose, pw,  kdcPath, kdmdPath, kdbPath, ldapPath, kdmlPath, kdmPath, cltPath, sandPath, confDir)
    print "########## Finished Launcher ############\n"

    return test
# # # # # # # # # # # # # # # # # # # # # # # # #

def makeParser():
    usage = "\n\t%prog [-v][-p][-c][-d][-b][-l][-t][-s]"
    description = "Description:\n\tTests for the master key migration commands."
    parser = OptionParser(usage=usage, description=description)

    parser.add_option("-v", "--verbose",  type="string", dest="opVerbose", 
default="True", help="'True' or 'False'.  Switch on for details of command lines and outputs.  Default is 'True'")

    parser.add_option("-p", "--password",  type="string", dest="opPassword",  default="test123", help="master password for many of the passwords in the test. Default is 'test123'")

    ## Default Paths
    dSrcPath = src_path=os.environ["PWD"]
    dKdcPath = '%s/kdc/krb5kdc' % dSrcPath #1    
    dKdmdPath = '%s/kadmin/server/kadmind' % dSrcPath #2   
    dKdbPath = '%s/kadmin/dbutil/kdb5_util' % dSrcPath #3a
    dLdapPath = '%s/plugins/kdb/ldap/ldap_util/kdb5_ldap_util' % dSrcPath #3b
    dKdmlPath = '%s/kadmin/cli/kadmin.local' % dSrcPath #4
    dKdmPath = '%s/kadmin/cli/kadmin' % dSrcPath #5
    dCltPath = '%s/clients' % dSrcPath #6

    parser.add_option("-c", "--krb5kdcpath",
type="string", dest="opKdcPath", 
default=dKdcPath, help="set krb5kdc path, default="+dKdcPath) #1

    parser.add_option("-d", "--kadmindpath", 
type="string", dest="opKdmdPath", 
default=dKdmdPath, help="set kadmind path, default="+dKdmdPath) #2

    parser.add_option("-b", "--kdb5_utilpath", 
type="string", dest="opKdbPath", 
default=dKdbPath, help="set kdb5_util path, default="+dKdbPath) #3a

    parser.add_option("-a", "--kdb5_ldap_utilpath", 
type="string", dest="opLdapPath", 
default=dKdbPath, help="set kdb5_ldap_util path, default="+dLdapPath) #3b

    parser.add_option("-l", "--kadminlocalpath", 
type="string", dest="opKdmlPath", 
default=dKdmlPath, help="set kadmin.local path, default="+dKdmlPath) #4

    parser.add_option("-n", "--kadminpath", 
type="string", dest="opKdmPath", 
default=dKdmPath, help="set kadmin path, default="+dKdmPath) #5 

    parser.add_option("-t", "--clientspath", 
type="string", dest="opCltPath", 
default=dCltPath, help="set clients path, default="+dCltPath) #6

    # set up / initializing stuff for the sandbox
    parser.add_option("-s", "--sandbox",
type="string", dest="opSandbox",
default="",
help="path for the sandbox. Default is 'src/tests/mk_migr/ldap_backend/sandbox'")

    return parser

####################################################
if __name__ == '__main__':
    #processInputs()
    
    parser = makeParser()    
    test = processInputs(parser)
    result = test.run()
