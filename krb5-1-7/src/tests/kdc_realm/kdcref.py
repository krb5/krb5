import os
import sys
import time
from subprocess import Popen, PIPE, STDOUT
import signal
import socket
import errno
import shutil


class LaunchError(Exception):
    """ Exception class to signal startup error"""
    pass

class AdminError(Exception):
    """ Exception class to handle admin errors"""
    pass


class Launcher:
    
    def __init__(self, path):
        self._buildDir = path
        self._confDir = '%s/tests/kdc_realm/input_conf' %  self._buildDir    
        confFile ='%s/test_setup.conf' % self._confDir       
        confParams = self._testSetup(confFile)       
        self._sandboxDir = '%s/%s' % (self._buildDir,confParams['sandboxDir'])
        self._sandboxTier1 = '%s/%s' % (self._sandboxDir, 'tier1')
        self._sandboxTier2 = '%s/%s' % (self._sandboxDir, 'tier2')
        self._configurations = self._readServerConfiguration('%s/%s' % (self._confDir,confParams['testKDCconf']))
        self._configurations_1 = self._readServerConfiguration('%s/%s' % (self._confDir,confParams['testKDCconf_1']))
        self._principals = self._readTestInputs('%s/%s' % (self._confDir,confParams['principals']))
        os.environ["LD_LIBRARY_PATH"] = '%s/lib' % self._buildDir
        self._pidRefKDC = 0
        self._pidMap = dict()
        self._initialized = False
        self._tier1Init = False
        self._tier2Init = False
        self._vars = {'srcdir': self._buildDir, 
                      'tier1':self._sandboxTier1, 
                      'tier2':self._sandboxTier2, 
                      'localFQDN':socket.getfqdn()}
 
    def _launchKDC(self, tierId, args, env):
        """
        Launching KDC server
        """
        cmd = '%s/kdc/krb5kdc' % self._buildDir
        handle = Popen([cmd, args], env=env)    
        time.sleep(1)
        # make sure that process is running
        rc = handle.poll()
        if rc is None:
            print 'KDC server has been launched: pid=%s, tier=%s' % (handle.pid, tierId)
            self._pidMap[handle.pid] = 1            
            return handle.pid
        else:
            raise LaunchError, 'Failed to launch kdc server'


    def _prepSandbox(self):
         for tierId in range(1,3):
            tierdir = '%s/tier%i' % (self._sandboxDir, tierId)
            if  os.path.exists(tierdir):
                shutil.rmtree(tierdir)                           
            os.makedirs(tierdir, 0777)
                

    def _kill(self, pid = None):
        """
         Kill specific process or group saved in pidMap 
        """
        if pid is None:
            target = self._pidMap.keys()
        else:
            target = [pid]
        for p in target:
            if p in self._pidMap:
                del self._pidMap[p]
            try:
                os.kill(p, signal.SIGKILL)
            except OSError:
                pass
        
        
    def _createDB(self, env):
        """
        Creating DB
        """
        cmd = '%s/kadmin/dbutil/kdb5_util'  % self._buildDir                
        p = Popen([cmd, 'create', '-s'], env = env, stdin=PIPE, stdout=PIPE, stderr=PIPE)        
        (out, err) = p.communicate('a\na\n')
        if p.returncode != 0:
            err_msg = 'Failed to create DB: %s' % err
            raise LaunchError, err_msg

        
    def _launchClient(self, args, env, princType):
        """
        kinit & kvno
        """
        self._addPrinc(args, env)
        p = Popen(['kinit', args], env = env, stdin=PIPE, stdout=PIPE, stderr=PIPE)
        (out, err) = p.communicate('a\n')
        if int(p.wait()) == 0:
            self._initialized = True            
        else:
            err_msg = 'Failed to kinit client: %s' % err
            raise AdminError, err_msg      

        # testHost', 'mybox.mit.edu is a srv defined in referral KDC. Get its kvno 
        cmd = '%s/clients/kvno/kvno' % self._buildDir 
        if princType == 0:
             handle = Popen([cmd, '-C', '-S', 'testHost', 'mybox.mit.edu'],
                            env = env, stdin=PIPE, stdout=PIPE, stderr=PIPE)
        if princType == 1:
            handle = Popen([cmd, '-C', '-u', 'testHost/mybox.mit.edu'],                
                       env = env, stdin=PIPE, stdout=PIPE, stderr=PIPE)
        (out, err) = handle.communicate()
        handle.wait()
        print 'kvno return code: %s' % handle.returncode

        # Cleanup cached info
        p = Popen(['kdestroy'], env = env, stdin=PIPE, stdout=PIPE, stderr=PIPE)
        (out, err) = p.communicate()
        if int(p.wait()) != 0:
            err_msg = 'Failed to kdestroy cashed tickets: %s' % err
            raise AdminError, err_msg
        
        return handle.returncode
    
            
    def _addPrinc(self, args, env):
        """
        Add Principal
        """     
        msg = 'addprinc -pw a %s' % args
        p = Popen(['kadmin.local' ], env = env, stdin=PIPE, stdout=PIPE, stderr=PIPE)
        (out, err) = p.communicate(msg)
        if int(p.wait()) != 0:
            err_msg = 'Failed to add principal %s' % err_msg 
            raise AdminError, err_msg

        
    def _crossRealm(self, r_local, r_remote, env):
        """
        Croos-realm setup
        """     
        msg = 'addprinc  -pw a krbtgt/%s@%s' % (r_remote, r_local)
        p = Popen(['kadmin.local' ], env = env, stdin=PIPE, stdout=PIPE, stderr=PIPE)
        (out, err) = p.communicate(msg)
        if int(p.wait()) != 0:
            err_msg = 'Failed to set cross-realm: %s' % err
            raise AdminError, err_msg 
        
        msg = 'addprinc  -pw a krbtgt/%s@%s' % (r_local, r_remote)
        p = Popen(['kadmin.local' ], env = env, stdin=PIPE, stdout=PIPE, stderr=PIPE)
        (out, err) = p.communicate(msg)
        if int(p.wait()) != 0:
            err_msg = 'Failed to set cross-realm: %s' % err
            raise AdminError, err_msg 

        
    def _launchRefKDC(self,test_env):
        """
        Launch referral KDC 
        """
        test_env["KRB5_CONFIG"] = '%s/krb5.conf' % self._sandboxTier1
        test_env["KRB5_KDC_PROFILE"] = '%s/kdc.conf' % self._sandboxTier1      
        server_args = '-n'
        if self._tier1Init == False:
            # Create adequate to the environment config files         
            self._createFileFromTemplate('%s' % test_env["KRB5_CONFIG"],
                        '%s/%s' % (self._confDir,'krb5_ref_template.conf'), 
                        self._vars)
            self._createFileFromTemplate('%s' % test_env["KRB5_KDC_PROFILE"],
                        '%s/%s' % (self._confDir, 'kdc_ref_template.conf'), 
                        self._vars)
            
            # create DB for  KDC to be referred to
            pid = self._createDB(test_env)
            
            # launch KDC to be referred to
            self._pidRefKDC = self._launchKDC(1, server_args, test_env)
 
            # The tests run against 'testHost/mybox.mit.edu' srv. 
            args = 'testHost/mybox.mit.edu'
            self._addPrinc(args, test_env)
            self._crossRealm('Z.COM', 'Y.COM', test_env)
            self._tier1Init = True
        
        
    def _launchTestingPair(self, srvParam,clntParam, princType):
        # launch KDC       
        server_env = os.environ.copy()
        server_env["KRB5_KDC_PROFILE"] = '%s/kdc.conf' % self._sandboxTier2  
        server_env["KRB5_CONFIG"] = '%s/krb5_KDC.conf' % self._sandboxTier2       
        server_args = '-n'
        self._createFileFromTemplate('%s' % server_env["KRB5_CONFIG"],
                                     '%s/%s' % (self._confDir,srvParam),
                                     self._vars)
        self._createFileFromTemplate('%s' % server_env["KRB5_KDC_PROFILE"],
                                     '%s/%s' % (self._confDir,'kdc_pri_template.conf'),
                                     self._vars)
        if self._tier2Init == False:
          pid = self._createDB(server_env)
          self._crossRealm('Y.COM', 'Z.COM', server_env)            
          self._tier2Init = True
            
        server = self._launchKDC( 2, server_args, server_env)
        
       # launch client
        client_env = os.environ.copy()
        client_env["KRB5_CONFIG"] = '%s/krb5_CL.conf' % self._sandboxTier2    
        self._createFileFromTemplate('%s' % client_env["KRB5_CONFIG"],
                        '%s/%s' % (self._confDir, 'krb5_priCL_template.conf'),
                         self._vars)  
        client_env["KRB5_KDC_PROFILE"] = server_env["KRB5_KDC_PROFILE"]                    
        rc = self._launchClient(clntParam, client_env, princType)
        self._kill(server)
        return rc
 
            
    def run(self, args):
        """
        run the test
        """
        test_env = os.environ.copy()
        test_env["SRCDIR"] = '%s' % self._buildDir
        
        # create sandbox file directory if it does not exist
        self._prepSandbox()

        if self._tier1Init == False:
            self._launchRefKDC(test_env)
       
        result = dict()
        for princs in self._principals:
            for conf in self._configurations:                                         
                rc = self._launchTestingPair( conf['confName'], princs % self._vars, 0)
                result[conf['confName']] = {'expected':conf['expected'], 'actual':rc}
                print 'Test code for configuration %s principal %s type KRB5_NT_SRV_HST: %s' % (conf, princs, rc)  
            self.printTestResults(result)
            for conf in self._configurations_1:                                         
                rc = self._launchTestingPair( conf['confName'], princs % self._vars, 1)
                result[conf['confName']] = {'expected':conf['expected'], 'actual':rc}
                print 'Test code for configuration %s principal %si type KRB5_NT_UNKNOWN: %s' % (conf, princs, rc)    
            self.printTestResults(result)
        return result


    def _readTestInputs(self, path):
        f = open(path, 'r')
        result = []
        for line in f:
            result.append(line.rstrip())
        f.close()
        return result
 

    def _readServerConfiguration(self, path):
        f = open(path, 'r')
        result = []
        for line in f:
            fields = (line.rstrip()).split(',')
            result.append({'confName':fields[0],'expected':fields[1]})
        f.close()
        return result

 
    def _testSetup(self, path):
        print path
        f = open(path, 'r')
        result = dict()
        for line in f:
            try:
                (a,v) = line.rstrip().split('=')
                result[a]=v
            except:
                print 'bad format for config file, line: %s' % line
                return None
        f.close()
        return result

    
    def _createFileFromTemplate(self, outpath, template, vars):
        fin = open(template, 'r')
        result = fin.read() % vars
        fin.close()
        fout = open(outpath, 'w')
        fout.write(result)
        fout.close()

        
    def _getDNS(self):
        print socket.getfqdn()
        
        
    def printTestResults(self, testResults):
        success_count = 0
        fail_count = 0
        print '\n'
        print '------------------- Test Results ------------------------'
        for (conf_name, result) in testResults.iteritems():
            if int(result['expected']) == int(result['actual']):
                print 'Test for configuration %s has succeeded' % conf_name
                success_count += 1
            else:
                print 'Test for configuration %s has failed' % conf_name
                fail_count += 1

        print '------------------- Summary -----------------------------'
        print 'Of %i tests %i failed, %i succeeded' % (len(testResults),
                                                       fail_count,
                                                       success_count)
        print '---------------------------------------------------------'
    

    def clean(self):
        self._kill()

        
if __name__ == '__main__':
    src_path = os.environ["PWD"]
    print "SOURCE PATH ==>" , src_path
    test = None
    try:
        test = Launcher(src_path)
        result = test.run('main')
        test.clean()
        
    except:
        if test is not None:
            test.clean()
        raise
