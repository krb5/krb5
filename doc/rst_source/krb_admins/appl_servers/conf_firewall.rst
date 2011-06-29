.. _conf_firewall_label:

Configuring your firewall to work with Kerberos V5
=====================================================

If you need off-site users to be able to get Kerberos tickets in your realm, they must be able to get to your KDC. This requires either that you have a slave KDC outside your firewall, or you configure your firewall to allow UDP requests into at least one of your KDCs, on whichever port the KDC is running. (The default is port 88; other ports may be specified in the KDC's kdc.conf file.) Similarly, if you need off-site users to be able to change their passwords in your realm, they must be able to get to your Kerberos admin server. The default port for the admin server is 749.

If your on-site users inside your firewall will need to get to KDCs in other realms, you will also need to configure your firewall to allow outgoing TCP and UDP requests to port 88. Additionally, if they will need to get to any Kerberos V4 KDCs, you may also need to allow TCP and UDP requests to port 750. If your on-site users inside your firewall will need to get to Kerberos admin servers in other realms, you will also need to allow outgoing TCP and UDP requests to port 749.

If any of your KDCs are outside your firewall, you will need to allow *kprop* requests to get through to the remote KDC. 
*kprop* uses the *krb5_prop* service on port 754 (tcp).

If you need your off-site users to have access to machines inside your firewall, you need to allow TCP connections from their off-site hosts on the appropriate ports for the programs they will be using. The following lines from */etc/services* show the default port numbers for the Kerberos V5 programs::

     ftp           21/tcp           # Kerberos ftp and telnet use the
     telnet        23/tcp           # default ports
     kerberos      88/udp    kdc    # Kerberos V5 KDC
     kerberos      88/tcp    kdc    # Kerberos V5 KDC
     klogin        543/tcp          # Kerberos authenticated rlogin
     kshell        544/tcp   cmd    # and remote shell
     kerberos-adm  749/tcp          # Kerberos 5 admin/changepw
     kerberos-adm  749/udp          # Kerberos 5 admin/changepw
     krb5_prop     754/tcp          # Kerberos slave propagation
     eklogin       2105/tcp         # Kerberos auth. & encrypted rlogin
     

By default, Kerberos V5 telnet and ftp use the same ports as the standard telnet and ftp programs, so if you already allow telnet and ftp connections through your firewall, the Kerberos V5 versions will get through as well. If you do not already allow telnet and ftp connections through your firewall, but need your users to be able to use Kerberos V5 telnet and ftp, you can either allow ftp and telnet connections on the standard ports, or switch these programs to non-default port numbers and allow ftp and telnet connections on those ports to get through. Kerberos V5 rlogin uses the *klogin* service, which by default uses port 543. Encrypted Kerberos V5 rlogin uses the *eklogin* service, which by default uses port 2105. Kerberos V5 rsh uses the kshell service, which by default uses port 544. However, the server must be able to make a TCP connection from the kshell port to an arbitrary port on the client, so if your users are to be able to use rsh from outside your firewall, the server they connect to must be able to send outgoing packets to arbitrary port numbers. Similarly, if your users need to run rsh from inside your firewall to hosts outside your firewall, the outside server needs to be able to connect to an arbitrary port on the machine inside your firewall. Because Kerberos V5 rcp uses rsh, the same issues apply. If you need to use rsh (or rcp) through your firewall and are concerned with the security implications of allowing connections to arbitrary ports, MIT suggests that you have rules that specifically name these applications and, if possible, list the allowed hosts.

The book UNIX System Security, by David Curry, is a good starting point for learning to configure firewalls. 

----------------------

Feedback:

Please, provide your feedback at krb5-bugs@mit.edu?subject=Documentation___appl_servers

