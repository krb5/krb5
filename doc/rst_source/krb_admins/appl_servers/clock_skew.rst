Clock Skew
============

In order to prevent intruders from resetting their system clocks in order to continue to use expired tickets, Kerberos V5 is set up to reject ticket requests from any host whose clock is not within the specified maximum clock skew of the KDC (as specified in the kdc.conf file). Similarly, hosts are configured to reject responses from any KDC whose clock is not within the specified maximum clock skew of the host (as specified in the krb5.conf file). The default value for maximum clock skew is 300 seconds, or five minutes. MIT suggests that you add a line to client machines' /etc/rc files to synchronize the machine's clock to your KDC at boot time. On UNIX hosts, assuming you had a kdc called kerberos in your realm, this would be::

     gettime -s kerberos
     

If the host is not likely to be rebooted frequently, you may also want to set up a cron job that adjusts the time on a regular basis. 

----------------------

Feedback:

Please, provide your feedback at krb5-bugs@mit.edu?subject=Documentation___appl_servers

