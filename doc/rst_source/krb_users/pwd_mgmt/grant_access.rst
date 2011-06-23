.. _gatya_label:

Granting access to your account
======================================

If you need to give someone access to log into your account, you can do so through Kerberos, without telling the person your password. Simply create a file called .k5login in your home directory. This file should contain the Kerberos principal of each person to whom you wish to give access. Each principal must be on a separate line. Here is a sample *.k5login* file::

     jennifer@ATHENA.MIT.EDU
     david@EXAMPLE.COM

This file would allow the users *jennifer* and *david* to use your user ID, provided that they had Kerberos tickets in their respective realms. If you will be logging into other hosts across a network, you will want to include your own Kerberos principal in your *.k5login* file on each of these hosts.

Using a *.k5login* file is much safer than giving out your password, because:

- You can take access away any time simply by removing the principal from your *.k5login* file.
- Although the user has full access to your account on one particular host (or set of hosts if your *.k5login* file is shared, e.g., over NFS), that user does not inherit your network privileges.
- Kerberos keeps a log of who obtains tickets, so a system administrator could find out, if necessary, who was capable of using your user ID at a particular time.

One common application is to have a *.k5login* file in root's home directory, giving root access to that machine to the Kerberos principals listed. This allows system administrators to allow users to become root locally, or to log in remotely as root, without their having to give out the root password, and without anyone having to type the root password over the network.

------------------

Feedback:

Please, provide your feedback at krb5-bugs@mit.edu?subject=Documentation___users_pwd_mgmt


