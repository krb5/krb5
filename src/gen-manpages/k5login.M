.TH .K5LOGIN 5
.SH NAME
.k5login \- Kerberos V5 acl file for host access.
.SH DESCRIPTION
The
.B .k5login
file, which resides in a user's home directory, contains a list of the
Kerberos principals.  Anyone with valid tickets for a principal in the
file is allowed host access with the UID of the user in whose home
directory the file resides.  One common use is to place a
.B .k5login
file in root's home directory, thereby granting system administrators
remote root access to the host via Kerberos.
.SH EXAMPLES
Suppose the user "janedoe" had a 
.B .k5login
file in her home directory containing the following line:
.sp
.nf
.in +1i
johndoe@FUBAR.ORG
.in -1i
.fi
.sp
This would allow her husband "johndoe" to use any of the Kerberos
network applications, such as
.IR telnet (1),
.IR rlogin (1),
.IR rsh (1),
and
.IR rcp (1),
to access her account, using his own Kerberos tickets.
.PP
Let us further suppose that "janedoe" is a system administrator.  She
and the other system administrators would have their principals in
root's
.B .k5login
file on each host:
.sp
.nf
.in +1i
janedoe@BLEEP.COM
joeadmin/root@BLEEP.COM
.in -1i
.fi
.sp
This would allow either system administrator to log in to these hosts
using their Kerberos tickets instead of having to type the root
password.  Note that because "janedoe"'s husband retains the Kerberos
tickets for his own principal, "johndoe@FUBAR.ORG", he would not have
any of the privileges that require his wife's tickets, such as root
access to any of her site's hosts, or the ability to change her
password.
.SH SEE ALSO
telnet(1), rlogin(1), rsh(1), rcp(1), ksu(1), telnetd(8), klogind(8)
