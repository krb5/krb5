@Comment[	$Source$]
@Comment[	$Author$]
@Comment[	$Id$]
@Comment[]
@device[postscript]
@make[report]
@comment[
@DefineFont(HeadingFont,
      P=<RawFont "NewCenturySchlbkBoldItalic">,
      B=<RawFont "NewCenturySchlbkBold">,
      I=<RawFont "NewCenturySchlbkBoldItalic">,
      R=<RawFont "NewCenturySchlbkRoman">)
]
@DefineFont(HeadingFont,
      P=<RawFont "TimesBoldItalic">,
      B=<RawFont "TimesBold">,
      I=<RawFont "TimesItalic">,
      R=<RawFont "TimesRoman">)
@Counter(MajorPart,TitleEnv HD0,ContentsEnv tc0,Numbered [@I],
          IncrementedBy Use,Announced)
@Counter(Chapter,TitleEnv HD1,ContentsEnv tc1,Numbered [@1. ],
          IncrementedBy Use,Referenced [@1],Announced)
@Counter(Appendix,TitleEnv HD1,ContentsEnv tc1,Numbered [@A. ],
          IncrementedBy,Referenced [@A],Announced,Alias Chapter)
@Counter(UnNumbered,TitleEnv HD1,ContentsEnv tc1,Announced,Alias 
           Chapter)
@Counter(Section,Within Chapter,TitleEnv HD2,ContentsEnv tc2,
          Numbered [@#@:.@1 ],Referenced [@#@:.@1],IncrementedBy
          Use,Announced)
@Counter(AppendixSection,Within Appendix,TitleEnv HD2,
          ContentsEnv tc2,
          Numbered [@#@:.@1 ],Referenced [@#@:.@1],IncrementedBy 
          Use,Announced)
@Counter(SubSection,Within Section,TitleEnv HD3,ContentsEnv tc3,
          Numbered [@#@:.@1 ],IncrementedBy Use,
          Referenced [@#@:.@1 ])
@Counter(AppendixSubSection,Within AppendixSection,TitleEnv HD3,
          ContentsEnv tc3,
          Numbered [@#@:.@1 ],IncrementedBy Use,
          Referenced [@#@:.@1 ])
@Counter(Paragraph,Within SubSection,TitleEnv HD4,ContentsEnv tc4,
          Numbered [@#@:.@1 ],Referenced [@#@:.@1],
          IncrementedBy Use)
@modify(CopyrightNotice, Fixed -1 inch, Flushright)
@Modify(Titlebox, Fixed 3.0 inches)
@Modify(hd1, below .2 inch, facecode B, size 16, spaces kept, pagebreak off)
@Modify(hd2, below .2 inch, facecode B, size 14, spaces kept)
@Modify(hd3, below .2 inch, facecode B, size 12, spaces kept)
@Modify(Description, Leftmargin +20, Indent -20,below 1 line, above 1 line)
@Modify(Tc1, Above .5,  Facecode B)
@Modify(Tc2, Above .25, Below .25, Facecode R)
@Modify(Tc3,Facecode R)
@Modify(Tc4,Facecode R)
@Modify(Itemize,Above 1line,Below 1line)
@Modify(Insert,LeftMargin +2, RightMargin +2)
@libraryfile[stable]
@comment[@Style(Font NewCenturySchoolBook, size 11)]
@Style(Font TimesRoman, size 11)
@Style(Spacing 1.1, indent 0)
@Style(leftmargin 1.0inch)
@Style(justification no)
@Style(BottomMargin 1.5inch)
@Style(ChangeBarLocation Right)
@Style(ChangeBars=off)
@pageheading[immediate]
@pagefooting[immediate, left = "MIT Project Athena", center = "@value(page)",
right = "@value(date)"]
@set[page = 0]
@blankspace[.5 inches]
@begin[group, size 20]
@begin(center)
@b[Kerberos Operation Notes]
@b[DRAFT]
@end[center]
@blankspace[.5 inches]
@end(group)
@begin[group, size 16]
@begin(center)
Bill Bryant
John Kohl
Project Athena, MIT
@blankspace[.5 inches]
@b[Initial Release, January 24, 1989]
@i[(plus later patches through patchlevel 7)]
@end[center]
@end(group)
@begin[group, size 10]
@end[group]
@blankspace[1inches]

These notes assume that you have used the
@i[Kerberos Installation Notes] to build and install your
Kerberos system.
As in that document, we refer to the directory that contains
the built Kerberos binaries as [OBJ_DIR].

This document assumes that you are a Unix system manager.

@newpage()
@chapter[How Kerberos Works: A Schematic Description]

This section provides a simplified description of
a general user's interaction with the Kerberos system.
This interaction happens transparently--users don't need to know
and probably don't care about what's going on--but Kerberos administrators
might find a schematic description of the process useful.
The description glosses over a lot of details;
for more information, see @i[Kerberos: An Authentication
Service for Open Network Systems],
a paper presented at Winter USENIX 1988, in Dallas, Texas.

@section[Network Services and Their Client Programs]

In an environment that provides network services,
you use @i[client] programs to request service from
@i[server] programs that are somewhere on the network.
Suppose you have logged in to a workstation
and you want to @i[rlogin] to another machine.
You use the local @i[rlogin] client program to
contact the remote machine's @i[rlogin] service daemon.

@section[Kerberos Tickets]

Under Kerberos, the @i[rlogin] service program
allows a client to login to a remote machine if it
can provide
a Kerberos @b[ticket] for the request.
This ticket proves the identity of the person who has used
the client program to access the server program.

@section[The Kerberos Master Database]

Kerberos will give you tickets only if you
have an entry in the Kerberos server's
@b[master database].
Your database entry includes your Kerberos username (often referred to
as your Kerberos @b[principal] name), and your Kerberos password.
Every Kerberos user must have an entry in this database.

@section[The Ticket-Granting Ticket]

The @i[kinit] command prompts for your Kerberos username and password,
and if you enter them successfully, you will obtain a Kerberos
@i[ticket-granting ticket].
As illustrated below,
client programs use this ticket to get other Kerberos tickets as
needed.

@section[Network Services and the Master Database]

The master database also contains entries for all network services that
require Kerberos authentication.
Suppose for instance that your site has a machine @i[laughter]
that requires Kerberos authentication from anyone who wants
to @i[rlogin] to it.
This service must be registered in the master database.
Its entry includes the service's principal name, and its @b[instance].

The @i[instance] is the name of the service's machine;
in this case, the service's instance is the name @i[laughter].
The instance provides a means for Kerberos to distinguish between
machines that provide the same service.
Your site is likely to have more than one machine that
provides @i[rlogin] service.

@section[The User-Kerberos Interaction]

Suppose that you (in the guise of a general user) walk up to a workstation
intending to login to it, and then @i[rlogin] to the machine @i[laughter].
Here's what happens.
@begin[enumerate]
You login to the workstation and use the @i[kinit] command
to to get a ticket-granting ticket.
This command prompts you for your username (your Kerberos Principal Name),
and your Kerberos password [on some systems which use the new version of
@i{/bin/login}, this may be done as part of the login process, not
requiring the user to run a separate program].
@begin[enumerate]
The @i[kinit] command sends your request to the Kerberos master server
machine.
The server software looks for your principal name's entry in the
Kerberos @b[master database].

If this entry exists, the
Kerberos server creates and returns a
@i[ticket-granting ticket], encrypted in your password.
If @i[kinit] can decrypt the Kerberos reply using the password you
provide, it stores this ticket in a @b[ticket file] on your
local machine for later use.
The ticket file to be used
can be specified in the @b[KRBTKFILE] environment
variable.  If this variable is not set, the name of the file will be
@i[/tmp/tkt@p(uid)], where @p(uid) is the UNIX user-id, represented in decimal.
@end[enumerate]

Now you use the @i[rlogin] client to try to access the machine @i[laughter].
@begin[example]
host% @b[rlogin  laughter]
@end[example]
@begin[enumerate]
The @i[rlogin] client checks your ticket file to see if you
have a ticket for @i[laughter]'s @i[rcmd] service (the rlogin program
uses the @i[rcmd] service name, mostly for historical reasons).
You don't, so @i[rlogin] uses the ticket file's @i[ticket-granting
ticket] to make a request to the master server's ticket-granting service.

This ticket-granting service receives the @i[rcmd-laughter] request
and looks in the master database for an @i[rcmd-laughter] entry.
If that entry exists, the ticket-granting service issues you a ticket
for that service.
That ticket is also cached in your ticket file.

The @i[rlogin] client now uses that ticket to request service from
the @i[laughter] @i[rlogin] service program.
The service program
lets you @i[rlogin] if the ticket is valid.
@end[enumerate]
@end[enumerate]

@chapter[Setting Up and Testing the Kerberos Server]

The procedure for setting up and testing a Kerberos server
is as follows:
@begin[enumerate]
Use the @i[kdb_init] command to create and initialize the master database.

Use the @i[kdb_edit] utility to add your username to the
master database.

Start the Kerberos server.

Use the @i[kinit] command to obtain a Kerberos ticket-granting ticket.

Use the @i[klist] command to verify that the @i[kinit] command
authenticated you successfully.
@end[enumerate]

@section[Creating and Initializing the Master Database]

Login to the Kerberos master server machine,
and use the @b[su] command to become root.
If you installed the Kerberos administration tools
with the @i[make install] command and the default pathnames,
they should be in the @i[/usr/etc] directory.
If you installed the tools in a different directory,
hopefully you know what it is.
From now on, we will refer to this directory as [ADMIN_DIR].

The @i[kdb_init] command creates and initializes the master database.
It asks you to enter the system's
realm name and the database's master password.
Do not forget this password.
If you do, the database becomes useless.
(Your realm name should be substituted for [REALMNAME] below.)

Use @i[kdb_init] as follows:
@tabset[3inches, +1.5inches]
@begin[example, rightmargin -10]
host# @b([ADMIN_DIR]/kdb_init)
Realm name (default XXX): @b([REALMNAME])@\@b[<--] @p[Enter your system's realm name.]
You will be prompted for the database Master Password.
It is important that you NOT FORGET this password.

Enter Kerberos master key: @\@b[<--] @p[Enter the master password.]
@comment(this needs to be re-fixed...:
Verifying, please re-enter
Enter Kerberos master key: @\@b[<--] @p[Re-enter it.]
)
@end[example]

@section[Storing the Master Password]

The @i[kstash] command ``stashes'' the master password in the file @i[/.k]
so that the Kerberos server can
be started automatically during an unattended reboot of the
master server.
Other administrative programs use this hidden password so that they
can access the master database without someone having to manually
provide the master password.
This command is an optional one;
if you'd rather enter the master password each time you
start the Kerberos server, don't use @i[kstash].

One the one hand, if you use @i[kstash], a copy of the master
key will reside
on disk which may not be acceptable; on the other hand, if you don't
use @i[kstash], the server cannot be started unless someone is around to
type the password in manually.

The command prompts you twice for the master password:
@begin[example]
@tabset[3inches]
host# @b([ADMIN_DIR]/kstash)

Enter Kerberos master key:@\@b[<--] @p[Enter the master password.]
Current Kerberos master key version is 1.

Master key entered   BEWARE!
@end[example]

A note about the Kerberos database master key:
if your master key is compromised and the database is obtained,
the security of your entire authentication system is compromised.
The master key must be a carefully kept secret.  If you keep backups,
you must guard all the master keys you use, in case someone has stolen
an old backup and wants to attack users' whose passwords haven't changed
since the backup was stolen.
This is why we provide the option not to store it on disk.

@section[Using @p(kdb_edit) to Add Users to the Master Database]

The @i[kdb_edit] program is used to add new users and services
to the master database, and to modify existing database information.
The program prompts you to enter a principal's @b[name] and @b[instance].

A principal name is typically a username or a service program's name.
An instance further qualifies the principal.
If the principal is a service,
the instance is used to specify the name of the machine on which that
service runs.
If the principal is a username that has general user privileges,
the instance is usually set to null.

The following example shows how to use @i[kdb_edit] to
add the user @i[wave] to the Kerberos database.
@begin[example, rightmargin -10]
@tabset[3inches, +1.5inches]
host# @b([ADMIN_DIR]/kdb_edit)

Opening database...

Enter Kerberos master key:
Verifying, please re-enter
Enter Kerberos master key:
Current Kerberos master key version is 1

Master key entered.  BEWARE!
Previous or default values are in [brackets] ,
enter return to leave the same, or new value.

Principal name: @b[wave]@\@b[<--] @p[Enter the username.]
Instance:@\@p[<-- Enter a null instance.]

<Not found>, Create [y] ? @b[y]@\@b[<--] @p[The user-instance does not exist.]
@\@p[      Enter y to create the user-instance.]
Principal: wave  Instance:  m_key_v: 1
New Password: @\@p[<-- Enter the user-instance's password.]
Verifying, please re-enter 
New Password:
Principal's new key version = 1
Expiration date (enter dd-mm-yy) [ 12/31/99 ] ?@\@b[<--] @p[Enter newlines]
Max ticket lifetime (*5 minutes) [ 255 ] ? @\@b[<--] @p[to get the]
Attributes [ 0 ] ? @\@\@b[<--] @p[default values.]
Edit O.K.

Principal name:@\@p[<-- Enter a newline to exit the program.]
@end[example]

Use the @i[kdb_edit] utility to add your username to the master database.

@section[Starting the Kerberos Server]

Change directories to the directory in which you have installed
the server program @i[kerberos]
(the default directory is @i[/usr/etc]),
and start the program as a background process:
@begin[example]
host# @b[./kerberos &]
@end[example]
If you have used the @i[kstash] command to store the master database password,
the server will start automatically.
If you did not use @i[kstash],
use the following command:
@begin[example]
host# @b[./kerberos -m]
@end[example]
The server will prompt you to enter the master password before actually
starting itself.

@section[Testing the Kerberos Server]

Exit the root account and use the @i[kinit] command obtain a Kerberos
ticket-granting ticket.
This command
creates your ticket file
and stores the ticket-granting ticket in it.

If you used the default @i[make install] command and directories to
install the Kerberos user utilities, @i[kinit] will be in the
@i[/usr/athena] directory. From now on, we'll refer to the Kerberos user
commands directory as [K_USER].

Use @i[kinit] as follows:
@begin[example]
@tabset[3 inches]
host% @b([K_USER]/kinit)
MIT Project Athena, (ariadne)
Kerberos Initialization
Kerberos name: @p[yourusername]@\@b[<--] @p[Enter your Kerberos username.]
Password: @\@b[<--] @p[Enter your Kerberos password.]
@end[example]

Use the @i[klist] program to list the contents of your ticket file.
@begin[example]
host% @b([K_USER]/klist)
@end[example]
The command should display something like the following:
@begin[example]
Ticket file:    /tmp/tkt5555
Principal:      yourusername@@REALMNAME

  Issued           Expires          Principal
May  6 10:15:23  May  6 18:15:23  krbtgt.REALMNAME@@REALMNAME
@end[example]

If you have any problems, you can examine the log file
@i[/kerberos/kerberos.log] on the Kerberos server machine to see if
there was some sort of error.

@chapter[Setting up and testing the Administration server]

The procedure for setting up and testing the Kerberos administration server
is as follows:
@begin[enumerate]
Use the @i[kdb_edit] utility to add your username with an administration
instance to the master database.

Edit the access control lists for the administration server

Start the Kerberos administration server.

Use the @i[kpasswd] command to change your password.

Use the @i[kadmin] command to add new entries to the database.

Use the @i[kinit] command to verify that the @i[kadmin] command
correctly added new entries to the database.
@end(enumerate)

@section[Adding an administration instance for the administrator]

Login to the Kerberos master server machine,
and use the @b[su] command to become root.
Use the @i[kdb_edit] program to create an entry for each administrator
with the instance ``@p(admin)''.
@begin[example]
@tabset[3inches, +1.5inches]
host# @b([ADMIN_DIR]/kdb_edit)

Opening database...

Enter Kerberos master key:
Verifying, please re-enter
Enter Kerberos master key:
Current Kerberos master key version is 1

Master key entered.  BEWARE!
Previous or default values are in [brackets] ,
enter return to leave the same, or new value.

Principal name: @b[wave]@\@b[<--] @p[Enter the username.]
Instance:@b[admin]@\@b[<--] @p[Enter ``admin''.]

<Not found>, Create [y] ? @b[y]@\@b[<--] @p[The user-instance does not exist.]
@\@p[      Enter y to create the user-instance.]
Principal: wave  Instance: admin m_key_v: 1
New Password: @\@p[<-- Enter the user-instance's password.]
Verifying, please re-enter 
New Password:
Principal's new key version = 1
Expiration date (enter dd-mm-yy) [ 12/31/99 ] ?@\@b[<--] @p[Enter newlines]
Max ticket lifetime (*5 minutes) [ 255 ] ? @\@b[<--] @p[to get the]
Attributes [ 0 ] ? @\@\@b[<--] @p[default values.]
Edit O.K.

Principal name:@\@p[<-- Enter a newline to exit the program.]
@end[example]

@section[The Access Control Lists]
The Kerberos administration server uses three access control lists to
determine who is authorized to make certain requests.  The access
control lists are stored on the master Kerberos server in the same
directory as the principal database, @i(/kerberos).  The access control
lists are simple ASCII text files, with each line specifying the name of
one principal who is allowed the particular function.  To allow several
people to perform the same function, put their principal names on
separate lines in the same file.

The first list, @i(/kerberos/admin_acl.mod), is a list of principals
which are authorized to change entries in the database.  To allow the
administrator `@b[wave]' to modify entries in the database for the realm
`@b[TIM.EDU]', you would put the following line into the file
@i(/kerberos/admin_acl.mod):
@begin(example)
wave.admin@@TIM.EDU
@end(example)

The second list, @i(/kerberos/admin_acl.get), is a list of principals
which are authorized to retrieve entries from the database.

The third list, @i(/kerberos/admin_acl.add), is a list of principals
which are authorized to add new entries to the database.

@section(Starting the administration server)
Change directories to the directory in which you have installed
the administration server program @i[kadmind]
(the default directory is @i[/usr/etc]),
and start the program as a background process:
@begin[example]
host# @b[./kadmind -n&]
@end[example]
If you have used the @i[kstash] command to store the master database password,
the server will start automatically.
If you did not use @i[kstash],
use the following command:
@begin[example]
host# @b[./kadmind]
@end[example]
The server will prompt you to enter the master password before actually
starting itself; after it starts, you should suspend it and put it in
the background (usually this is done by typing control-Z and then @b(bg)).

@section(Testing @p[kpasswd])

To test the administration server, you should try changing your password
with the @i[kpasswd] command, and you should try adding new users with
the @i[kadmin] command (both commands are installed into @i[/usr/athena]
by default).

Before testing, you should exit the root account.

To change your password, run the @i[kpasswd] command:
@begin(example)
@tabset[3inches, +1.5inches]
host% @b([K_USER]/kpasswd)
Old password for wave@@TIM.EDU:@\@b[<--]@p[Enter your password]
New Password for wave@@TIM.EDU:@\@b[<--]@p[Enter a new password]
Verifying, please re-enter New Password for wave@@TIM.EDU:
@\@b[<--]@p[Enter new password again]
Password changed.
@end(example)
Once you have changed your password, use the @i[kinit] program as shown
above to verify that the password was properly changed.

@section(Testing @p[kadmin])
You should also test the function of the @i[kadmin] program, by adding a
new user (here named ``@t[username]''):
@begin(example)
@tabset[3inches, +1.5inches]
host% @b([K_USER]/kadmin)
Welcome to the Kerberos Administration Program, version 2
Type "help" if you need it.
admin:  @b(ank username)@\@p[`ank' stands for Add New Key]
Admin password: @\@b[<--]@p[enter the password 
@\you chose above for wave.admin]
Password for username:@\@b[<--]@p[Enter the user's initial password]
Verifying, please re-enter Password for username:@\@b[<--]@p[enter it again]
username added to database.

admin:  quit
Cleaning up and exiting.
@end[example]

@section(Verifying with @p[kinit])
Once you've added a new user, you should test to make sure it was added
properly by using @i[kinit], and trying to get tickets for that user:

@begin[example]
@tabset[3inches, +1.5inches]
host% @b([K_USER]/kinit username)
MIT Project Athena (ariadne)
Kerberos Initialization for "username@@TIM.EDU"
Password: @b[<--]@p[Enter the user's password you used above]
host% @b([K_USER]/klist)
Ticket file:    /tmp/tkt_5509_spare1
Principal:      username@@TIM.MIT.EDU

  Issued           Expires          Principal
Nov 20 15:58:52  Nov 20 23:58:52  krbtgt.TIM.EDU@@TIM.EDU
@end[example]

If you have any problems, you can examine the log files
@i[/kerberos/kerberos.log] and @i[/kerberos/admin_server.syslog] on the
Kerberos server machine to see if there was some sort of error.

@chapter[Setting up and testing slave server(s)]

[Unfortunately, this chapter is not yet ready.  Sorry. -ed]

@chapter[A Sample Application]

This release of Kerberos comes with a sample application
server and a corresponding client program.
You will find this software in the [OBJ_DIR]@i[/appl/sample] directory.
The file @i[sample_client] contains the client program's executable
code, the file @i[sample_server] contains the server's executable.

The programs are rudimentary.
When they have been installed (the installation procedure is described
in detail later), they work as follows:
@begin[itemize]
The user starts @i[sample_client] and provides as arguments
to the command the name of the server machine and a checksum.
For instance:
@begin[example]
host% @b[sample_client]  @p[servername] @p[43]
@end[example]

@i[Sample_client] contacts the server machine and
authenticates the user to @i[sample_server].

@i[Sample_server] authenticates itself to @i[sample_client],
then returns a message to the client program.
This message contains diagnostic information
that includes the user's username, the Kerberos realm,
and the user's workstation address.

@i[Sample_client] displays the server's message on the user's
terminal screen.
@end[itemize]

@section[The Installation Process]

In general,
you use the following procedure to install a Kerberos-authenticated
server-client system.
@begin[enumerate]
Add the appropriate entry to the Kerberos database using @i[kdb_edit] or
@i[kadmin] (described below).

Create a @i[/etc/srvtab] file for the server machine.

Install the service program and the @i[/etc/srvtab]
file on the server machine.

Install the client program on the client machine.

Update the @i[/etc/services] file on the client and server machines.
@end[enumerate]

We will use the sample application as an example, although
the procedure used to install @i[sample_server] differs slightly
from the general case because the @i[sample_server]
takes requests via the
@i[inetd] program.
@i[Inetd] starts @i[sample_server] each time
a client process contacts the server machine.
@i[Sample_server] processes the request,
terminiates, then is restarted when @i[inetd] receives another
@i[sample_client] request.
When you install the program on the server,
you must add a @i[sample] entry to the server machine's
@i[/etc/inetd.conf] file.

The following description assumes that you are installing
@i[sample_server] on the machine @i[ariadne.tim.edu].
Here's the process, step by step:
@begin[enumerate]
Login as or @i[su] to root on the Kerberos server machine.
Use the @i[kdb_edit] or @i[kadmin] program to create an entry for
@i[sample] in the Kerberos database:
@begin[example, rightmargin -10]
@tabset[2.0inches, +.5inches]
host# @b([ADMIN_DIR]/kdb_edit)

Opening database...

Enter Kerberos master key:
Verifying, please re-enter
master key entered.  BEWARE!
Previous or default values are in [brackets] ,
enter return to leave the same, or new value.

Principal name: @b[sample]@\@b[<--] @p[Enter the principal name.]
Instance: @b[ariadne]@\@b[<--] @p[Instances cannot have periods in them.]

<Not found>, Create [y] ? @b[y]

Principal: sample_server  Instance: ariadne m_key_v: 1
New Password:@\@b[<--] @p[Enter ``RANDOM'' to get random password.]
Verifying, please re-enter 
New Password:@\@b[<--] @p[Enter ``RANDOM'' again.]
Random password [y] ? @b[y]

Principal's new key version = 1
Expiration date (enter dd-mm-yy) [ 12/31/99 ] ? 
Max ticket lifetime (*5 minutes) [ 255 ] ? 
Attributes [ 0 ] ? 
Edit O.K.

Principal name:@\@b[<--] @p[Enter newline to exit kdb_edit.]
@end[example]

Use the @i[ext_srvtab] program to create a @i[srvtab] file
for @i[sample_server]'s host machine:
@begin[example]
host# @b([ADMIN_DIR]/ext_srvtab  ariadne)

Enter Kerberos master key: 
Current Kerberos master key version is 1.

Generating 'ariadne-new-srvtab'....
@end[example]
Transfer the @i[ariadne-new-srvtab] file to @i[ariadne] and install it as
@i[/etc/srvtab].
Note that this file is equivalent to the service's password and should
be treated with care.
For example, it could be transferred by removable media, but should
not be sent over an open network in the clear.
Once installed, this file should be readable only by root.

Add the following line to the @i[/etc/services] file on
@i[ariadne], and on all machines that
will run the @i[sample_client] program:
@begin[example]
sample     906/tcp       # Kerberos sample app server
@end[example]

Add a line similar to the following line to the @i[/etc/inetd.conf]
file on @i[sample_server]'s machine:
@begin[example]
sample   stream   tcp   nowait   switched   root
    [PATH]/sample_server sample_server
@end[example]
where [PATH] should be substituted with
the path to the @i[sample_server] program.
(This @i[inetd.conf] information should be placed on one line.)
You should examine existing lines in @i[/etc/inetd.conf] and use the
same format used by other entries (e.g. for telnet).  Most systems do
not have a column for the `switched' keyword, and some do not have a
column for the username (usually `root', as above).

Restart @i[inetd] by sending the current @i[inetd] process
a hangup signal:
@begin[example]
host# @b[kill  -HUP   @p(process_id_number)]
@end[example]

The @i[sample_server] is now ready to take @i[sample_client] requests.
@end[enumerate]

@section[Testing the Sample Server]

Assume that you have installed @i[sample_server] on @i[ariadne].

Login to your workstation and use the @i[kinit] command to
obtain a Kerberos ticket-granting ticket:
@begin[example]
@tabset[3 inches]
host% @b([K_USER]/kinit)
MIT Project Athena, (your_workstation)
Kerberos Initialization
Kerberos name: @p[yourusername]@\@b[<--] @p[Enter your Kerberos username.]
Password: @\@b[<--] @p[Enter your Kerberos password.]
@end[example]

Now use the @i[sample_client] program as follows:
@begin[example]
host% @b([PATH]/sample_client  ariadne)
@end[example]
The command should display something like the following:
@begin[example]
The server says:
You are @p[yourusername].@@REALMNAME (local name @p[yourusername]),
 at address @p[yournetaddress], version VERSION9, cksum 997
@end[example]

@chapter[Service names and other services]

@section(rlogin, rsh, rcp, tftp, and others)

Many services use a common principal name for authentication purposes.
@i[rlogin], @i[rsh], @i[rcp], @i[tftp] and others use the principal name
``@t[rcmd]''.  For example, to set up the machine @i[ariadne] to support
Kerberos rlogin, it needs to have a service key for principal
``@t[rcmd]'', instance ``@t[ariadne]''.  You create this key in the same
way as shown above for the sample service.

After creating this key, you need to run the @i[ext_srvtab] program
again to generate a new srvtab file for ariadne.

@section(NFS modifications)

The NFS modifications distributed separately use the service name
``@t[rvdsrv]'' with the instance set to the machine name (as for the
sample server and the rlogin, rsh, rcp and tftp services).

@section(inetd.conf entries)
The following are the @i(/etc/inetd.conf) entries necessary to support
rlogin, encrypted rlogin, rsh, and rcp services on a server machine.  As
above, your @i(inetd.conf) may not support all the fields shown here.
@begin[example]
eklogin  stream   tcp   nowait   unswitched   root
    [PATH]/klogind   eklogind
kshell   stream   tcp   nowait   unswitched   root
    [PATH]/kshd   kshd
klogin   stream   tcp   nowait   unswitched   root
    [PATH]/klogind   klogind
@end[example]
