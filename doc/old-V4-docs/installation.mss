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
@b[Kerberos Installation Notes]
@b[DRAFT]
@end[center]
@end(group)
@blankspace[.5 inches]
@begin[group, size 16]
@begin(center)
Bill Bryant
Jennifer Steiner
John Kohl
@blankspace[1 line]
Project Athena, MIT
@blankspace[.5 inches]
@b[Initial Release, January 24, 1989]
@i[(plus later patches through patchlevel 7)]
@end[center]
@end(group)
@begin[group, size 10]
@end[group]
@blankspace[.75 inches]


The release consists of three parts.

The first part consists of the core Kerberos system, which was developed
at MIT and does not require additional licenses for us to distribute.
Included in this part are the Kerberos authentication server, the
Kerberos library, the
@i[ndbm]
database interface library, user programs, administration programs,
manual pages, some applications which use Kerberos for authentication,
and some utilities.

The second part is the Data Encryption Standard (DES) library, which we
are distributing only within the United States.

The third part contains Kerberos modifications to Sun's NFS, which we
distribute as ``context diffs'' to the Sun NFS source code.  Its
distribution is controlled to provide an accounting of who has retrieved
the patches, so that Project Athena can comply with its agreements with
Sun regarding distribution of these changes.

@newpage()
@chapter[Organization of the Source Directory]

The Kerberos building and installation process,
as described in this document,
builds the binaries and executables from the files contained in the Kerberos
source tree, and deposits them in a separate object tree.
This is intended to easily support several different build trees from a
single source tree (this is useful if you support several machine
architectures).
We suggest that you copy the Kerberos sources into a
@i[/mit/kerberos/src] directory,
and create as well a @i[/mit/kerberos/obj] directory in which
to hold the executables.
In the rest of this document, we'll refer to the Kerberos
source and object directories as [SOURCE_DIR]
and [OBJ_DIR], respectively.

Below is a brief overview of the organization of the complete
source directory.
More detailed descriptions follow.

@begin[description]

@b[admin]@\utilities for the Kerberos administrator

@b[appl]@\applications that use Kerberos

@b[appl/bsd]@\Berkeley's rsh/rlogin suite, using Kerberos

@b[appl/knetd]@\(old) software for inetd-like multiplexing of a single
TCP listening port

@b[appl/sample]@\sample application servers and clients

@b[appl/tftp]@\Trivial File Transfer Protocol, using Kerberos

@b[include]@\include files

@b[kadmin]@\remote administrative interface to the Kerberos master database

@b[kuser]@\assorted user programs

@b[lib]@\libraries for use with/by Kerberos

@b[lib/acl]@\Access Control List library

@b[lib/des]@\Data Encryption Standard library (US only)

@b[lib/kadm]@\administrative interface library

@b[lib/kdb]@\Kerberos server library interface to @i[ndbm]

@b[lib/knet]@\(old) library for use with @b[knetd]

@b[lib/krb]@\Kerberos library

@b[man]@\manual pages

@b[prototypes]@\sample configuration files

@b[server]@\the authentication server

@b[slave]@\Kerberos slave database propagation software

@b[tools]@\shell scripts for maintaining the source tree

@b[util]@\utilities

@b[util/imake]@\Imakefile-to-Makefile ``compilation'' tool

@b[util/ss]@\Sub-system library (for command line subsystems)

@b[util/et]@\Error-table library (for independent, unique error codes)

@b[util/makedepend]@\Makefile dependency generator tool

@end[description]

@section[The @p(admin) Directory]

This directory contains source for
the Kerberos master database administration tools.
@begin[description]
@b[kdb_init]@\This program creates and initializes the
Kerberos master database.
It prompts for a Kerberos realmname, and the Kerberos master password.

@b[kstash]@\This program ``stashes'' the master password in the file
@i[/.k] so that the master server machine can restart the Kerberos
server automatically after an unattended reboot.
The hidden password is also available to administrative programs
that have been set to run automatically.

@b[kdb_edit]@\This program is a low-level tool for editing
the master database.

@b[kdb_destroy]@\This program deletes the master database.

@b[kdb_util]@\This program can be used to dump the master database
into an ascii file, and can also be used to load the ascii file
into the master database.

@b[ext_srvtab]@\This program extracts information from the master
database and creates a host-dependent @i[srvtab] file.
This file contains the Kerberos keys for the host's
``Kerberized'' services.
These services look up their keys in the @i[srvtab] file
for use in the authentication process.
@end[description]

@section[The @p(kuser) Directory]

This directory contains the source code for several user-oriented
programs.
@begin[description]
@b[kinit]@\This program prompts users for their usernames and
Kerberos passwords, then furnishes them with Kerberos ticket-granting
tickets.

@b[kdestroy]@\This program destroys any active tickets.
Users should use @i[kdestroy] before they log off their workstations.

@b[klist]@\This program lists a user's active tickets.

@b[ksrvtgt]@\This retrieves a ticket-granting ticket with a life time
of five minutes, using a server's secret key in lieu of a password.  It
is primarily for use in shell scripts and other batch facilities.

@b[ksu]@\Substitute user id, using Kerberos to mediate attempts to
change to ``root''.
@end[description]

@section[The @p(appl) Directory]

If your site has the appropriate BSD license,
your Kerberos release provides certain Unix utilities
The Berkeley programs that have been modified to use Kerberos
authentication are found in the @i[appl/bsd] directory.
They include @i[login], @i[rlogin], @i[rsh], and @i[rcp], as well as the
associated daemon programs @i[kshd] and @i[klogind].
The @i[login] program obtains ticket-granting tickets for users
upon login; the other utilities provide authenticated
Unix network services.

The @i[appl] directory also contains samples Kerberos application
client and server programs, an authenticated @i[tftp] program,
@i[knetd], an authenticated inet daemon.

@section[The @p(server) Directory]

The @i[server] directory contains the Kerberos KDC server, called
@i[kerberos].
This program manages read-only requests made to the
master database,
distributing tickets and encryption keys to clients requesting
authentication service.

@section[The @p(kadmin) Directory]

The @i[kadmin] directory contains the Kerberos administration server and
associated client programs.
The server accepts network requests from the
user program @i[kpasswd] (used to change a user's password), the
Kerberos administration program @i(kadmin), and the srvtab utility
program @i[ksrvutil].
The administration server can make modifications to the master database.

@section[The @p(include) Directory]

This directory contains the @i[include] files needed to
build the Kerberos system.

@section[The @p(lib) Directory]

The @i[lib] directory has six subdirectories:
@i[acl], @i[des], @i[kadm], @i[kdb], @i[knet], and @i[krb].
The @i[des] directory contains source for the DES encryption library.
The @i[kadm] directory contains source for the Kerberos administration
server utility library.
The @i[kdb] directory contains source for the Kerberos database
routine library.
The @i[knet] directory contains source for a library used by clients of
the @i[knetd] server.
The @i[krb] directory contains source for the @i[libkrb.a]
library.
This library contains routines that are used by the Kerberos server program,
and by applications programs that require authentication service.

@section[The @p(man) Directory]

This directory contains manual pages for Kerberos programs and
library routines.

@section[The @p(prototypes) Directory]

This directory contains prototype
@i[/etc/services] and @i[/etc/krb.conf] files.
New entries must be added to the @i[/etc/services] file for
the Kerberos server, and possibly for Kerberized applications
(@i[services.append] contains the entries used by the Athena-provided
servers & applications, and is suitable for appending to your existing
@i[/etc/services] file.).
The @i[/etc/krb.conf] file defines the local Kerberos realm
for its host and lists Kerberos servers for given realms.
The @i[/etc/krb.realms] file defines exceptions for mapping machine
names to Kerberos realms.

@section[The @p(tools) Directory]

This directory contains
a makefile to set up a directory tree
for building the software in, and
a shell script to format code in the
style we use.


@section[The @p(util) Directory]

This directory contains several utility programs and libraries.
Included are Larry Wall's @i[patch] program, a @i[make] pre-processor
program called
@i[imake], and a program for generating Makefile dependencies,
@i[makedepend], as well as the Sub-system library and
utilities (@i[ss]), and the Error table library and utilities (@i[et]).

@chapter[Preparing for Installation]

This document assumes that you will build the system
on the machine on which you plan to install
the Kerberos master server and its database.
You'll need about 10 megabytes for source and executables.

By default, there must be
a @i[/kerberos] directory on the master server machine
in which to store the Kerberos
database files.
If the master server machine does not have room on its root partition
for these files,
create a @i[/kerberos] symbolic link to another file system.

@chapter[Preparing for the Build]

Before you build the system,
you have to choose a @b[realm name],
the name that specifies the system's administrative domain.
Project Athena uses the internet domain name ATHENA.MIT.EDU
to specify its Kerberos realm name.
We recommend using a name of this form.
@b[NOTE:] the realm-name is case sensitive; by convention, we suggest
that you use your internet domain name, in capital letters.

Edit the [SOURCE_DIR]/@i[include/krb.h] file and look for the following
lines of code:
@begin[example]
/*
 * Kerberos specific definitions
 *
 * KRBLOG is the log file for the kerberos master server.
 * KRB_CONF is the configuration file where different host
 * machines running master and slave servers can be found.
 * KRB_MASTER is the name of the machine with the master
 * database.  The admin_server runs on this machine, and all
 * changes to the db (as opposed to read-only requests, which
 * can go to slaves) must go to it.
 * KRB_HOST is the default machine when looking for a kerberos
 * slave server.  Other possibilities are in the KRB_CONF file.
 * KRB_REALM is the name of the realm.
 */

#ifdef notdef
this is server-only, does not belong here;
#define       KRBLOG          "/kerberos/kerberos.log"
are these used anyplace '?';
#define               VX_KRB_HSTFILE  "/etc/krbhst"
#define               PC_KRB_HSTFILE  "\\kerberos\\krbhst"
#endif

#define               KRB_CONF        "/etc/krb.conf"
#define               KRB_RLM_TRANS   "/etc/krb.realms"
#define               KRB_MASTER      "kerberos"
#define               KRB_HOST         KRB_MASTER
#define               KRB_REALM       "ATHENA.MIT.EDU"
@end[example]
Edit the last line as follows:
@begin[enumerate]
Change the KRB_REALM definition so that it specifies the realm name
you have chosen for your Kerberos system.  This is a default which is
usually overridden by a configuration file on each machine; however, if
that config file is absent, many programs will use this "built-in" realm
name.
@end[enumerate]

@section[The @p(/etc/krb.conf) File]

Create a @i[/etc/krb.conf] file using the following format:
@begin[example]
@p[realm_name]
@p[realm_name]  @p[master_server_name] admin server
@end[example]
where @i[realm_name] specifies the system's realm name,
and @i[master_server_name] specifies the machine name on
which you will run the master server.  The words 'admin server' must
appear next to the name of the server on which you intend to run the
administration server (which must be a machine with access to the database).

For example,
if your realm name is @i[tim.edu] and your master server's name is
@i[kerberos.tim.edu], the file should have these contents:
@begin[example]
tim.edu
tim.edu  kerberos.tim.edu admin server
@end[example]

See the [SOURCE_DIR]/@i[prototypes/etc.krb.conf] file for an
example @i[/etc/krb.conf] file.  That file has examples of how to
provide backup servers for a given realm (additional lines with the same
leading realm name) and how to designate servers for remote realms.

@section[The @p(/etc/krb.realms) File]

In many situations, the default realm in which a host operates will be
identical to the domain portion its Internet domain name.

If this is not the case, you will need to establish a translation from
host name or domain name to realm name.  This is accomplished with the
@i(/etc/krb.realms) file.

Each line of the translation file specifies either a hostname or domain
name, and its associated realm:
@begin[example]
.domain.name kerberos.realm1
host.name kerberos.realm2
@end[example]
For example, to map all hosts in the domain LSC.TIM.EDU to KRB.REALM1
but the host FILMS.LSC.TIM.EDU to KRB.REALM2 your file would read:
@begin[example]
.LSC.TIM.EDU KRB.REALM1
FILMS.LSC.TIM.EDU KRB.REALM2
@end[example]
If a particular host matches both a domain and a host entry, the host
entry takes precedence.

@chapter[Building the Software]

Before you build the software
read the @b[README] file in [SOURCE_DIR].
What follows is a more detailed description of the instructions
listed in README.
@begin[enumerate]
Create an [OBJ_DIR] directory to hold the tree of Kerberos object files you
are about to build, for example,
@i[/mit/kerberos/obj].

Change directory to [OBJ_DIR].
The following command creates directories under [OBJ_DIR]
and installs Makefiles for the final build.
@begin[example, rightmargin -7]
host% @b(make  -f  [SOURCE_DIR]/tools/makeconfig  SRCDIR=[SOURCE_DIR])
@end[example]



Change directory to util/imake.includes.  Read through config.Imakefile,
turning on appropriate flags for your installation.  Change SRCTOP so
that it is set to the top level of your source directory.

Check that your machine type has a definition in include/osconf.h &
related files in the source tree (if it doesn't, then you may need to
create your own; if you get successful results, please post to
kerberos@@athena.mit.edu)

Change directory to [OBJ_DIR].  The next command generates new Makefiles
based on the configuration you selected in config.Imakefile, then adds
dependency information to the Makefiles, and finally builds the system:
@begin[example, rightmargin -7]
host% @b(make  world)
@end[example]
This command takes a while to complete; you may wish to redirect the
output onto a file and put the job in the background:
@begin[example, rightmargin -7]
host% @b(make  world >&WORLDLOG_891201 &)
@end[example]
If you need to rebuild the Kerberos programs and libraries after making
a change, you can usually just type:
@begin[example, rightmargin -7]
host% @b(make  all)
@end[example]
However, if you changed the configuration in config.Imakefile or modified
the Imakefiles or Makefiles, you should run @i[make world] to re-build
all the Makefiles and dependency lists.
@end(enumerate)

@section[Testing the DES Library]

Use the @i[verify] command to test the DES library
implementation:
@begin[example]
host% @b([OBJ_DIR]/lib/des/verify)
@end[example]
The command should display the following:
@begin[example, rightmargin -10]
Examples per FIPS publication 81, keys ivs and cipher
in hex.  These are the correct answers, see below for
the actual answers.

Examples per Davies and Price.

EXAMPLE ECB     key = 08192a3b4c5d6e7f
        clear = 0
        cipher = 25 dd ac 3e 96 17 64 67
ACTUAL ECB
        clear ""
        cipher  = (low to high bytes)
                25 dd ac 3e 96 17 64 67 

EXAMPLE ECB     key = 0123456789abcdef
        clear = "Now is the time for all "
        cipher = 3f a4 0e 8a 98 4d 48 15 ...
ACTUAL ECB
        clear "Now is the time for all "
        cipher  = (low to high bytes)
                3f a4 0e 8a 98 4d 48 15 

EXAMPLE CBC     key = 0123456789abcdef  iv = 1234567890abcdef
        clear = "Now is the time for all "
        cipher =        e5 c7 cd de 87 2b f2 7c
                        43 e9 34 00 8c 38 9c 0f
                        68 37 88 49 9a 7c 05 f6
ACTUAL CBC
        clear "Now is the time for all "
        ciphertext = (low to high bytes)
                e5 c7 cd de 87 2b f2 7c 
                43 e9 34 00 8c 38 9c 0f 
                68 37 88 49 9a 7c 05 f6 
                00 00 00 00 00 00 00 00 
                00 00 00 00 00 00 00 00 
                00 00 00 00 00 00 00 00 
                00 00 00 00 00 00 00 00 
                00 00 00 00 00 00 00 00 
        decrypted clear_text = "Now is the time for all "
EXAMPLE CBC checksum    key =  0123456789abcdef iv =  1234567890abcdef
        clear =         "7654321 Now is the time for "
        checksum        58 d2 e7 7e 86 06 27 33  or some part thereof
ACTUAL CBC checksum
                encrypted cksum = (low to high bytes)
                58 d2 e7 7e 86 06 27 33
@end[example]

If the @i[verify] command fails to display this information as specified
above, the implementation of DES for your hardware needs to
be adjusted.
Your Kerberos system cannot work properly if your DES library
fails this test.

When you have finished building the software,
you will find the executables in the object tree as follows:
@begin[description]
@b([OBJ_DIR]/admin)@\@i[ext_srvtab], @i[kdb_destroy],
@i[kdb_edit], @i[kdb_init], @i[kdb_util], and @i[kstash].

@b([OBJ_DIR]/kuser)@\@i[kdestroy], @i[kinit], @i[klist], @i[ksrvtgt],
and @i[ksu].

@b([OBJ_DIR]/server)@\@i[kerberos].

@b([OBJ_DIR]/appl/bsd)@\@i[klogind], @i[kshd], @i[login.krb], @i[rcp],
@i[rlogin], and @i[rsh].

@b([OBJ_DIR]/appl/knetd)@\@i[knetd].

@b([OBJ_DIR]/appl/sample)@\@i[sample_server], @i[sample_client],
@i[simple_server], and @i[simple_client].

@b([OBJ_DIR]/appl/tftp)@\@i[tcom], @i[tftpd], and @i[tftp].

@b([OBJ_DIR]/slave)@\@i[kprop] and @i[kpropd].
@end[description]

@chapter[Installing the Software]

To install the software, issue the @i[make install] command from
the [OBJ_DIR] (you need to be a privileged user in order to
properly install the programs).
Programs can either be installed in default directories, or under
a given root directory, as described below.

@section[The ``Standard'' Places]

If you use the @i[make] command as follows:
@begin[example]
host# @b(make  install)
@end[example]
the installation process will try to install the various parts of the
system in ``standard'' directories.
This process creates the ``standard'' directories as needed.

The standard installation process copies things as follows:
@begin[itemize]
The @i[include] files @i[krb.h], @i[des.h], @i[mit-copyright.h],
@i[kadm.h] and @i[kadm_err.h] get copied to the
@i[/usr/include] directory.

The Kerberos libraries @i[libdes.a], @i[libkrb.a], @i[libkdb.a],
@i[libkadm.a], @i[libknet.a], and @i[libacl.a] get copied
to the @i[/usr/athena/lib] (or wherever you pointed LIBDIR in
config.Imakefile) directory.

The Kerberos master database utilities @i[kdb_init], @i[kdb_destroy],
@i[kdb_edit], @i[kdb_util], @i[kstash], and @i[ext_srvtab] get copied to
the @i[/usr/etc] (DAEMDIR) directory.

The Kerberos user utilities @i[kinit], @i[kdestroy], @i[klist],
@i[ksrvtgt] and @i[ksu] get copied to the @i[/usr/athena] (PROGDIR)
directory.

The modified Berkeley utilities @i[rsh], @i[rlogin] get copied to the
@i[/usr/ucb] (UCBDIR) directory; @i[rcp] gets copied to the @i[/bin]
(SLASHBINDIR) directory; and @i[rlogind], @i[rshd], and @i[login.krb]
get copied to the @i[/usr/etc] (DAEMDIR) directory.  The old copies of
the user programs are renamed @i(rsh.ucb), @i(rlogin.ucb) and
@i(rcp.ucb), respectively.  The Kerberos versions of these programs are
designed to fall back and execute the original versions if something
prevents the Kerberos versions from succeeding.

The Kerberos version of @i[tftp] and @i[tcom] get copied to the
@i[/usr/athena] (PROGDIR) directory; @i[tftpd] gets copied to the
@i[/etc] (ETCDIR) directory.  @i[tftp] and @i[tftpd] are installed
set-uid to an unprivileged user (user id of DEF_UID).

The @i[knetd] daemon gets copied to the @i[/usr/etc] (DAEMDIR) directory.

The Kerberos server @i[kerberos], the slave propagation software
@i[kprop] and @i[kpropd], and the administration server @i[kadmind] get
copied to the @i[/usr/etc] (SVRDIR, SVRDIR, and DAEMDIR) directory.

The remote administration tools @i[kpasswd], @i[ksrvutil] and @i[kadmin]
get copied to the @i[/usr/athena] (PROGDIR) directory.

The Kerberos manual pages get installed in the appropriate
@i[/usr/man] directories.  Don't forget to run @i[makewhatis]
after installing the manual pages.

@end[itemize]

@section[``Non-Standard'' Installation]

If you'd rather install the software in a different location,
you can use the @i[make] command as follows,
where [DEST_DIR] specifies an alternate destination directory
which will be used as the root for the installed programs, i.e. programs
that would normally be installed in /usr/athena would be installed in
[DEST_DIR]/usr/athena.
@begin[example]
host# @b(make  install  DESTDIR=[DEST_DIR])
@end[example]

@chapter[Conclusion]

Now that you have built and installed your Kerberos system,
use the accompanying @u[Kerberos Operation Notes]
to create a Kerberos Master database, install authenticated services,
and start the Kerberos server.

@chapter [Acknowledgements]

We'd like to thank Henry Mensch and Jon Rochlis for helping us debug
this document.
