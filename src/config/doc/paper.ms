.\" macros ripped off from Rosenthal and Lemke's paper
.\"	refer -e -n -p vis.refs -s vis.nr | eqn | pic | psroff -ms
.\.EQ
.\delim $$
.\.EN
.ds CH
.de Ip
.IP \(bu 3
..
.de Qp
.nr PS -2
.nr VS -2
.QP
..
.de Qe
.nr PS +2
.nr VS +2
..
.de RQ
.br
.di
.nr NF 0
.if \\n(dn-\\n(.t .nr NF 1
.if \\n(TC .nr NF 1
.if !\\n(NF .if \\n(TB .nr TB 0
.nf
.rs
.nr TC 5
.in 0
.ls 1
.if !\\n(TB \{\
.	ev
.	br
.	ev 2
.	KK
.\}
.ls
.ce 0
.if !\\n(TB .rm KK
.if \\n(TB .da KJ
.if \\n(TB \!.KD \\n(dn
.if \\n(TB .KK
.if \\n(TB .di
.nr TC \\n(TB
.if \\n(KN .fi
.in
.ev
..
.\"	These macros should select a typewriter font if you have one.
.de LS
.LP
.KS
.LD
.ft L
.ta .6i 1.2i 1.8i 2.4i 3i 3.6i 4.2i
..
.de LE
.ft P
.DE
.KE
..
.de Ls
.nr PS -4
.nr VS -6
.LS
..
.de Le
.LE
.nr PS +4
.nr VS +6
.LP
..
.nr PO 1.25i
.TL
Configuration Management in the X Window System
.AU
Jim Fulton
.AI
X Consortium
MIT Laboratory for Computer Science
545 Technology Square
Cambridge, MA  02139
.AB
The X Window System\(dg has become an industry standard for network window
technology in part because of the
portability of the sample implementation from MIT.  Although many systems are
designed to reuse source code across different platforms, X is 
unusual in its
portability across software build environments.  This paper describes several
mechanisms used in the MIT release of the X Window System to obtain such
flexibility, and summarizes some of the lessons learned in trying to support
X on a number of different platforms.
.AE
.NH 1
Introduction
.LP
The X Window System\f(d is a portable, network transparent window system 
originally developed at MIT.  It is intended for use on raster display
devices ranging from simple monochrome frame buffers to deep,
true color graphics processors.  Because of its client/server architecture,
the non-proprietary nature of its background, and the portability of the
sample implementation from MIT, the X Window System has rapidly grown to 
become an industry standard.  This portability is the result of several
factors: a system architecture that isolates operating system and
device-specifics at several levels; a slow, but machine-independent, graphics
package that may be used for an initial port and to handle cases that
the underlying graphics hardware does not support; and the use of a few,
higher-level tools for managing the build process itself.
.FS
\(dg X Window System is a trademark of MIT; DECnet is a trademark of 
Digital Equipment Corporation; UNIX is a registered trademark of AT&T.
.sp
Copyright \(co\ 1989 by the Massachusetts Institute of Technology.
.sp
Permission to use, copy, modify, and distribute this
document for any purpose and without
fee is hereby granted, provided that the above copyright
notice appear in all copies and that both that copyright
notice and this permission notice appear in supporting
documentation, and that the name of M.I.T. not be used in
advertising or publicity pertaining to distribution of the
software without specific, written prior permission.
M.I.T. makes no representations about the suitability of
the software described herein for any purpose.  It is provided "as is"
without express or implied warranty.
.FE
.NH 2
Summary of X Window System Architecture
.LP
The X Window System is the result of a combined effort between MIT Project 
Athena and the MIT Laboratory for Computer Science.  Since its inception 
in 1984, X has been redesigned three times, culminating in Version 11 which
has since become an industry standard (see [Scheifler 88] for a more detailed
history).  X uses the client/server model of 
limiting interactions with the physical display hardware to a single program
(the \fIserver\fP) and providing a way for applications (the \fIclients\fP)
to send messages (known as \fIrequests\fP) to the server to ask it to perform
graphics operations on the client's behalf.  These messages are sent along
a reliable, sequenced, duplex byte stream using whatever underlying transport
mechanisms the operating system provides.  If connections 
using network virtual circuits (such as TCP/IP or DECnet) are supported,
clients may be run
on any remote machine (including ones of differing architectures) while still
displaying on the local server.
.LP
The details of how the client establishes and maintains connections with the
server are typically hidden in a subroutine package (known as a \fIlanguage
binding\fP) which provides a function call interface to the X protocol.  Higher
level toolkits and user interface management systems are then built on top of 
the binding library, as shown in Figure 1 for the C programming language.
Since only the underlying
operating system networking interface of the binding (shown in \fIitalics\fP)
need be changed when 
porting to a new platform, well-written applications can simply be recompiled.
.sp 1
.DS C
.TS
box tab (/) ;
cB    s    s    s 
_     lB   lB   lB 
cBe | le   le   le
_     s    lB   lB
cB    s |  lB   lB
_     s    s    lB
cB    s    s |  lB
_     s    s    s
cB    s    s    s
_     lB   lB   _
cI    s    s    s .
application///
///
UIMS///
///
widgets///
///
toolkit///
///
Xlib///
///
os
.TE
.sp 1
\fBFigure 1:\fP  architecture of a typical C language client program
.DE
.sp 1
.LP
The server takes care of clipping of graphics output and routing keyboard and
pointer input
to the appropriate applications.  Unlike many previous window systems, 
moving and resizing of windows are handled outside the server
by special X applications called
\fIwindow managers\fP.  Different user interface policies can be selected 
simply by running a different window manager.
.LP
The MIT sample server can be divided into three sections: a device-independent
layer called \fIdiX\fP for managing the various shared resources (windows, 
pixmaps, colormaps, fonts, cursors, etc.), an operating system layer called
\fIos\fP for performing machine-specific operations (managing
connections to clients, dealing with timers, reading color and font name 
databases, and memory allocation), and a device-specific
layer called \fIddX\fP for drawing on the display and getting input from the 
keyboard and pointer.  Only the \fIos\fP and \fIddX\fP portions of the server
need to be changed when porting X to a new device.
.LP
Although this is still
a substantial amount of work, a collection of pixel-oriented drawing packages
that only require device-specific routines (refered to as \fIspans\fP) 
to read and write rows of pixels are provided
to allow initial ports of X to be done in a very short time.  A server
developer can then concentrate on replacing those operations that can be
implemented more efficiently by the hardware.  Figure 2 shows the relative
layering of the various packages within the sample server from MIT.  The
\fImi\fP library provides highly portable, machine-independent routines that
may be used on a wide variety of displays.  The \fImfb\fP and \fIcfb\fP 
libraries contain versions of the graphics routines for monochrome and
color frame buffers, respectively.  Finally, the \fIsnf\fP library can be
used to read fonts stored in Server Natural Format.  Typically, only the 
sections printed in \fIitalics\fP need be changed when moving to a new 
platform.
.sp 1
.DS C
.TS
allbox tab (/) ;
cB s s s s
cI s s s cI
cB cB cB cB cB
cI s s s cB .
diX
ddX/os
mi/mfb/cfb/snf/\^
spans/\^
.TE
.sp 1
\fBFigure 2:\fP  architecture of the MIT sample server
.DE
.sp 1
.LP
By splitting out the device-specific code (by separating clients from servers
and \fIdiX\fP from \fIddX\fP) and then providing portable utility libraries 
(\fImi\fP, \fImfb\fP, \fIcfb\fP, and \fIcfb\fP) that may be used to 
implement the non-portable portions
of the system, much of the code can be reused across many platforms, ranging
from personal computers to supercomputers.
.NH 1
Configuring the Software Build Process
.LP
In practice, porting X to a new platform typically requires adding support 
in the operating system-specific networking routines and mixing together
pieces of machine-independent and device-specific code to access the
input and output hardware.  Although this approach is very portable, it
increases the complexity of the build process as different implementations 
require different subsets.  One solution is to litter the 
source code with machine-specific compiler directives controlling which 
modules areas get built on a given platform.  However, this rapidly leads to 
sources that are hard to understand and even harder to maintain.
.LP
A more serious problem with this approach is that it requires 
configuration information to be replicated in almost every module.  In
addition to being highly prone to error, modifying or adding a new 
configuration becomes extremely difficult.  In contrast, collecting the 
various options and parameters in a single location makes it possible for
someone to reconfigure the system without having to 
understand how all of the modules fit together.
.LP
Although sophisticated software management systems are very useful, they 
tend to be found only on specific platforms.  Since the configuration system 
must be working before a build can begin, the MIT releases try to adhere to
the following principles:
.RS .5in
.Ip
Use existing tools to do the build (e.g. \fImake\fP) where possible; writing
complicated new tools simply adds to the amount of software that has to be
bootstrapped.
.Ip
Keep it simple.  Every platform has a different set of extensions and bugs.
Plan for the least common denominator by only using 
the core features of known tools; don't rely on vendor-specific features.
.Ip
Providing sample implementations of simple tools that are not available on
all platforms (e.g. a BSD-compatible \fIinstall\fP script for System V) is
very useful.
.Ip
Machine-dependencies should be centralized to make reconfiguration easy.
.Ip
Site-wide options (e.g. default parameters such as directory names, 
file permissions, and enabling particular features) should be stored in
only one location.
.Ip
Rebuilding within the source tree without losing any of the configuration
information must be simple.
.Ip
It should be possible to configure external software without requiring 
access to the source tree.
.RE
.LP
One approach is to add certain programming constructs (particularly 
conditionals and iterators) to the utility used to actually build the 
software (usually \fImake\fP; see [Lord 88]).  Although this an attractive
solution, limits on time and personnel made implementing and maintaining
such a system impractical for X.
.LP
The MIT releases of X employ a less ambitious approach that uses existing tools
(particularly \fImake\fP and \fIcpp\fP).  \fIMakefiles\fP
are generated automatically by a small,
very simple program named \fIimake\fP (written by Todd Brunhoff of Tektronix)
that combines a template listing variables and rules
that are common to all 
\fIMakefiles\fP, a machine- and a site-specific configuration file,
a set of rule functions written as \fIcpp\fP macros,
and simple specifications of targets and sources called \fIImakefiles\fP.
Since the descriptions of the inputs and outputs of the build are separated
from the commands that implement them, machine dependencies such as the
following can be controlled from a single location:
.RS .5in
.Ip
Some versions of \fImake\fP require that the variable SHELL to be set to the
name of the shell that should be used to execute \fImake\fP commands.
.Ip
The names of various special \fImake\fP variables (e.g. MFLAGS vs. MAKEFLAGS) 
differ between versions.
.Ip
Special directives to control interaction with source code maintenance systems
are required by some versions of \fImake\fP.
.Ip
Rules for building targets (e.g. \fIranlib\fP,
lint options, executable shell scripts, selecting alternate compilers)
differ among platforms.
.Ip
Some systems require special compiler options (e.g. increased internal
table sizes, floating point options) for even simple programs.
.Ip
Some systems require extra libraries when linking programs.
.Ip
Not all systems need to compile all sources.
.Ip
Configuration parameters may need to be passed to some (such as -DDNETCONN
to compile in DECnet support) or all (such as -DSYSV to select System V code)
programs as preprocessor symbols.
.Ip
Almost all systems organize header files differently, making
static dependencies in \fIMakefiles\fP impossible to generate.
.RE
.LP
By using the C preprocessor, \fIimake\fP provides a familiar set of interfaces
to conditionals, macros, and symbolic constants.  Common operations, such as
compiling programs, creating libraries,	creating shell scripts, and
managing subdirectories, can be described in a concise, simple way.  
Figure 3 shows the \fIImakefile\fP used to build a manual page browser
named \fIxman\fP (written by Chris Peterson program of the MIT X Consortium,
based on an implementation for X10 by Barry Shein):
.sp 1
.KF
.RS 1in
.nf
.ft L
DEFINES =  -DHELPFILE=\e"$(LIBDIR)$(PATHSEP)xman.help\e"
LOCAL_LIBRARIES =  $(XAWLIB) $(XMULIB) $(XTOOLLIB) $(XLIB)
SRCS =  ScrollByL.c handler.c man.c pages.c buttons.c help.c menu.c search.c \e
        globals.c main.c misc.c tkfuncs.c
OBJS =  ScrollByL.o handler.o man.o pages.o buttons.o help.o menu.o search.o \e
        globals.o main.o misc.o tkfuncs.o
INCLUDES =  -I$(TOOLKITSRC) -I$(TOP)

ComplexProgramTarget (xman)
InstallNonExec (xman.help, $(LIBDIR))

.ft P
.fi
.RE
.DS C
.sp 1
\fBFigure 3:\fP  \fIImakefile\fP used by a typical client program
.DE
.KE
.sp 1
.LP
This application requires the name of the directory in which its help file is
installed (which is a configuration parameter), several libraries, and 
various X header files.  The macro
\fIComplexProgramTarget\fP generates the appropriate rules to build
the program, install it, compute dependencies, and remove old versions of
the program and its object files.  The \fIInstallNonExec\fP macro generates
rules to install \fIxman\fP's help file with appropriate permissions.
.NH 1
Generating Makefiles
.LP
Although \fIimake\fP is a fairly powerful tool, it is a very simple program.
All of the real work is performed by the template, rule, and configuration
files.  The version currently used at MIT (which differs somewhat from the 
version supplied in the last release of X)
uses symbolic constants for all configuration 
parameters so that they may be overridden or used by other parameters.
General build issues (such as the command to execute to run the compiler) 
are isolated from X issues (such as where should application default files be
installed) by splitting the template as shown in Figure 4.
.KF
.sp 1
.DS C
.TS
box tab (%) ;
l s s
l   _   l
l | l | l
l   _   l
l   _   l
l | l | l
l   _   l
l   _   l
l | l | l
l   _   l
l   _   l
l | l | l
l   _   l
l   _   l
l | l | l
l   _   l .
Imake.tmpl
 %
%#include "\fImachine\fP.cf"%
 %
 %
%#include "site.def"%
 %
 %
%#include "Project.tmpl"%
 %
 %
%#include "Imake.rules"%
 %
 %
%#include "./Imakefile"%
 %
.TE
.sp 1
\fBFigure 4:\fP  structure of \fIimake\fP template used by X
.DE
.sp 1
.KE
.LP
This template instructs \fIimake\fP to perform the following steps when
creating a \fIMakefile\fP:
.RS .5in
.IP 1.
Using conditionals, \fIImake.tmpl\fP determines the machine for which the
build is being configured and includes a machine-specific configuration file 
(usually named \fImachine\fP.cf).  Using the C preprocessor to define various
symbols, this configuration file sets the major and minor version 
numbers of the operating system, the names of any servers 
to build, and any special programs (such as alternate compilers)
or options (usually to increase internal table sizes) that
need to be used during the build.  Defaults are provided for
all parameters, so .cf files need only describe how this particular
platform differs from ``generic'' UNIX System V or BSD UNIX.
Unlike previous versions of the \fIimake\fP configuration files,
when new parameters are added, only the systems which are
effected by them need to be updated.
.IP 2.
Next, a site-specific file (named \fIsite.def\fP) is included so
that parameters from the .cf files may be overridden or
defaults for other options provided.  This is typically used
by a site administrator to set the names of the various
directories into which the software should be installed.
Again, all of the standard \fIcpp\fP constructs may be used.
.IP 3.
A project-specific file (named \fIProject.tmpl\fP) is 
included to set various parameters used by the particular
software package being configured.  By separating the 
project parameters (such as directories, options, etc.)
from build parameters (such as compilers, utilities, etc.),
the master template and the .cf files can be shared among various development
efforts.  
.IP 4.
A file containing the set of \fIcpp\fP rules (named \fIImake.rules\fP)
is included.  This is where the various macro functions used
in the master template and the per-directory description
files (named \fIImakefile\fP) are defined.  These rules typically
make very heavy use of the \fImake\fP variables defined in
\fIImake.tmpl\fP so that a build's configuration may be changed without
having to edit this file.
.IP 5.
The \fIImakefile\fP describing the input files and output targets 
for the current directory is included.  This file is supplied
by the programmer instead of a \fIMakefile\fP.  The functions that
it invokes are translated by \fIcpp\fP into series of \fImake\fP 
rules and targets.
.IP 6.
Finally, \fImake\fP rules for recreating the \fIMakefile\fP and managing
subdirectories are appended, and the result is written out as the
new \fIMakefile\fP.
.RE
.LP
\fIImake\fP, along with a separate tool (named \fImakedepend\fP, also 
written by
Brunhoff) that generates \fIMakefile\fP dependencies
between object files and the source files used to build them, allows
properly configured \fIMakefiles\fP to be regenerated quickly and correctly.  
By isolating the machine- and site-specifics from the programmer,
\fIimake\fP is much like a well-developed text formatter: both allow 
the writer to concentrate on the content, rather than the production, of a 
document.
.NH 1
How X uses \fIimake\fP
.LP
Development of X at MIT is currently done on more than half a dozen 
different platforms, each of which is running a different operating system.
A common source pool is shared across those machines that support
symbolic links and NFS by creating trees of links pointing
back to the master sources (similar to the object trees of [Harrison 88]).
Editing and source code control is done in the master sources and builds are 
done in the link trees.  
.LP
.ne 4
A full build is done by creating a fresh link tree and invoking a
simple, stub top-level \fIMakefile\fP which:
.RS .5in
.IP 1.
compiles \fIimake\fP.
.IP 2.
builds the real top-level \fIMakefile\fP.
.IP 3.
builds the rest of the \fIMakefiles\fP using the new top-level \fIMakefile\fP.
.IP 4.
removes any object files left over from the previous build.
.IP 5.
builds the header file tree, and
computes and appends the list of dependencies between object files and sources
to the appropriate \fIMakefiles\fP.
.IP 6.
and finally, compiles all of the sources.
.RE
.LP
If the build completes successfully, programs, libraries, data files, and
manual pages may then be installed.  By keeping object files out of the master
source tree, backups and releases can be done easily and efficiently.  By
substituting local copies of particular files for the appropriate links, 
developers can work without disturbing others.
.NH 1
Limitations
.LP
Although the system described here is very useful, it isn't perfect.  
Differences
between utilities on various systems places a restriction on how well
existing tools can be used.  One of the reasons why \fIimake\fP is a program
instead of a trivial invocation of the C preprocessor is that some \fIcpp\fP's
collapse tabs into spaces while others do not.  Since \fImake\fP uses
tabs to separate commands from targets, \fIimake\fP must sometimes reformat
the output from \fIcpp\fP so that a valid \fIMakefile\fP is generated.
.LP
Since \fIcpp\fP only provides global 
scoping of symbolic constants, parameters
are visible to the whole configuration system.  For larger projects, this
approach will probably prove unwieldy both to the people trying to maintain 
them and to the preprocessors that keep the entire symbol table in memory.
.LP
The macro facility provided by \fIcpp\fP is convenient because it is available
on every platform and it is familar to most people.  However, a better
language with real programming constructs might provide a better interface.
The notions of describing one platform in terms of another and providing
private configuration parameters map intriguingly well into the models used
in object management systems.
.NH 1
Summary and Observations
.LP
The sample implementation of the X Window System from MIT takes advantage
of a system architecture that goes to great lengths to isolate
device-dependencies.  By selectively using portable versions of
the device-specific functions, a developer moving X to a new platform can
quickly get an initial port up and running very quickly.
.LP
To manage the various combinations of modules and to cope with the 
differing requirements of every platform and site, X uses a
utility named \fIimake\fP
to separate the description of sources and targets from the
details of how the software is actually built.  Using as few external
tools as possible, this mechanism allows support for new platforms to be
added with relatively little effort.
.LP
Although the approaches taken by MIT will not work for everyone, several of
its experiences may be useful in other projects:
.RS .5in
.Ip
Even if portability isn't a goal now, it probably will become one sooner
than expected.
.Ip
Just as in other areas, it frequently pays to periodically stand back 
from a problem and see whether or not a simple tool will help.  With
luck and the right amount of abstracting it may even solve several
problems at once.  
.Ip
Be wary of anything that requires manual intervention.
.Ip
And finally, there is no such thing as portable software, only software that
has been ported.
.RE
.NH 1
References
.LP
.IP "\[Harrison 88\]"
.br
``Rtools: Tools for Software Management in a Distributed Computing
Environment,'' Helen E. Harrison, Stephen P. Schaefer, Terry S. Yoo,
\fIProceedings of the Usenix Association Summer Conference\fP, 
June 1988, 85-94.
.IP "\[Lord 88\]"
.br
``Tools and Policies for the Hierarchical Management of Source Code 
Development,'' Thomas Lord, \fIProceedings of the Usenix Association
Summer Conference\fP, June 1988, 95-106.
.IP "\[Scheifler 88\]"
.br
\fIX Window System: C Library and Protocol Reference\fP, Robert Scheifler, 
James Gettys, and Ron Newman, Digital Press, Bedford, MA, 1988.


.\
.\XXX - Xos.h:
.\	o  12 character file names
.\	o  isolate system calls
.\	o  avoid tricky coding
.\	o  index vs. strchr
.\	o  bcopy
.\	o  test on as wide a range of systems as possible
.\
