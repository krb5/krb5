.TH IMAKE 1 "Release 4" "X Version 11"
.SH NAME
imake \- C preprocessor interface to the make utility
.SH SYNOPSIS
\fBimake \fP[-D\fIdefine\fP] [-I\fIdir\fP] [-T\fItemplate\fP]
[-f \fIfilename\fP] [-s \fIfilename\fP] [-e] [-v]
.SH DESCRIPTION
.I Imake
is used to 
generate \fIMakefiles\fP from a template, a set of \fIcpp\fP macro functions,
and a per-directory input file called an \fIImakefile\fP.  This allows machine
dependencies (such has compiler options, alternate command names, and special
\fImake\fP rules) to be kept separate from the descriptions of the
various items to be built.
.SH OPTIONS
The following command line options may be passed to \fIimake\fP:
.TP 8
.B \-D\fIdefine\fP
This option is passed directly to \fIcpp\fP.  It is typically used to set
directory-specific variables.  For example, the X Window System uses this
flag to set \fITOPDIR\fP to the name of the directory containing the top
of the core distribution and \fICURDIR\fP to the name of the current 
directory, relative to the top.
.TP 8
.B \-I\fIdirectory\fP
This option is passed directly to \fIcpp\fP.  It is typically used to 
indicate the directory in which the \fIimake\fP template and configuration
files may be found.
.TP 8
.B \-T\fItemplate\fP
This option specifies the name of the master template file (which is usually
located in the directory specified with \fI\-I\fP) used by \fIcpp\fP.
The default is \fIImake.tmpl\fP.
.TP 8
.B \-f \fIfilename\fP
This option specifies the name of the per-directory input file.  The default
is \fIImakefile\fP.
.TP 8
.B \-s \fIfilename\fP
This option specifies the name of the \fImake\fP description file to be 
generated but \fImake\fP should not be invoked.
If the \fIfilename\fP is a dash (-), the 
output is written to \fIstdout\fP.  The default is to generate, but
not execute, a \fIMakefile\fP.
.TP 8
.B \-e
This option indicates the \fIimake\fP should execute the generated
\fIMakefile\fP.  The default is to leave this to the user.
.TP 8
.B \-v
This option indicates that \fIimake\fP should print the \fIcpp\fP command line 
that it is using to generate the \fIMakefile\fP.
.SH "HOW IT WORKS"
\fIImake\fP invokes \fIcpp\fP with any \fI\-I\fP or \fI-D\fP flags passed
on the command line and passes it the following 3 lines:
.sp
.nf
		#define IMAKE_TEMPLATE "Imake.tmpl"
		#define INCLUDE_IMAKEFILE "Imakefile"
		#include IMAKE_TEMPLATE
.fi
.sp
where \fIImake.tmpl\fP and \fIImakefile\fP may be overridden by the 
\fI\-T\fP and \fI\-f\fP command options, respectively.  If the 
\fIImakefile\fP contains any lines beginning with a '#' character
that is not followed by a \fIcpp\fP directive (\fB#include\fP,
\fB#define\fP, \fB#undef\fP, \fB#ifdef\fP, \fB#else\fP, \fB#endif\fP,
or \fB#if\fP), \fIimake\fP will make a temporary \fImakefile\fP in
which the '#' lines are prepended with the string ``/**/'' (so that
\fIcpp\fP will copy the line into the \fIMakefile\fP as a comment).
.PP
The \fIImakefile\fP reads in file containing machine-dependent parameters 
(specified as \fIcpp\fP symbols), a site-specific parameters file, a file
containing \fIcpp\fP macro functions for generating \fImake\fP rules, and
finally the \fIImakefile\fP (specified by INCLUDE_IMAKEFILE) in the current 
directory.  The \fIImakefile\fP uses the macro functions to indicate what
targets should be built; \fIimake\fP takes care of generating the appropriate
rules.
.PP
The rules file (usually named \fIImake.rules\fP in the configuration
directory) contains a variety of \fIcpp\fP macro functions that are
configured according to the current platform.  \fIImake\fP replaces 
any occurrences of the string ``@@'' with a newline to allow macros that
generate more than one line of \fImake\fP rules.  
For example, the macro
.ta .8i 1.6i 5i
.nf

#define	program_target(program, objlist)	@@\e
program:	objlist		@@\e
	$(CC) -o $@ objlist $(LDFLAGS)

.fi
when called with
.I "program_target(foo, foo1.o foo2.o)"
will expand to
.nf

foo:	foo1.o foo2.o
	$(CC) -o $@ foo1.o foo2.o $(LDFLAGS)

.fi
.PP
On systems whose \fIcpp\fP reduces multiple tabs and spaces to a single
space, \fIimake\fP attempts to put back any necessary tabs (\fImake\fP is
very picky about the difference between tabs and spaces).  For this reason,
colons (:) in command lines must be preceded by a backslash (\\).
.SH "USE WITH THE X WINDOW SYSTEM"
The X Window System uses \fIimake\fP extensively, for both full builds within
the source tree and external software.  As mentioned above, two special
variables, \fITOPDIR\fP and \fICURDIR\fP set to make referencing files
using relative path names easier.  For example, the following command is
generated automatically to build the \fIMakefile\fP in the directory
\fIlib/X/\fP (relative to the top of the sources):
.sp
.nf
	%  ../.././config/imake  -I../.././config \\
		-DTOPDIR=../../. -DCURDIR=./lib/X
.fi
.sp
When building X programs outside the source tree, a special symbol
\fIUseInstalled\fP is defined and \fITOPDIR\fP and
\fICURDIR\fP are omitted.  If the configuration files have been
properly installed, the script \fIxmkmf(1)\fP may be used to specify
the proper options:
.sp
.nf
	%  xmkmf
.fi
.sp
The command \fImake Makefiles\fP can then be used to generate \fIMakefiles\fP
in any subdirectories.
.SH FILES
.ta 3i
/usr/tmp/tmp-imake.\fInnnnnn\fP	temporary input file for cpp
.br
/usr/tmp/tmp-make.\fInnnnnn\fP	temporary input file for make
.br
/lib/cpp	default C preprocessor
.DT
.SH "SEE ALSO"
make(1)
.br
S. I. Feldman
.I
Make \- A Program for Maintaining Computer Programs
.SH "ENVIRONMENT VARIABLES"
The following environment variables may be set, however their use is not
recommended as they introduce dependencies that are not readily apparent
when \fIimake\fP is run:
.TP 5
.B IMAKEINCLUDE
If defined, this should be a valid include argument for the
C preprocessor.  E.g. ``-I/usr/include/local''.
Actually, any valid
.I cpp
argument will work here.
.TP 5
.B IMAKECPP
If defined, this should be a valid path to a preprocessor program.
E.g. ``/usr/local/cpp''.
By default,
.I imake
will use /lib/cpp.
.TP 5
.B IMAKEMAKE
If defined, this should be a valid path to a make program.
E.g. ``/usr/local/make''.
By default,
.I imake
will use whatever
.I make
program is found using
.I execvp(3).
.SH "BUGS"
Comments should be preceded by ``/**/#'' to protect them from \fIcpp\fP.
.SH "AUTHOR"
Todd Brunhoff, Tektronix and MIT Project Athena; Jim Fulton, MIT X Consortium

