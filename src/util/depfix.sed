#
# Insert the header.....
#
1i\
# +++ Dependency line eater +++\
# \
# Makefile dependencies follow.  This must be the last section in\
# the Makefile.in file\
#

#
# Remove line continuations....
#
:FIRST
y/	/ /
s/^ *//
/\\$/{
N
y/	/ /
s/\\\n */ /
bFIRST
}
# for simplicity, always have a trailing space
s/$/ /
s/  */ /g

# change foo.o -> $(OUTPRE)foo.$(OBJEXT)
s;^\([a-zA-Z0-9_\-]*\).o:;$(OUTPRE)\1.$(OBJEXT):;

# delete system-specific or compiler-specific files from list
# (the last two are pathnames used at MIT -- if you have a local
#  gcc installation in some odd place, you may need to customize this)
s;/usr/include/[^ ]* ;;g
s;/usr/lib/[^ ]* ;;g
s;/mit/cygnus[^ ]* ;;g
s;/mit/gnu/[^ ]* ;;g

# remove foo/../ sequences
:dotdot
/\/[a-z][a-z0-9_.\-]*\/\.\.\// {
s;/[a-z][a-z0-9_.\-]*/\.\./;/;g
bdotdot
}

# rely on VPATH for $(srcdir) files
s;\$(srcdir)/\([^ /]* \);\1;g

# allow override of some util dependencies in case local tools are used
s;\$(BUILDTOP)/include/com_err.h ;$(COM_ERR_DEPS) ;g
s;\$(BUILDTOP)/include/ss/ss.h \$(BUILDTOP)/include/ss/ss_err.h ;$(SS_DEPS) ;g
s;\$(BUILDTOP)/include/db.h \$(BUILDTOP)/include/db-config.h ;$(DB_DEPS) ;g

# now delete trailing whitespace
s; *$;;g

# Split lines if they're too long.
s/\(.\{50\}[^ ]*\) /\1 \\\
  /g


#
# Now insert a trailing newline...
#
$a\

