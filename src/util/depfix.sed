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

# delete tcl-specific headers
s;/[^ ]*/tcl\.h ;;g
s;/[^ ]*/tclDecls\.h ;;g
s;/[^ ]*/tclPlatDecls\.h ;;g

# delete system-specific or compiler-specific files from list
s;/os/usr/include/[^ ]* ;;g
s;/usr/include/[^ ]* ;;g
s;/usr/lib/[^ ]* ;;g

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

# Some krb4 dependencies should only be present if building with krb4 enabled
s;\$(BUILDTOP)/include/kerberosIV/krb_err.h ;$(KRB_ERR_H_DEP) ;g

# now delete trailing whitespace
s; *$;;g

# Split lines if they're too long.
s/\(.\{50\}[^ ]*\) /\1 \\\
  /g


#
# Now insert a trailing newline...
#
$a\

