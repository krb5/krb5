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

# delete system-specific or compiler-specific files from list
s;/usr/include/[^ ]* ;;g
s;/usr/lib/[^ ]* ;;g
s;/mit/cygnus[^ ]* ;;g
# rely on VPATH for $(srcdir) files
s;\$(srcdir)/\([^ /]* \);\1;g
# now delete trailing whitespace
s; *$;;g

# Split lines if they're too long.
s/\(.\{50\}[^ ]*\) /\1 \\\
  /g


#
# Now insert a trailing newline...
#
$a\

