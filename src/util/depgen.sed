# input srctop myfulldir
# something like ../../../../asrc/lib/krb5/asn.1/../../../ lib/krb5/asn.1
# 
# output a sequence of sed commands for recognizing and replacing srctop,
# something like:
# s; ../../../../asrc/lib/krb5/asn.1/../../../; $(SRCTOP)/;g
# s; ../../../../asrc/lib/krb5/../../; $(SRCTOP)/;g
# s; ../../../../asrc/lib/../; $(SRCTOP)/;g
# s; ../../../../asrc/; $(SRCTOP)/;g
# s; $(SRCTOP)/lib/krb5/asn.1/; $(srcdir)/;g
# s; $(SRCTOP)/lib/krb5/; $(srcdir)/../;g
# ...

# just process first "word"
h
s/ .*$//

# replace multiple slashes with one single one
s,///*,/,g
# replace /./ with /
s,/\./,/,g
# strip trailing slashes, but not if it'd leave the string empty
s,\(..*\)///*,\1/,
# quote dots
s,\.,\\.,g
# turn string into sed pattern
s,^,s; ,
s,$,/; $(SRCTOP)/;g,
# emit potentially multiple patterns
:loop
/\/[a-z][a-zA-Z0-9_.\-]*\/\\\.\\\.\// {
p
s;/[a-z][a-zA-Z0-9_.\-]*/\\\.\\\./;/;
bloop
}
p

# now process second "word"
x
s/^.* //

# treat "." specially
/^\.$/{
d
q
}
# make sed pattern
s,^,s; $(SRCTOP)/,
s,$,/; $(srcdir)/;g,
# emit potentially multiple patterns
:loop2
\,[^/)]/; , {
p
# strip trailing dirname off first part; append "../" to second part
s,/[a-z][a-zA-Z0-9_.\-]*/; ,/; ,
s,/;g,/../;g,
bloop2
}
# kill implicit print at end; don't change $(SRCTOP) into .. sequence
d
