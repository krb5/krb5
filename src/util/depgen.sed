# input srctop something like ../../../../asrc/lib/krb5/asn.1/../../../
# output a sequence of sed commands for recognizing and replacing srctop,
# something like:
# s; ../../../../asrc/lib/krb5/asn.1/../../../; $(SRCTOP)/;g
# s; ../../../../asrc/lib/krb5/../../; $(SRCTOP)/;g
# s; ../../../../asrc/lib/../; $(SRCTOP)/;g
# s; ../../../../asrc/; $(SRCTOP)/;g

s,\.,\\.,g
s,^,s; ,
s,$,/; $(SRCTOP)/;g,
:loop
/\/[a-z][a-z0-9_.\-]*\/\\\.\\\.\// {
p
s;/[a-z][a-z0-9_.\-]*/\\\.\\\./;/;
bloop
}
# implicit print at end
