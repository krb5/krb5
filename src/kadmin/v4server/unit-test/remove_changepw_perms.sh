#!/bin/sh

# tcl sucks big fat hairy rocks

ed /krb5/ovsec_adm.acl <<EOF >/dev/null 2>&1
g/changepw\/kerberos/s/^/#/
w
q
EOF
