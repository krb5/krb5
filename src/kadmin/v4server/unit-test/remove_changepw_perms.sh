#!/bin/sh

# tcl sucks big fat hairy rocks

ed $K5ROOT/ovsec_adm.acl <<EOF >/dev/null 2>&1
g/changepw\/kerberos/s/^/#/
w
q
EOF
