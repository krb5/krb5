#!/bin/sh

PROFILE_DIR=$SRCROOT/../util/profile
echo "Generating profile.h"
cat $PROFILE_DIR/profile.hin $PROFILE_DIR/prof_err.h > $PROFILE_DIR/profile.h

INCLUDE_DIR=$SRCROOT/../include
ERROR_TABLE_DIR=$SRCROOT/../lib/krb5/error_tables
GSS_DIR=$SRCROOT/../lib/gssapi

echo "Symlinking error table header files"
ln -sf $ERROR_TABLE_DIR/adm_err.h $INCLUDE_DIR
ln -sf $ERROR_TABLE_DIR/asn1_err.h $INCLUDE_DIR
ln -sf $ERROR_TABLE_DIR/kdb5_err.h $INCLUDE_DIR
ln -sf $ERROR_TABLE_DIR/krb5_err.h $INCLUDE_DIR
ln -sf $ERROR_TABLE_DIR/kv5m_err.h $INCLUDE_DIR

if [ -f $INCLUDE_DIR/krb5.h ]; then
    echo "Removing previous krb5.h"
    rm $INCLUDE_DIR/krb5.h
fi

echo "Generating krb5.h"
echo "/* This is the prologue to krb5.h */" > $INCLUDE_DIR/krb5.h
echo "/* Unfortunately some of these defines are compiler dependent */" >> $INCLUDE_DIR/krb5.h
grep SIZEOF $SRCROOT/GSSKerberosPrefix.h >> $INCLUDE_DIR/krb5.h
grep HAVE_STDARG_H $SRCROOT/GSSKerberosPrefix.h >> $INCLUDE_DIR/krb5.h
grep HAVE_SYS_TYPES_H $SRCROOT/GSSKerberosPrefix.h >> $INCLUDE_DIR/krb5.h
echo "/* End of prologue section */"  >> $INCLUDE_DIR/krb5.h
cat $INCLUDE_DIR/krb5.hin $INCLUDE_DIR/krb5_err.h $INCLUDE_DIR/kdb5_err.h \
    $INCLUDE_DIR/kv5m_err.h $INCLUDE_DIR/asn1_err.h >> $INCLUDE_DIR/krb5.h

if [ -f $GSS_DIR/gssapi.h ]; then
    echo "Removing previous gssapi.h"
    rm $GSS_DIR/gssapi.h
fi

echo "Generating gssapi.h"
echo "/* This is the gssapi.h prologue. */" > $GSS_DIR/gssapi.h
echo "/* It contains some choice pieces of autoconf.h */" >> $GSS_DIR/gssapi.h
grep SIZEOF $SRCROOT/GSSKerberosPrefix.h >> $GSS_DIR/gssapi.h
grep 'HAVE_.*_H' $SRCROOT/GSSKerberosPrefix.h >> $GSS_DIR/gssapi.h
grep 'USE_.*_H' $SRCROOT/GSSKerberosPrefix.h >> $GSS_DIR/gssapi.h
echo "/* End of gssapi.h prologue. */"  >> $GSS_DIR/gssapi.h
cat $GSS_DIR/generic/gssapi.hin  >> $GSS_DIR/gssapi.h

echo "Generating fake autoconf.h; the real one is included as a prefix file."
touch $INCLUDE_DIR/autoconf.h
