#!/bin/sh

COMERR_DIR=$SRCROOT/../util/et
COMPILE_ET_SH=$COMERR_DIR/compile_et.sh
COMPILE_ET=$COMERR_DIR/compile_et

PROFILE_DIR=$SRCROOT/../util/profile
ERROR_TABLES_DIR=$SRCROOT/../lib/krb5/error_tables
GSS_GENERIC_DIR=$SRCROOT/../lib/gssapi/generic
GSS_KRB5_DIR=$SRCROOT/../lib/gssapi/krb5

if [ ! -x $COMPILE_ET ] || [ $COMPILE_ET_SH -nt $COMPILE_ET ]; then
    echo "Building compile_et"
    $COMERR_DIR/config_script $COMPILE_ET_SH /usr/bin/awk /usr/bin/sed > $COMPILE_ET
    /bin/chmod 755 $COMPILE_ET
fi

if [ -x $COMPILE_ET ]; then
    echo "Generating profile error tables"
    cd $PROFILE_DIR && $COMPILE_ET $PROFILE_DIR/prof_err.et
    
    echo "Generating adm error tables"
    cd $ERROR_TABLES_DIR && $COMPILE_ET $ERROR_TABLES_DIR/adm_err.et

    echo "Generating asn1 error tables"
    cd $ERROR_TABLES_DIR && $COMPILE_ET $ERROR_TABLES_DIR/asn1_err.et

    echo "Generating kdb5 error tables"
    cd $ERROR_TABLES_DIR && $COMPILE_ET $ERROR_TABLES_DIR/kdb5_err.et

    echo "Generating krb5 error tables"
    cd $ERROR_TABLES_DIR && $COMPILE_ET $ERROR_TABLES_DIR/krb5_err.et

    echo "Generating kv5m error tables"
    cd $ERROR_TABLES_DIR && $COMPILE_ET $ERROR_TABLES_DIR/kv5m_err.et

    echo "Generating gss error tables"
    cd $GSS_GENERIC_DIR && $COMPILE_ET $GSS_GENERIC_DIR/gssapi_err_generic.et
    cd $GSS_KRB5_DIR && $COMPILE_ET $GSS_KRB5_DIR/gssapi_err_krb5.et
fi
