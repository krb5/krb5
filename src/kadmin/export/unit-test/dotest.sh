#!/bin/sh

DUMMY=${TESTDIR=$TOP/testing}
DUMMY=${BSDDB_DUMP=$TESTDIR/util/bsddb_dump}
DUMMY=${KDB5_EDIT=$TOP/../admin/edit/kdb5_edit}

DPRINC=/tmp/dbdump.princ
DPOL=/tmp/dbdump.policy

DPRINC1=$DPRINC.1
DPRINC2=$DPRINC.2

DPOL1=$DPOL.1
DPOL2=$DPOL.2

DEXPORT=/tmp/dbexport

./add-to-db.sh

rm -f $DEXPORT
../kadm5_export > $DEXPORT

if $KDB5_EDIT -R ddb | sort > $DPRINC1; then
	:
else
	echo "error dumping princ.1"
fi
if $BSDDB_DUMP /krb5/kadb5 | sort > $DPOL1; then
	:
else
	echo "error dumping policy.1"
fi

rm -f /krb5/kadb5*
touch /krb5/ovsec_adm.lock

../../import/kadm5_import < $DEXPORT

if $KDB5_EDIT -R ddb | sort > $DPRINC2; then
	:
else
	echo "error dumping princ.2"
fi
if $BSDDB_DUMP /krb5/kadb5 | sort > $DPOL2; then
	:
else
	echo "error dumping policy.2"
fi


status=0

if test -s $DPRINC1 && \
   test -s $DPRINC2 && \
   cmp -s $DPRINC1 $DPRINC2; then
	echo "export/import principal db succeeded"
else
	echo "export/import principal db failed"
	status=1
fi

if test -s $DPOL1 && \
   test -s $DPOL2 && \
   cmp -s $DPOL1 $DPOL2; then
	echo "export/import policy db succeeded"
else
	echo "export/import policy db failed"
	status=1
fi

if [ $status -eq 0 ]; then
	rm -f $DPRINC* $DPOL* $DEXPORT
fi

exit $status
