#!/bin/sh
#
#
AWK=@AWK@
DIR=@DIR@

usage="usage: $0 [ -d scriptDir ] inputfile.et"

if [ "$1" = "-d" ]; then
    if [ $# -lt 3 ]; then
	echo $usage 1>&2 ; exit 1
    fi
    DIR=$2 ; shift ; shift
fi
if [ $# -ne 1 ]; then
    echo $usage 1>&2 ; exit 1
fi

ROOT=`echo $1 | sed -e s/.et$//`
BASE=`echo $ROOT | sed -e 's;.*/;;'`

set -ex
$AWK -f ${DIR}/et_h.awk outfile=${BASE}.h $ROOT.et
$AWK -f ${DIR}/et_c.awk outfile=${BASE}.c $ROOT.et
