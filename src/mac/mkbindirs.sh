#!/bin/sh
#
# This shell script creates the Macintosh binary hierarchies.

topbin=$1
shift

for DIR do
  mkdir $topbin/$DIR
  for SDIR in `sed -n -e 's/MAC_SUBDIRS.*=//p' $DIR/Makefile.in`; do
    /bin/sh mac/mkbindirs.sh $topbin $DIR/$SDIR;
  done
done
