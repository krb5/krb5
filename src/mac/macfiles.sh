#!/bin/sh

for DIR do
  for SDIR in `sed -n -e 's/MAC_SUBDIRS.*=//p' $DIR/Makefile.in`; do
    awk '/^MACSRCS?[ 	]*=/, /[^\\]$/' $DIR/$SDIR/Makefile.in | \
      tr ' 	' '\012\012' | sed -n -e 's|.*[/)]\([A-Za-z0-9_]*\.c\).*|\1|' -e 's|\(.*\.c\)|'$DIR/$SDIR'/\1|p';
    awk '/^SRCS?[ 	]*=/, /[^\\]$/' $DIR/$SDIR/Makefile.in | \
      tr ' 	' '\012\012' | sed -n -e 's|.*[/)]\([A-Za-z0-9_]*\.c\).*|\1|' -e 's|\(.*\.c\)|'$DIR/$SDIR'/\1|p';
    ls -1 $DIR/$SDIR/*.h 2> /dev/null
    mac/macfiles.sh $DIR/$SDIR;
  done
done
