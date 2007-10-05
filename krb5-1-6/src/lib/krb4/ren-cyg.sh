#!/bin/sh
# Rename Kerberos Cygnus V4 filenames to proposed names
# for converting old trees.
awk '/^@ / {	if ($6 != "")
			if ($6 != $4)
				print "mv	" $6 "	" $4
			else ;
		else if ($2 != $4 && $2 != "-")
			print "mv	" $2 "	" $4
	  }
    ' <ren.msg | grep -v '(gone)' | sh -x
