#!/bin/sh
# Produce a sed script for converting Kerberos Cygnus V4 filenames to proposed
# names -- for converting old makefiles and doc.
# We fix any "oldfoo." into "newfoo." including .c and .o and .h files.
awk '/^@ / {	if ($6 != "")
			if ($6 != $4)
				print "s/" $6 "/" $4 "/g"
			else ;
		else if ($2 != $4 && $2 != "-")
			print "s/" $2 "/" $4 "/g"
	  }
     /^@sed / { print $2 }
    ' <ren.msg | grep -v '(gone)' | sed 's/\.c/\\./g'
