#!/bin/sh
# Produce a sed script for converting Kerberos V4 pl10 filenames to proposed
# names -- for converting old makefiles and doc.
# We fix any "oldfoo." into "newfoo." including .c and .o and .h files.
awk '/^@ / {	
		if ($2 != $4)
			print "s/" $2 "/" $4 "/g"
	  }
     /^@sed / { print $2 }
    ' <ren.msg | sed 's/\.c/\\./g'
