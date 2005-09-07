#!/bin/sh
# Produce a sed script for converting Kerberos V4 MIT PC filenames to proposed
# names -- for converting old makefiles and doc.
# We fix any "oldfoo." into "newfoo." including .c and .o and .h files.
awk '/^@ / {	
		if ($3 != $4)
			print "s/" $3 "/" $4 "/g"
	  }
     /^@sed / { print $2 }
    ' <ren.msg | grep -v '(gone)' | sed 's/\.c/\\./g'

