# Rename Kerberos V4 pl10 filenames to proposed names
# for converting old trees.
awk '/^@ / {
		if ($2 != $4 && $2 != "-")
			print "mv	" $2 "	" $4
	   }
    ' <ren.msg | grep -v '(gone)' | sh -x
