# Rename Kerberos V4 MIT PC-port filenames to proposed names
# for converting old PC trees on Unix systems.
awk '/^@ / {
		if ($3 != $4 && $3 != "-")
			print "mv	" $3 "	" $4
	   }
    ' <ren.msg | grep -v '(gone)' | sh -x
