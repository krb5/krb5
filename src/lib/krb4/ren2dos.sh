# Rename Unix filenames to DOS-truncated filenames for KRB library.
# for converting Unix distributions to DOS distributions
awk '/^@ / {
		if ($4 != $5)
			print "mv	" $4 "	" $5
	  }
    ' <ren.msg | sh -x
