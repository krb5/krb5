# Rename DOS-truncated filenames to Unix filenames for KRB library.
# for converting DOS distributions to Unix distributions
awk '/^@ / {
		if ($4 != $5)
			print "mv	" $5 "	" $4
	  }
    ' <ren.msg | sh -x
