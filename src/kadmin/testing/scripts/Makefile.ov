# $Id$

TOP = ../..
include $(TOP)/config.mk/template

GEN_SCRIPTS = compare_dump.pl fixup-conf-files.pl make-host-keytab.pl \
	simple_dump.pl verify_xrunner_report.pl

all:: $(GEN_SCRIPTS)

%.pl: %.pl.in
	-rm -f $@.tmp
	echo "#!$(PERL)" > $@.tmp
	sed 1d $@.in >> $@.tmp
	chmod +x $@.tmp
	mv $@.tmp $@

clean::
	-rm -f $(GEN_SCRIPTS) *.tmp
