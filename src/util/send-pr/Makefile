#
# Makefile for building a standalone send-pr.
#
RELEASE=1.0
SUBMITTER=net
sendprname = krb5-send-pr
EMACS=emacs

prefix = /usr/local
bindir = $(prefix)/bin
datadir = $(prefix)/lib
infodir = $(prefix)/info
lispdir = $(prefix)/lib/emacs/site-lisp
mandir = $(prefix)/man
man1dir = $(mandir)/man1

all: send-pr  install-sid

send-pr: send-pr.sh
	sed -e 's,@DATADIR@,$(datadir),g' \
	    -e 's,@SUBMITTER@,$(SUBMITTER),g' \
	    -e 's/@DEFAULT_RELEASE@/$(RELEASE)/g' send-pr.sh > send-pr



install-sid: install-sid.sh
	sed -e 's,@BINDIR@,$(bindir),g' install-sid.sh > install-sid

install: all
	if [ -d $(prefix) ]; then true ; else mkdir $(prefix) ; fi
	if [ -d $(bindir) ]; then true ; else mkdir $(bindir) ; fi
	cp send-pr $(bindir)/$(sendprname)
	chmod 755 $(bindir)/$(sendprname)
	cp install-sid $(bindir)
	chmod 755 $(bindir)/install-sid
	if [ -d $(datadir) ] ; then true ; else mkdir $(datadir) ; fi
	if [ -d $(datadir)/gnats ] ; then true ; else mkdir $(datadir)/gnats ; fi
	cp categories $(datadir)/gnats/mit
	chmod 644 $(datadir)/gnats/mit
	-parent=`echo $(man1dir)|sed -e 's@/[^/]*$$@@'`; \
	if [ -d $$parent ] ; then true ; else mkdir $$parent ; fi
	if [ -d $(man1dir) ] ; then true ; else mkdir $(man1dir) ; fi
	cp send-pr.1 $(man1dir)/$(sendprname).1
	chmod 644 $(man1dir)/$(sendprname).1

clean:
	rm -f install-sid send-pr send-pr.el*

