SHELL = /bin/sh
MAKE = make
FLAGS = $(MFLAGS) -f Makefile.ini BOOTSTRAPCFLAGS="$(BOOTSTRAPCFLAGS)"

all:
	@echo Please use make World.
	@echo Check the configuration parameters in the ./config/cf directory,
	@echo and pass BOOTSTRAPCFLAGS if necessary.
	@echo Read the release notes carefully before proceeding.
	@echo Do not name your log file make.log or it will be deleted.
	@echo If the top-level Makefile gets corrupted, copy Makefile.ini
	@echo to Makefile and try again.

world:
	$(MAKE) $(FLAGS) world
