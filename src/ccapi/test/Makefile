# run with "make all" to create CCAPI tests in "/tmp/ccapi_test"
# run resulting tests with "sh test_ccapi.sh"

CC = gcc
LIBS = -lkrb5

SRCDIR = src
DSTROOT = /tmp
OBJDIR = $(DSTROOT)/ccapi_intermediates
DSTDIR = $(DSTROOT)/ccapi_test
TESTDIR = $(DSTDIR)/tests

SCRIPT_NAME = test_ccapi.sh

_OBJECTS = test_ccapi_ccache test_ccapi_check test_ccapi_constants test_ccapi_context test_ccapi_globals test_ccapi_iterators test_ccapi_log test_ccapi_util

OBJECTS = $(patsubst %,$(OBJDIR)/%.o,$(_OBJECTS))

TEST_NAMES = test_constants test_cc_initialize test_cc_context_get_version test_cc_context_release test_cc_context_get_change_time test_cc_context_get_default_ccache_name test_cc_context_open_ccache test_cc_context_open_default_ccache test_cc_context_create_ccache test_cc_context_create_default_ccache test_cc_context_create_new_ccache test_cc_context_new_ccache_iterator test_cc_context_compare test_cc_ccache_release test_cc_ccache_destroy test_cc_ccache_set_default test_cc_ccache_get_credentials_version test_cc_ccache_get_name test_cc_ccache_get_principal test_cc_ccache_set_principal test_cc_ccache_store_credentials test_cc_ccache_remove_credentials test_cc_ccache_new_credentials_iterator test_cc_ccache_get_change_time test_cc_ccache_get_last_default_time test_cc_ccache_move test_cc_ccache_compare test_cc_ccache_get_kdc_time_offset test_cc_ccache_set_kdc_time_offset test_cc_ccache_clear_kdc_time_offset test_cc_ccache_iterator_next test_cc_credentials_iterator_next

TEST_OBJECTS = $(patsubst %,$(OBJDIR)/%.o,$(TEST_NAMES))

all: setup-test-dir build-base build-tests link-tests copy-script success-message

# compile base files used by all tests
build-base: $(OBJECTS)

# compile each test
build-tests: $(TEST_OBJECTS)

# rule to compile files in src directory
$(OBJDIR)/%.o: $(SRCDIR)/%.c
	$(CC) -c -o $@ $<

# Make a build directory
setup-test-dir:
	@echo "Removing old destination directory... $(DSTDIR)"
	if [ -d "$(DSTDIR)" ]; then chmod -R u+w "$(DSTDIR)" && rm -rf "$(DSTDIR)"; fi
	mkdir -p "$(TESTDIR)"
	if [ -d "$(OBJDIR)" ]; then chmod -R u+w "$(OBJDIR)" && rm -rf "$(OBJDIR)"; fi
	mkdir -p "$(OBJDIR)"

link-tests: $(TEST_NAMES)

$(TEST_NAMES): $(TEST_OBJECTS)
	$(CC) -o $(TESTDIR)/$@ $(OBJDIR)/$@.o $(OBJECTS) $(LIBS)

copy-script:
	cp $(SRCDIR)/$(SCRIPT_NAME) $(DSTDIR)/$(SCRIPT_NAME)

success-message:
	@echo
	@echo "CCAPI tests created in $(DSTDIR)"

.PHONY: clean

clean:
	-rm -rf "$(OBJDIR)"
	

