#
# $Id$
#

TOP = ../../..
include $(TOP)/config.mk/template

export RPC_TEST_SRVTAB := /tmp/rpc_test_v5srvtab

unit-test:: unit-test-setup unit-test-body unit-test-cleanup

unit-test-setup::
	$(START_SERVERS)
	./rpc_test_setup.sh

unit-test-body::
	$(RUNTEST) SERVER=../server CLIENT=../client --tool rpc_test

unit-test-cleanup::
	$(STOP_SERVERS)
	-rm -f /tmp/rpc_test_v5srvtab /tmp/krb5cc_rpc_test_fullrun

clean::
	$(CLEAN) rpc_test.log rpc_test.plog rpc_test.sum rpc_test.psum
