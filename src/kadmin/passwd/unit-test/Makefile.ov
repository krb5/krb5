#
# $Id$
#

TOP = ../..
include $(TOP)/config.mk/template

USER = root

unit-test:: unit-test-setup unit-test-body unit-test-cleanup

unit-test-body::	
	$(RUNTEST) KPASSWD=../kpasswd \
		KINIT=$(TOP)/../clients/kinit/kinit \
		KDESTROY=$(TOP)/../clients/kdestroy/kdestroy \
		USER=$(USER) --tool kpasswd
    
unit-test-setup::
	$(START_SERVERS)
	echo "source $(TCLUTIL); catch {ovsec_kadm_init admin admin \$$OVSEC_KADM_ADMIN_SERVICE null \$$OVSEC_KADM_STRUCT_VERSION \$$OVSEC_KADM_API_VERSION_1 server_handle; ovsec_kadm_create_principal \$$server_handle [simple_principal $(USER)] {OVSEC_KADM_PRINCIPAL} $(USER); ovsec_kadm_destroy \$$server_handle;}; if {[info exists errorInfo]} { puts stderr \$$errorInfo; exit 1; }" | $(CLNTTCL)

unit-test-cleanup::
	$(STOP_SERVERS)
