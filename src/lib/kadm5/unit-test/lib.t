global timeout
set timeout 60

proc cmd {command} {
    global prompt
    global spawn_id
    global test

    send "[string trim $command]\n"
    expect {
	-re "OK .*$prompt$" { return 1 }
        -re "ERROR .*$prompt$" { return 0 }
	"wrong # args" { error "$test: wrong number args"; return 0 }
        timeout { fail "$test: timeout"; return 0 }
        eof { fail "$test: eof"; api_exit; api_start; return 0 }
    }
}

proc tcl_cmd {command} {
    global prompt
    global spawn_id

    send "[string trim $command]\n"
    expect {
	-re "$prompt$" { return 1}
	"wrong # args" { error "$test: wrong number args"; return 0 }
	timeout { error_and_restart "timeout" }
	eof { api_exit; api_start; return 0 }
    }
}

proc one_line_succeed_test {command} {
    global prompt
    global spawn_id
    global test

    send "[string trim $command]\n"
    expect {
	-re "OK .*$prompt$"		{ pass "$test"; return 1 }
	-re "ERROR .*$prompt$" { 
		fail "$test: $expect_out(buffer)"; return 0
	}
	"wrong # args" { error "$test: wrong number args"; return 0 }
	timeout				{ fail "$test: timeout"; return 0 }
	eof				{ fail "$test: eof"; api_exit; api_start; return 0 }
    }
}

proc one_line_fail_test {command code} {
    global prompt
    global spawn_id
    global test

    send "[string trim $command]\n"
    expect {
	-re "ERROR .*$code.*$prompt$"	{ pass "$test"; return 1 }
	-re "ERROR .*$prompt$"	{ fail "$test: bad failure"; return 0 }
	-re "OK .*$prompt$"		{ fail "$test: bad success"; return 0 }
	"wrong # args" { error "$test: wrong number args"; return 0 }
	timeout				{ fail "$test: timeout"; return 0 }
	eof				{ fail "$test: eof"; api_exit; api_start; return 0 }
    }
}

proc one_line_fail_test_nochk {command} {
    global prompt
    global spawn_id
    global test

    send "[string trim $command]\n"
    expect {
	-re "ERROR .*$prompt$"	{ pass "$test:"; return 1 }
	-re "OK .*$prompt$"		{ fail "$test: bad success"; return 0 }
	"wrong # args" { error "$test: wrong number args"; return 0 }
	timeout				{ fail "$test: timeout"; return 0 }
	eof				{ fail "$test: eof"; api_exit; api_start; return 0 }
    }
}

proc resync {} {
    global prompt
    global spawn_id

    expect {
	-re "$prompt$"	{}
	"wrong # args" { error "$test: wrong number args"; return 0 }
	eof { api_exit; api_start }
    }
}

proc create_principal {name} {
    api_exit
    api_start

    set ret [expr {
	[cmd {
	    ovsec_kadm_init admin admin $OVSEC_KADM_ADMIN_SERVICE null \
		    $OVSEC_KADM_STRUCT_VERSION $OVSEC_KADM_API_VERSION_1 \
		    server_handle
	}] &&
	[cmd [format {
	    ovsec_kadm_create_principal $server_handle [simple_principal \
		    "%s"] {OVSEC_KADM_PRINCIPAL} "%s"
	} $name $name]]
    }]

    cmd {ovsec_kadm_destroy $server_handle}

    api_exit
    api_start

    return $ret
}

proc create_policy {name} {
    api_exit
    api_start

    set ret [expr {
	[cmd {
	    ovsec_kadm_init admin admin $OVSEC_KADM_ADMIN_SERVICE  null \
		    $OVSEC_KADM_STRUCT_VERSION $OVSEC_KADM_API_VERSION_1 \
		    server_handle
	}] &&
	[cmd [format {
	    ovsec_kadm_create_policy $server_handle [simple_policy "%s"] \
		    {OVSEC_KADM_POLICY}
	} $name $name]]
    }]

    cmd {ovsec_kadm_destroy $server_handle}

    api_exit
    api_start

    return $ret
}

proc create_principal_pol {name policy} {
    api_exit
    api_start

    set ret [expr {
	[cmd {
	    ovsec_kadm_init admin admin $OVSEC_KADM_ADMIN_SERVICE  null \
		    $OVSEC_KADM_STRUCT_VERSION $OVSEC_KADM_API_VERSION_1 \
		    server_handle
	}] &&
	[cmd [format {
	    ovsec_kadm_create_principal $server_handle [princ_w_pol "%s" \
		    "%s"] {OVSEC_KADM_PRINCIPAL OVSEC_KADM_POLICY} "%s"
	} $name $policy $name]]
    }]

    cmd {ovsec_kadm_destroy $server_handle}

    api_exit
    api_start

    return $ret
}

proc delete_principal {name} {
    api_exit
    api_start

    set ret [expr {
	[cmd {
	    ovsec_kadm_init admin admin $OVSEC_KADM_ADMIN_SERVICE null \
		    $OVSEC_KADM_STRUCT_VERSION $OVSEC_KADM_API_VERSION_1 \
		    server_handle
	}] &&
	[cmd [format {
	    ovsec_kadm_delete_principal $server_handle "%s"
	} $name]]
    }]

    cmd {ovsec_kadm_destroy $server_handle}

    api_exit
    api_start

    return $ret
}

proc delete_policy {name} {
    api_exit
    api_start

    set ret [expr {
	[cmd {
	    ovsec_kadm_init admin admin $OVSEC_KADM_ADMIN_SERVICE null \
		    $OVSEC_KADM_STRUCT_VERSION $OVSEC_KADM_API_VERSION_1 \
		    server_handle
	}] &&
	[cmd [format {ovsec_kadm_delete_policy $server_handle "%s"} $name]]
    }]

    cmd {ovsec_kadm_destroy $server_handle}

    api_exit
    api_start

    return $ret
}

proc principal_exists {name} {
    api_exit
    api_start

#    puts stdout "Starting principal_exists."

    set ret [expr {
        [cmd {
	    ovsec_kadm_init admin admin $OVSEC_KADM_ADMIN_SERVICE null \
		    $OVSEC_KADM_STRUCT_VERSION $OVSEC_KADM_API_VERSION_1 \
		    server_handle
	}] &&
        [cmd [format {
	    ovsec_kadm_get_principal $server_handle "%s" principal
	} $name]]
    }]

    cmd {ovsec_kadm_destroy $server_handle}

    api_exit
    api_start

#    puts stdout "Finishing principal_exists."

    return $ret
}

proc policy_exists {name} {
    api_exit
    api_start

#    puts stdout "Starting policy_exists."

    set ret [expr {
        [cmd {
	    ovsec_kadm_init admin admin $OVSEC_KADM_ADMIN_SERVICE null \
		    $OVSEC_KADM_STRUCT_VERSION $OVSEC_KADM_API_VERSION_1 \
		    server_handle
	}] &&
        [cmd [format {
	    ovsec_kadm_get_policy $server_handle "%s" policy
	} $name]]
    }]

    cmd {ovsec_kadm_destroy $server_handle}

    api_exit
    api_start

#    puts stdout "Finishing policy_exists."

    return $ret
}

proc error_and_restart {error} {
    api_exit
    api_start
    error $error
}

proc test {name} {
   global test verbose

   set test $name
   if {$verbose >= 1} {
	puts stdout "At $test"
   }
}

proc begin_dump {} {
    global TOP
    global RPC
    
    if { ! $RPC } {
#	exec $env(SIMPLE_DUMP) > /tmp/dump.before
    }
}

proc end_dump_compare {name} {
    global  file
    global  TOP
    global  RPC

    if { ! $RPC } { 
#	set file $TOP/admin/lib/unit-test/diff-files/$name
#	exec $env(SIMPLE_DUMP) > /tmp/dump.after
#	exec $env(COMPARE_DUMP) /tmp/dump.before /tmp/dump.after $file
    }
}

proc kinit { princ pass {opts ""} } {
	global env;
        global KINIT

	eval spawn $KINIT $opts $princ
	expect {
		-re {Password for .*: $}
		    {send "$pass\n"}
		timeout {puts "Timeout waiting for prompt" ; close }
	}

	# this necessary so close(1) in the child will not sleep waiting for
	# the parent, which is us, to read pending data.

	expect {
		eof {}
	}
	wait
}

proc kdestroy {} {
        global KDESTROY
	global errorCode errorInfo
	global env

	if {[info exists errorCode]} {
		set saveErrorCode $errorCode
	}
	if {[info exists errorInfo]} {
		set saveErrorInfo $errorInfo
	}
	catch "system $KDESTROY 2>/dev/null"
	if {[info exists saveErrorCode]} {
		set errorCode $saveErrorCode
	} elseif {[info exists errorCode]} {
		unset errorCode
	}
	if {[info exists saveErrorInfo]} {
		set errorInfo $saveErrorInfo
	} elseif {[info exists errorInfo]} {
		unset errorInfo
	}
}

proc create_principal_with_keysalts {name keysalts} {
    global kadmin_local

    spawn $kadmin_local -e "$keysalts"
    expect {
	"kadmin.local:" {}
	default { error "waiting for kadmin.local prompt"; return 1}
    }
    send "ank -pw \"$name\" \"$name\"\n"
    expect {
	-re "Principal \"$name.*\" created." {}
	"kadmin.local:" {
	    error "expecting principal created message"; 
	    return 1
	}
	default { error "waiting for principal created message"; return 1 }
    }
    expect {
	"kadmin.local:" {}
	default { error "waiting for kadmin.local prompt"; return 1 }
    }
    close
    wait
    return 0
}

    
