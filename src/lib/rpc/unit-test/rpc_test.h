#ifndef _RPC_TEST_H_RPCGEN
#define	_RPC_TEST_H_RPCGEN

#include <rpc/rpc.h>

#define	RPC_TEST_PROG ((unsigned long)(1000001))
#define	RPC_TEST_VERS_1 ((unsigned long)(1))
#define	RPC_TEST_ECHO ((unsigned long)(1))
extern  char ** rpc_test_echo_1();
extern int rpc_test_prog_1_freeresult();

#endif /* !_RPC_TEST_H_RPCGEN */
