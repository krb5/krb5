#include <gssrpc/rpc.h>
#include <kadm5/kadm_rpc.h>
#include <krb5.h>
#include <kadm5/admin.h>
#ifdef HAVE_MEMORY_H
#include <memory.h>
#endif

/* Default timeout can be changed using clnt_control() */
static struct timeval TIMEOUT = { 25, 0 };

generic_ret *
create_principal_1(argp, clnt)
	cprinc_arg *argp;
	CLIENT *clnt;
{
	static generic_ret res;

	memset((char *)&res, 0, sizeof(res));
	if (clnt_call(clnt, CREATE_PRINCIPAL, xdr_cprinc_arg, argp, xdr_generic_ret, &res, TIMEOUT) != RPC_SUCCESS) {
		return (NULL);
	}
	return (&res);
}

generic_ret *
create_principal3_1(argp, clnt)
	cprinc3_arg *argp;
	CLIENT *clnt;
{
	static generic_ret res;

	memset((char *)&res, 0, sizeof(res));
	if (clnt_call(clnt, CREATE_PRINCIPAL3, xdr_cprinc3_arg, argp, xdr_generic_ret, &res, TIMEOUT) != RPC_SUCCESS) {
		return (NULL);
	}
	return (&res);
}

generic_ret *
delete_principal_1(argp, clnt)
	dprinc_arg *argp;
	CLIENT *clnt;
{
	static generic_ret res;

	memset((char *)&res, 0, sizeof(res));
	if (clnt_call(clnt, DELETE_PRINCIPAL, xdr_dprinc_arg, argp, xdr_generic_ret, &res, TIMEOUT) != RPC_SUCCESS) {
		return (NULL);
	}
	return (&res);
}

generic_ret *
modify_principal_1(argp, clnt)
	mprinc_arg *argp;
	CLIENT *clnt;
{
	static generic_ret res;

	memset((char *)&res, 0, sizeof(res));
	if (clnt_call(clnt, MODIFY_PRINCIPAL, xdr_mprinc_arg, argp, xdr_generic_ret, &res, TIMEOUT) != RPC_SUCCESS) {
		return (NULL);
	}
	return (&res);
}

generic_ret *
rename_principal_1(argp, clnt)
	rprinc_arg *argp;
	CLIENT *clnt;
{
	static generic_ret res;

	memset((char *)&res, 0, sizeof(res));
	if (clnt_call(clnt, RENAME_PRINCIPAL, xdr_rprinc_arg, argp, xdr_generic_ret, &res, TIMEOUT) != RPC_SUCCESS) {
		return (NULL);
	}
	return (&res);
}

gprinc_ret *
get_principal_1(argp, clnt)
	gprinc_arg *argp;
	CLIENT *clnt;
{
	static gprinc_ret res;

	memset((char *)&res, 0, sizeof(res));
	if (clnt_call(clnt, GET_PRINCIPAL, xdr_gprinc_arg, argp, xdr_gprinc_ret, &res, TIMEOUT) != RPC_SUCCESS) {
		return (NULL);
	}
	return (&res);
}

gprincs_ret *
get_princs_1(argp, clnt)
	gprincs_arg *argp;
	CLIENT *clnt;
{
	static gprincs_ret res;

	memset((char *)&res, 0, sizeof(res));
	if (clnt_call(clnt, GET_PRINCS, xdr_gprincs_arg, argp,
		      xdr_gprincs_ret, &res, TIMEOUT) != RPC_SUCCESS) { 
	     return (NULL);
	}
	return (&res);
}

generic_ret *
chpass_principal_1(argp, clnt)
	chpass_arg *argp;
	CLIENT *clnt;
{
	static generic_ret res;

	memset((char *)&res, 0, sizeof(res));
	if (clnt_call(clnt, CHPASS_PRINCIPAL, xdr_chpass_arg, argp, xdr_generic_ret, &res, TIMEOUT) != RPC_SUCCESS) {
		return (NULL);
	}
	return (&res);
}

generic_ret *
chpass_principal3_1(argp, clnt)
	chpass3_arg *argp;
	CLIENT *clnt;
{
	static generic_ret res;

	memset((char *)&res, 0, sizeof(res));
	if (clnt_call(clnt, CHPASS_PRINCIPAL3, xdr_chpass3_arg, argp, xdr_generic_ret, &res, TIMEOUT) != RPC_SUCCESS) {
		return (NULL);
	}
	return (&res);
}

generic_ret *
setv4key_principal_1(argp, clnt)
	setv4key_arg *argp;
	CLIENT *clnt;
{
	static generic_ret res;

	memset((char *)&res, 0, sizeof(res));
	if (clnt_call(clnt, SETV4KEY_PRINCIPAL, xdr_setv4key_arg, argp, xdr_generic_ret, &res, TIMEOUT) != RPC_SUCCESS) {
		return (NULL);
	}
	return (&res);
}

generic_ret *
setkey_principal_1(argp, clnt)
	setkey_arg *argp;
	CLIENT *clnt;
{
	static generic_ret res;

	memset((char *)&res, 0, sizeof(res));
	if (clnt_call(clnt, SETKEY_PRINCIPAL, xdr_setkey_arg, argp, xdr_generic_ret, &res, TIMEOUT) != RPC_SUCCESS) {
		return (NULL);
	}
	return (&res);
}

generic_ret *
setkey_principal3_1(argp, clnt)
	setkey3_arg *argp;
	CLIENT *clnt;
{
	static generic_ret res;

	memset((char *)&res, 0, sizeof(res));
	if (clnt_call(clnt, SETKEY_PRINCIPAL3, xdr_setkey3_arg, argp, xdr_generic_ret, &res, TIMEOUT) != RPC_SUCCESS) {
		return (NULL);
	}
	return (&res);
}

chrand_ret *
chrand_principal_1(argp, clnt)
	chrand_arg *argp;
	CLIENT *clnt;
{
	static chrand_ret res;

	memset((char *)&res, 0, sizeof(res));
	if (clnt_call(clnt, CHRAND_PRINCIPAL, xdr_chrand_arg, argp, xdr_chrand_ret, &res, TIMEOUT) != RPC_SUCCESS) {
		return (NULL);
	}
	return (&res);
}

chrand_ret *
chrand_principal3_1(argp, clnt)
	chrand3_arg *argp;
	CLIENT *clnt;
{
	static chrand_ret res;

	memset((char *)&res, 0, sizeof(res));
	if (clnt_call(clnt, CHRAND_PRINCIPAL3, xdr_chrand3_arg, argp, xdr_chrand_ret, &res, TIMEOUT) != RPC_SUCCESS) {
		return (NULL);
	}
	return (&res);
}

generic_ret *
create_policy_1(argp, clnt)
	cpol_arg *argp;
	CLIENT *clnt;
{
	static generic_ret res;

	memset((char *)&res, 0, sizeof(res));
	if (clnt_call(clnt, CREATE_POLICY, xdr_cpol_arg, argp, xdr_generic_ret, &res, TIMEOUT) != RPC_SUCCESS) {
		return (NULL);
	}
	return (&res);
}

generic_ret *
delete_policy_1(argp, clnt)
	dpol_arg *argp;
	CLIENT *clnt;
{
	static generic_ret res;

	memset((char *)&res, 0, sizeof(res));
	if (clnt_call(clnt, DELETE_POLICY, xdr_dpol_arg, argp, xdr_generic_ret, &res, TIMEOUT) != RPC_SUCCESS) {
		return (NULL);
	}
	return (&res);
}

generic_ret *
modify_policy_1(argp, clnt)
	mpol_arg *argp;
	CLIENT *clnt;
{
	static generic_ret res;

	memset((char *)&res, 0, sizeof(res));
	if (clnt_call(clnt, MODIFY_POLICY, xdr_mpol_arg, argp, xdr_generic_ret, &res, TIMEOUT) != RPC_SUCCESS) {
		return (NULL);
	}
	return (&res);
}

gpol_ret *
get_policy_1(argp, clnt)
	gpol_arg *argp;
	CLIENT *clnt;
{
	static gpol_ret res;

	memset((char *)&res, 0, sizeof(res));
	if (clnt_call(clnt, GET_POLICY, xdr_gpol_arg, argp, xdr_gpol_ret, &res, TIMEOUT) != RPC_SUCCESS) {
		return (NULL);
	}
	return (&res);
}

gpols_ret *
get_pols_1(argp, clnt)
	gpols_arg *argp;
	CLIENT *clnt;
{
	static gpols_ret res;

	memset((char *)&res, 0, sizeof(res));
	if (clnt_call(clnt, GET_POLS, xdr_gpols_arg, argp,
		      xdr_gpols_ret, &res, TIMEOUT) != RPC_SUCCESS) { 
	     return (NULL);
	}
	return (&res);
}

getprivs_ret *get_privs_1(argp, clnt)
   void *argp;
   CLIENT *clnt;
{
     static getprivs_ret res;

     memset((char *)&res, 0, sizeof(res));
     if (clnt_call(clnt, GET_PRIVS, xdr_u_int32, argp,
		   xdr_getprivs_ret, &res, TIMEOUT) != RPC_SUCCESS) {
	  return (NULL);
     }
     return (&res);
}

generic_ret *
init_1(argp, clnt)
   void *argp;
   CLIENT *clnt;
{
     static generic_ret res;

     memset((char *)&res, 0, sizeof(res));
     if (clnt_call(clnt, INIT, xdr_u_int32, argp,
		   xdr_generic_ret, &res, TIMEOUT) != RPC_SUCCESS) {
	  return (NULL);
     }
     return (&res);
}
