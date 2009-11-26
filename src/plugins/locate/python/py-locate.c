/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 * plugins/locate/python/py-locate.c
 *
 * Copyright 2006, 2007 Massachusetts Institute of Technology.
 * All Rights Reserved.
 *
 * Export of this software from the United States of America may
 *   require a specific license from the United States Government.
 *   It is the responsibility of any person or organization contemplating
 *   export to obtain such a license before exporting.
 *
 * WITHIN THAT CONSTRAINT, permission to use, copy, modify, and
 * distribute this software and its documentation for any purpose and
 * without fee is hereby granted, provided that the above copyright
 * notice appear in all copies and that both that copyright notice and
 * this permission notice appear in supporting documentation, and that
 * the name of M.I.T. not be used in advertising or publicity pertaining
 * to distribution of the software without specific, written prior
 * permission.  Furthermore if you modify this software you must label
 * your software as modified software and not distribute it in such a
 * fashion that it might be confused with the original M.I.T. software.
 * M.I.T. makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 */

/* This is a demo module.  The error checking is incomplete, there's
   no exception handling, and it wouldn't surprise me in the least if
   there are more bugs in the refcount maintenance.

   But it will demonstrate (1) the plugin interface for locating a KDC
   or other Kerberos-related service, and (2) that it's possible for
   these plugins to call out to scripts in various languages for
   prototyping or whatever.

   Some notes:

   If delayed initialization is not done, and the script is executed
   when this module is loaded, loading other Python modules may not
   work, if they include object code referencing the Python symbols.
   Under glibc at least, it appears that the symbols of this module
   aren't available to random dlopen/dlsym calls until loading
   finishes, including the initialization routine.  It's completely
   logical -- in fact, I'd be concerned if it were otherwise.  But not
   obvious if you're not thinking about it.

   Actually, sometimes even with delayed initialization it could be a
   problem.

   You may be able to work around it with something like:
   % env LD_PRELOAD=/usr/lib/libpython2.3.so.1.0 kinit ...blah...

   This module seems rather sensitive to bugs in the Python code.  If
   it's not correct, you may get core dumps, Python GC errors, etc.
   Probably more signs of bugs in this code.

   All of the -1 returns should be cleaned up and made to return
   real error codes, with appropriate output if debugging is enabled.

   Blah.  */

/* Include Python.h before autoconf.h, because our autoconf.h seems
   to confuse Python's headers.  */
#include <autoconf.h>
#if HAVE_PYTHON_H
#include <Python.h>
#elif HAVE_PYTHON2_3_PYTHON_H
#include <python2.3/Python.h>
#elif HAVE_PYTHON2_5_PYTHON_H
#include <python2.5/Python.h>
#else
#error "Where's the Python header file?"
#endif
#include <errno.h>
#include "k5-platform.h"        /* for init/fini macros */
#include "fake-addrinfo.h"

#include <krb5/locate_plugin.h>

#define LIBDIR                  "/tmp" /* should be imported from configure */
#define SCRIPT_PATH             LIBDIR "/krb5/locate-service.py"
#define LOOKUP_FUNC_NAME        "locate"

static PyObject *locatefn;

MAKE_INIT_FUNCTION(my_init);
MAKE_FINI_FUNCTION(my_fini);

#define F       (strchr(__FILE__, '/') ? 1 + strrchr(__FILE__, '/') : __FILE__)

static krb5_context sctx;       /* XXX ugly hack! */

int
my_init(void)
{
    PyObject *mainmodule;
    FILE *f;

    Py_Initialize ();
//    fprintf(stderr, "trying to load %s\n", SCRIPT_PATH);
    f = fopen(SCRIPT_PATH, "r");
    if (f == NULL) {
        if (sctx)
            krb5_set_error_message(sctx, -1,
                                   "couldn't open Python script %s (%s)",
                                   SCRIPT_PATH, strerror(errno));
        return -1;
    }
    set_cloexec_file(f);
    PyRun_SimpleFile (f, SCRIPT_PATH);
    fclose(f);
    mainmodule = PyModule_GetDict(PyImport_AddModule("__main__"));
    if (PyErr_Occurred()) { fprintf(stderr,"%s:%d: python error\n", F, __LINE__); PyErr_Print(); return -1; }
    locatefn = PyDict_GetItemString (mainmodule, LOOKUP_FUNC_NAME);
    if (PyErr_Occurred()) { fprintf(stderr,"%s:%d: python error\n", F, __LINE__); PyErr_Print(); return -1; }
    /* Don't DECREF mainmodule, it's sometimes causing crashes.  */
    if (locatefn == 0)
        return -1;
    if (!PyCallable_Check (locatefn)) {
        Py_DECREF (locatefn);
        locatefn = 0;
        return -1;
    }
    if (PyErr_Occurred()) { fprintf(stderr,"%s:%d: python error\n", F, __LINE__); PyErr_Print(); return -1; }
    return 0;
}

void
my_fini(void)
{
//    fprintf(stderr, "%s:%d: Python module finalization\n", F, __LINE__);
    if (! INITIALIZER_RAN (my_init))
        return;
    Py_DECREF (locatefn);
    locatefn = 0;
    Py_Finalize ();
}

static krb5_error_code
ctxinit(krb5_context ctx, void **blobptr)
{
    /* If we wanted to create a separate Python interpreter instance,
       look up the pathname of the script in the config file used for
       the current krb5_context, and load the script in that
       interpreter, this would be a good place for it; the blob could
       be allocated to hold the reference to the interpreter
       instance.  */
    *blobptr = ctx;
    return 0;
}

static void
ctxfini(void *blob)
{
}

/* Special return codes:

   0: We set a (possibly empty) set of server locations in the result
   field.  If the server location set is empty, that means there
   aren't any servers, *not* that we should try the krb5.conf file or
   DNS or something.

   KRB5_PLUGIN_NO_HANDLE: This realm or service isn't handled here,
   try some other means.

   Other: Some error happened here.  It may be reported, if the
   service can't be located by other means.  (In this implementation,
   the catch-all error code returned in a bunch of places is -1, which
   isn't going to be very useful to the caller.)  */

static krb5_error_code
lookup(void *blob, enum locate_service_type svc, const char *realm,
       int socktype, int family,
       int (*cbfunc)(void *, int, struct sockaddr *), void *cbdata)
{
    PyObject *py_result, *svcarg, *realmarg, *arglist;
    int listsize, i, x;
    struct addrinfo aihints, *airesult;
    int thissocktype;

//    fprintf(stderr, "%s:%d: lookup(%d,%s,%d,%d)\n", F, __LINE__,
//          svc, realm, socktype, family);
    sctx = blob;                /* XXX: Not thread safe!  */
    i = CALL_INIT_FUNCTION (my_init);
    if (i) {
#if 0
        fprintf(stderr, "%s:%d: module initialization failed\n", F, __LINE__);
#endif
        return i;
    }
    if (locatefn == 0)
        return KRB5_PLUGIN_NO_HANDLE;
    svcarg = PyInt_FromLong (svc);
    /* error? */
    realmarg = PyString_FromString ((char *) realm);
    /* error? */
    arglist = PyTuple_New (4);
    /* error? */

    PyTuple_SetItem (arglist, 0, svcarg);
    PyTuple_SetItem (arglist, 1, realmarg);
    PyTuple_SetItem (arglist, 2, PyInt_FromLong (socktype));
    PyTuple_SetItem (arglist, 3, PyInt_FromLong (family));
    /* references handed off, no decref */

    py_result = PyObject_CallObject (locatefn, arglist);
    Py_DECREF (arglist);
    if (PyErr_Occurred()) {
        fprintf(stderr,"%s:%d: python error\n", F, __LINE__);
        PyErr_Print();
        krb5_set_error_message(blob, -1,
                               "Python evaluation error, see stderr");
        return -1;
    }
    if (py_result == 0) {
        fprintf(stderr, "%s:%d: returned null object\n", F, __LINE__);
        return -1;
    }
    if (py_result == Py_False)
        return KRB5_PLUGIN_NO_HANDLE;
    if (! PyList_Check (py_result)) {
        Py_DECREF (py_result);
        fprintf(stderr, "%s:%d: returned non-list, non-False\n", F, __LINE__);
        krb5_set_error_message(blob, -1,
                               "Python script error -- returned non-list, non-False result");
        return -1;
    }
    listsize = PyList_Size (py_result);
    /* allocate */
    memset(&aihints, 0, sizeof(aihints));
    aihints.ai_flags = AI_NUMERICHOST;
    aihints.ai_family = family;
    for (i = 0; i < listsize; i++) {
        PyObject *answer, *field;
        char *hoststr, *portstr, portbuf[3*sizeof(long) + 4];
        int cbret;

        answer = PyList_GetItem (py_result, i);
        if (! PyTuple_Check (answer)) {
            krb5_set_error_message(blob, -1,
                                   "Python script error -- returned item %d not a tuple", i);
            /* leak?  */
            return -1;
        }
        if (PyTuple_Size (answer) != 3) {
            krb5_set_error_message(blob, -1,
                                   "Python script error -- returned tuple %d size %d should be 3",
                                   i, PyTuple_Size (answer));
            /* leak?  */
            return -1;
        }
        field = PyTuple_GetItem (answer, 0);
        if (! PyString_Check (field)) {
            /* leak?  */
            krb5_set_error_message(blob, -1,
                                   "Python script error -- first component of tuple %d is not a string",
                                   i);
            return -1;
        }
        hoststr = PyString_AsString (field);
        field = PyTuple_GetItem (answer, 1);
        if (PyString_Check (field)) {
            portstr = PyString_AsString (field);
        } else if (PyInt_Check (field)) {
            snprintf(portbuf, sizeof(portbuf), "%ld", PyInt_AsLong (field));
            portstr = portbuf;
        } else {
            krb5_set_error_message(blob, -1,
                                   "Python script error -- second component of tuple %d neither a string nor an integer",
                                   i);
            /* leak?  */
            return -1;
        }
        field = PyTuple_GetItem (answer, 2);
        if (! PyInt_Check (field)) {
            krb5_set_error_message(blob, -1,
                                   "Python script error -- third component of tuple %d not an integer",
                                   i);
            /* leak?  */
            return -1;
        }
        thissocktype = PyInt_AsLong (field);
        switch (thissocktype) {
        case SOCK_STREAM:
        case SOCK_DGRAM:
            /* okay */
            if (socktype != 0 && socktype != thissocktype) {
                krb5_set_error_message(blob, -1,
                                       "Python script error -- tuple %d has socket type %d, should only have %d",
                                       i, thissocktype, socktype);
                /* leak?  */
                return -1;
            }
            break;
        default:
            /* 0 is not acceptable */
            krb5_set_error_message(blob, -1,
                                   "Python script error -- tuple %d has invalid socket type %d",
                                   i, thissocktype);
            /* leak?  */
            return -1;
        }
        aihints.ai_socktype = thissocktype;
        x = getaddrinfo (hoststr, portstr, &aihints, &airesult);
        if (x != 0)
            continue;
        cbret = cbfunc(cbdata, airesult->ai_socktype, airesult->ai_addr);
        freeaddrinfo(airesult);
        if (cbret != 0)
            break;
    }
    Py_DECREF (py_result);
    return 0;
}

const krb5plugin_service_locate_ftable service_locator = {
    /* version */
    0,
    /* functions */
    ctxinit, ctxfini, lookup,
};
