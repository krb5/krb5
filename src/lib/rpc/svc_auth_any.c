/*
 * svc_auth_any.c
 * Provides default service-side functions for authentication flavors
 * that do not use all the fields in struct svc_auth_ops.
 *
 * Copyright 1993 OpenVision Technologies, Inc., All Rights Reserved.
 */

#include <stdio.h>
#include <rpc/rpc.h>

extern int authany_wrap();

struct svc_auth_ops svc_auth_any_ops = {
     authany_wrap,
     authany_wrap,
};

SVCAUTH svc_auth_any = {
     &svc_auth_any_ops,
     NULL,
};
