/*
 * Copyright (c) 2005 Massachusetts Institute of Technology
 *
 * Permission is hereby granted, free of charge, to any person
 * obtaining a copy of this software and associated documentation
 * files (the "Software"), to deal in the Software without
 * restriction, including without limitation the rights to use, copy,
 * modify, merge, publish, distribute, sublicense, and/or sell copies
 * of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

/* $Id$ */

#ifndef __KHIMAIRA_CONFIGUI_H
#define __KHIMAIRA_CONFIGUI_H

typedef struct tag_cfg_node_data {
    void *      key;
    HWND        hwnd;
    LPARAM      param;
    khm_int32   flags;
} cfg_node_data;

typedef struct tag_khui_config_node_i {
    khm_int32   magic;

    khui_config_node_reg reg;
    kmm_plugin  owner;
    khm_int32   id;

    HWND        hwnd;
    LPARAM      param;

    cfg_node_data * data;
    khm_size    n_data;
    khm_size    nc_data;

    khm_int32   refcount;
    khm_int32   flags;
    TDCL(struct tag_khui_config_node_i);
} khui_config_node_i;

#define KHUI_CONFIG_NODE_MAGIC 0x38f4cb52

#define KHUI_NODEDATA_ALLOC_INCR 8

#define KHUI_CN_FLAG_DELETED 0x0008

#define cfgui_is_valid_node_handle(v) \
((v) && ((khui_config_node_i *) (v))->magic == KHUI_CONFIG_NODE_MAGIC)

#define cfgui_is_valid_node(n) \
((n)->magic == KHUI_CONFIG_NODE_MAGIC)

#define cfgui_node_i_from_handle(v) \
((khui_config_node_i *) v)

#define cfgui_handle_from_node_i(n) \
((khui_config_node) n)

#endif
