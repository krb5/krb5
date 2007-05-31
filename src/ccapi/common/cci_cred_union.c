/*
 * $Header$
 *
 * Copyright 2006 Massachusetts Institute of Technology.
 * All Rights Reserved.
 *
 * Export of this software from the United States of America may
 * require a specific license from the United States Government.
 * It is the responsibility of any person or organization contemplating
 * export to obtain such a license before exporting.
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

#include "cci_common.h"

#pragma mark - 

/* ------------------------------------------------------------------------ */

static cc_uint32 cci_credentials_v4_release (cc_credentials_v4_t *io_v4creds)
{
    cc_int32 err = ccNoError;
    
    if (!io_v4creds) { err = ccErrBadParam; }
    
    if (!err) {
        memset (io_v4creds, 0, sizeof (*io_v4creds));
        free (io_v4creds);
    }
    
    return err;
}

/* ------------------------------------------------------------------------ */

static cc_uint32 cci_credentials_v4_read (cc_credentials_v4_t **out_v4creds,
                                          cci_stream_t          io_stream)
{
    cc_int32 err = ccNoError;
    cc_credentials_v4_t *v4creds = NULL;
    
    if (!io_stream  ) { err = cci_check_error (ccErrBadParam); }
    if (!out_v4creds) { err = cci_check_error (ccErrBadParam); }
    
    if (!err) {
        v4creds = malloc (sizeof (*v4creds));
        if (!v4creds) { err = cci_check_error (ccErrNoMem); }
    }
    
    if (!err) {
        err = cci_stream_read_uint32 (io_stream, &v4creds->version);
    }
    
    if (!err) {
        err = cci_stream_read (io_stream, v4creds->principal, cc_v4_name_size);
    }
    
    if (!err) {
        err = cci_stream_read (io_stream, v4creds->principal_instance, cc_v4_instance_size);
    }
    
    if (!err) {
        err = cci_stream_read (io_stream, v4creds->service, cc_v4_name_size);
    }
    
    if (!err) {
        err = cci_stream_read (io_stream, v4creds->service_instance, cc_v4_instance_size);
    }
    
    if (!err) {
        err = cci_stream_read (io_stream, v4creds->realm, cc_v4_realm_size);
    }
    
    if (!err) {
        err = cci_stream_read (io_stream, v4creds->session_key, cc_v4_key_size);
    }
    
    if (!err) {
        err = cci_stream_read_int32 (io_stream, &v4creds->kvno);
    }
    
    if (!err) {
        err = cci_stream_read_int32 (io_stream, &v4creds->string_to_key_type);
    }
    
    if (!err) {
        err = cci_stream_read_time (io_stream, &v4creds->issue_date);
    }
    
    if (!err) {
        err = cci_stream_read_int32 (io_stream, &v4creds->lifetime);
    }
    
    if (!err) {
        err = cci_stream_read_uint32 (io_stream, &v4creds->address);
    }
    
    if (!err) {
        err = cci_stream_read_int32 (io_stream, &v4creds->ticket_size);
    }
    
    if (!err) {
        err = cci_stream_read (io_stream, v4creds->ticket, cc_v4_ticket_size);
    }
    
    if (!err) {
        *out_v4creds = v4creds;
        v4creds = NULL;
    }
    
    free (v4creds);
    
    return cci_check_error (err);
}

/* ------------------------------------------------------------------------ */

static cc_uint32 cci_credentials_v4_write (cc_credentials_v4_t *in_v4creds,
                                           cci_stream_t         io_stream)
{
    cc_int32 err = ccNoError;
    
    if (!io_stream ) { err = cci_check_error (ccErrBadParam); }
    if (!in_v4creds) { err = cci_check_error (ccErrBadParam); }
    
    if (!err) {
        err = cci_stream_write_uint32 (io_stream, in_v4creds->version);
    }
    
    if (!err) {
        err = cci_stream_write (io_stream, in_v4creds->principal, cc_v4_name_size);
    }
    
    if (!err) {
        err = cci_stream_write (io_stream, in_v4creds->principal_instance, cc_v4_instance_size);
    }
    
    if (!err) {
        err = cci_stream_write (io_stream, in_v4creds->service, cc_v4_name_size);
    }
    
    if (!err) {
        err = cci_stream_write (io_stream, in_v4creds->service_instance, cc_v4_instance_size);
    }
    
    if (!err) {
        err = cci_stream_write (io_stream, in_v4creds->realm, cc_v4_realm_size);
    }
    
    if (!err) {
        err = cci_stream_write (io_stream, in_v4creds->session_key, cc_v4_key_size);
    }
    
    if (!err) {
        err = cci_stream_write_int32 (io_stream, in_v4creds->kvno);
    }
    
    if (!err) {
        err = cci_stream_write_int32 (io_stream, in_v4creds->string_to_key_type);
    }
    
    if (!err) {
        err = cci_stream_write_time (io_stream, in_v4creds->issue_date);
    }
    
    if (!err) {
        err = cci_stream_write_int32 (io_stream, in_v4creds->lifetime);
    }
    
    if (!err) {
        err = cci_stream_write_uint32 (io_stream, in_v4creds->address);
    }
    
    if (!err) {
        err = cci_stream_write_int32 (io_stream, in_v4creds->ticket_size);
    }
    
    if (!err) {
        err = cci_stream_write (io_stream, in_v4creds->ticket, cc_v4_ticket_size);
    }
    
    return cci_check_error (err);
}

#pragma mark - 

/* ------------------------------------------------------------------------ */

static cc_uint32 cci_cc_data_contents_release (cc_data *io_ccdata)
{
    cc_int32 err = ccNoError;
    
    if (!io_ccdata && io_ccdata->data) { err = ccErrBadParam; }
    
    if (!err) {
        if (io_ccdata->length) {
            memset (io_ccdata->data, 0, io_ccdata->length);
        }
        free (io_ccdata->data);
    }
    
    return err;
}

/* ------------------------------------------------------------------------ */

static cc_uint32 cci_cc_data_release (cc_data *io_ccdata)
{
    cc_int32 err = ccNoError;
    
    if (!io_ccdata) { err = ccErrBadParam; }
    
    if (!err) {
        cci_cc_data_contents_release (io_ccdata);
        free (io_ccdata);
    }
    
    return err;
}

/* ------------------------------------------------------------------------ */

static cc_uint32 cci_cc_data_read (cc_data      *io_ccdata,
                                   cci_stream_t  io_stream)
{
    cc_int32 err = ccNoError;
    cc_uint32 type = 0;
    cc_uint32 length = 0;
    char *data = NULL;
    
    if (!io_stream) { err = cci_check_error (ccErrBadParam); }
    if (!io_ccdata) { err = cci_check_error (ccErrBadParam); }
    
    if (!err) {
        err = cci_stream_read_uint32 (io_stream, &type);
    }
    
    if (!err) {
        err = cci_stream_read_uint32 (io_stream, &length);
    }
    
    if (!err && length > 0) {
        data = malloc (length);
        if (!data) { err = cci_check_error (ccErrNoMem); }

        if (!err) {
            err = cci_stream_read (io_stream, data, length);
        }
    }
    
    if (!err) {
        io_ccdata->type = type;
        io_ccdata->length = length;
        io_ccdata->data = data;
        data = NULL;
    }
    
    free (data);
    
    return cci_check_error (err);
}

/* ------------------------------------------------------------------------ */

static cc_uint32 cci_cc_data_write (cc_data      *in_ccdata,
                                    cci_stream_t  io_stream)
{
    cc_int32 err = ccNoError;
    
    if (!io_stream) { err = cci_check_error (ccErrBadParam); }
    if (!in_ccdata) { err = cci_check_error (ccErrBadParam); }
    
    if (!err) {
        err = cci_stream_write_uint32 (io_stream, in_ccdata->type);
    }
    
    if (!err) {
        err = cci_stream_write_uint32 (io_stream, in_ccdata->length);
    }
    
    if (!err && in_ccdata->length > 0) {
        err = cci_stream_write (io_stream, in_ccdata->data, in_ccdata->length);
    }
    
    return cci_check_error (err);
}

#pragma mark - 

/* ------------------------------------------------------------------------ */

static cc_uint32 cci_cc_data_array_release (cc_data **io_ccdata_array)
{
    cc_int32 err = ccNoError;
    
    if (!io_ccdata_array) { err = ccErrBadParam; }
    
    if (!err) {
        cc_uint32 i;
        
        for (i = 0; io_ccdata_array && io_ccdata_array[i]; i++) {
            cci_cc_data_release (io_ccdata_array[i]);
        }
        free (io_ccdata_array);        
    }
    
    return err;
}

/* ------------------------------------------------------------------------ */

static cc_uint32 cci_cc_data_array_read (cc_data      ***io_ccdata_array,
                                         cci_stream_t    io_stream)
{
    cc_int32 err = ccNoError;
    cc_uint32 count = 0;
    cc_data **array = NULL;
    cc_uint32 i;
    
    if (!io_stream      ) { err = cci_check_error (ccErrBadParam); }
    if (!io_ccdata_array) { err = cci_check_error (ccErrBadParam); }
    
    if (!err) {
        err = cci_stream_read_uint32 (io_stream, &count);
    }
    
    if (!err && count > 0) {
        array = malloc ((count + 1) * sizeof (*array));
        if (array) { 
            for (i = 0; i <= count; i++) { array[i] = NULL; }
        } else {
            err = cci_check_error (ccErrNoMem); 
        }
    }
    
    if (!err) {
        for (i = 0; !err && i < count; i++) {
            array[i] = malloc (sizeof (cc_data));
            if (!array[i]) { err = cci_check_error (ccErrNoMem); }
            
            if (!err) {
                err = cci_cc_data_read (array[i], io_stream);
            }
        }
    }
    
    if (!err) {
        *io_ccdata_array = array;
        array = NULL;
    }
    
    cci_cc_data_array_release (array);
    
    return cci_check_error (err);
}

/* ------------------------------------------------------------------------ */

static cc_uint32 cci_cc_data_array_write (cc_data      **in_ccdata_array,
                                          cci_stream_t   io_stream)
{
    cc_int32 err = ccNoError;
    cc_uint32 count = 0;
    
    if (!io_stream) { err = cci_check_error (ccErrBadParam); }
    /* in_ccdata_array may be NULL */
    
    if (!err) {
        for (count = 0; in_ccdata_array && in_ccdata_array[count]; count++);
        
        err = cci_stream_write_uint32 (io_stream, count);
    }
    
    if (!err) {
        cc_uint32 i;
        
        for (i = 0; !err && i < count; i++) {
            err = cci_cc_data_write (in_ccdata_array[i], io_stream);
        }            
    }
    
    return cci_check_error (err);
}

#pragma mark - 

/* ------------------------------------------------------------------------ */

cc_credentials_v5_t cci_credentials_v5_initializer = {
    NULL,
    NULL,
    { 0, 0, NULL },
    0, 0, 0, 0, 0, 0, 
    NULL,
    { 0, 0, NULL },
    { 0, 0, NULL },
    NULL
};

/* ------------------------------------------------------------------------ */

static cc_uint32 cci_credentials_v5_release (cc_credentials_v5_t *io_v5creds)
{
    cc_int32 err = ccNoError;
    
    if (!io_v5creds) { err = ccErrBadParam; }
    
    if (!err) {
        free (io_v5creds->client);
        free (io_v5creds->server);
        cci_cc_data_contents_release (&io_v5creds->keyblock);
        cci_cc_data_array_release (io_v5creds->addresses);
        cci_cc_data_contents_release (&io_v5creds->ticket);
        cci_cc_data_contents_release (&io_v5creds->second_ticket);
        cci_cc_data_array_release (io_v5creds->authdata);
        free (io_v5creds);        
    }
    
    return err;
}

/* ------------------------------------------------------------------------ */

static cc_uint32 cci_credentials_v5_read (cc_credentials_v5_t **out_v5creds,
                                          cci_stream_t          io_stream)
{
    cc_int32 err = ccNoError;
    cc_credentials_v5_t *v5creds = NULL;
    
    if (!io_stream  ) { err = cci_check_error (ccErrBadParam); }
    if (!out_v5creds) { err = cci_check_error (ccErrBadParam); }
    
    if (!err) {
        v5creds = malloc (sizeof (*v5creds));
        if (v5creds) { 
            *v5creds = cci_credentials_v5_initializer;
        } else {
            err = cci_check_error (ccErrNoMem); 
        }
    }
    
    if (!err) {
        err = cci_stream_read_string (io_stream, &v5creds->client);
    }
    
    if (!err) {
        err = cci_stream_read_string (io_stream, &v5creds->server);
    }
    
    if (!err) {
        err = cci_cc_data_read (&v5creds->keyblock, io_stream);
    }
    
    if (!err) {
        err = cci_stream_read_time (io_stream, &v5creds->authtime);
    }
    
    if (!err) {
        err = cci_stream_read_time (io_stream, &v5creds->starttime);
    }
    
    if (!err) {
        err = cci_stream_read_time (io_stream, &v5creds->endtime);
    }
    
    if (!err) {
        err = cci_stream_read_time (io_stream, &v5creds->renew_till);
    }
    
    if (!err) {
        err = cci_stream_read_uint32 (io_stream, &v5creds->is_skey);
    }
    
    if (!err) {
        err = cci_stream_read_uint32 (io_stream, &v5creds->ticket_flags);
    }
    
    if (!err) {
        err = cci_cc_data_array_read (&v5creds->addresses, io_stream);
    }
        
    if (!err) {
        err = cci_cc_data_read (&v5creds->ticket, io_stream);
    }
    
    if (!err) {
        err = cci_cc_data_read (&v5creds->second_ticket, io_stream);
    }
    
    if (!err) {
        err = cci_cc_data_array_read (&v5creds->authdata, io_stream);
    }
    
    if (!err) {
        *out_v5creds = v5creds;
        v5creds = NULL;
    }
    
    cci_credentials_v5_release (v5creds);
    
    return cci_check_error (err);
}

/* ------------------------------------------------------------------------ */

static cc_uint32 cci_credentials_v5_write (cc_credentials_v5_t *in_v5creds,
                                           cci_stream_t         io_stream)
{
    cc_int32 err = ccNoError;
    
    if (!io_stream ) { err = cci_check_error (ccErrBadParam); }
    if (!in_v5creds) { err = cci_check_error (ccErrBadParam); }
    
    if (!err) {
        err = cci_stream_write_string (io_stream, in_v5creds->client);
    }
    
    if (!err) {
        err = cci_stream_write_string (io_stream, in_v5creds->server);
    }
    
    if (!err) {
        err = cci_cc_data_write (&in_v5creds->keyblock, io_stream);
    }
    
    if (!err) {
        err = cci_stream_write_time (io_stream, in_v5creds->authtime);
    }
    
    if (!err) {
        err = cci_stream_write_time (io_stream, in_v5creds->starttime);
    }
    
    if (!err) {
        err = cci_stream_write_time (io_stream, in_v5creds->endtime);
    }
    
    if (!err) {
        err = cci_stream_write_time (io_stream, in_v5creds->renew_till);
    }
    
    if (!err) {
        err = cci_stream_write_uint32 (io_stream, in_v5creds->is_skey);
    }
    
    if (!err) {
        err = cci_stream_write_uint32 (io_stream, in_v5creds->ticket_flags);
    }
    
    if (!err) {
        err = cci_cc_data_array_write (in_v5creds->addresses, io_stream);
    }
    
    if (!err) {
        err = cci_cc_data_write (&in_v5creds->ticket, io_stream);
    }
    
    if (!err) {
        err = cci_cc_data_write (&in_v5creds->second_ticket, io_stream);
    }
    
    if (!err) {
        err = cci_cc_data_array_write (in_v5creds->authdata, io_stream);
    }
    
    
    return cci_check_error (err);
}

#pragma mark - 

/* ------------------------------------------------------------------------ */

cc_uint32 cci_cred_union_release (cc_credentials_union *io_cred_union)
{
    cc_int32 err = ccNoError;
    
    if (!io_cred_union) { err = ccErrBadParam; }
    
    if (!err) {
        if (io_cred_union->version == cc_credentials_v4) {
            cci_credentials_v4_release (io_cred_union->credentials.credentials_v4);
        } else if (io_cred_union->version == cc_credentials_v5) {
            cci_credentials_v5_release (io_cred_union->credentials.credentials_v5);
        }
        free (io_cred_union);
    }
    
    return err;
}

/* ------------------------------------------------------------------------ */

cc_uint32 cci_cred_union_read (cc_credentials_union **out_credentials_union,
                               cci_stream_t           io_stream)
{
    cc_int32 err = ccNoError;
    cc_credentials_union *cred_union = NULL;
    
    if (!io_stream            ) { err = cci_check_error (ccErrBadParam); }
    if (!out_credentials_union) { err = cci_check_error (ccErrBadParam); }
    
    if (!err) {
        cred_union = malloc (sizeof (*cred_union));
        if (!cred_union) { err = cci_check_error (ccErrNoMem); }
    }
    
    if (!err) {
        err = cci_stream_read_uint32 (io_stream, &cred_union->version);
    }
    
    if (!err) {
        if (cred_union->version == cc_credentials_v4) {
            err = cci_credentials_v4_read (&cred_union->credentials.credentials_v4,
                                           io_stream);
        
        } else if (cred_union->version == cc_credentials_v5) {
            err = cci_credentials_v5_read (&cred_union->credentials.credentials_v5,
                                           io_stream);
           
        
        } else {
            err = ccErrBadCredentialsVersion;
        }
    }
    
    if (!err) {
        *out_credentials_union = cred_union;
        cred_union = NULL;
    }
    
    if (cred_union) { cci_cred_union_release (cred_union); }
    
    return cci_check_error (err);
}

/* ------------------------------------------------------------------------ */

cc_uint32 cci_cred_union_write (const cc_credentials_union *in_credentials_union,
                                cci_stream_t                io_stream)
{
    cc_int32 err = ccNoError;
    
    if (!io_stream           ) { err = cci_check_error (ccErrBadParam); }
    if (!in_credentials_union) { err = cci_check_error (ccErrBadParam); }
    
    if (!err) {
        err = cci_stream_write_uint32 (io_stream, in_credentials_union->version);
    }
    
    if (!err) {
        if (in_credentials_union->version == cc_credentials_v4) {
            err = cci_credentials_v4_write (in_credentials_union->credentials.credentials_v4,
                                            io_stream);
            
        } else if (in_credentials_union->version == cc_credentials_v5) {
            err = cci_credentials_v5_write (in_credentials_union->credentials.credentials_v5,
                                            io_stream);
            
        } else {
            err = ccErrBadCredentialsVersion;
        }
    }
    
    return cci_check_error (err);    
}
