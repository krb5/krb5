Environment variables
==========================

The following environment variables can be used during runtime:


**KRB5_CONFIG** 
           Main Kerberos configuration file.
           (See :ref:`mitK5defaults` for the default name)

**KRB5_KDC_PROFILE** 
           KDC configuration file.
           (See :ref:`mitK5defaults` for the default name)

**KRB5_KTNAME** 
           Default *keytab* file name.  
           (See :ref:`mitK5defaults` for the default name)

**KRB5CCNAME** 
           Default name for the credentials cache file, in the form *type:residual*. 
           The type of the default cache may determine the availability of a cache collection.
           For instance, a default cache of type DIR causes caches within the directory 
           to be present in the global cache collection.

**KRB5RCACHETYPE**
           Default replay cache type. Defaults to "dfl".

           E.g. *KRB5RCACHETYPE="none"*

**KRB5RCACHENAME** 
           Default replay cache name. 
           (See :ref:`mitK5defaults` for the default name)

**KRB5RCACHEDIR** 
           Default replay cache directory.
           (See :ref:`mitK5defaults` for the default location)

**KPROP_PORT**                     
           *kprop* port to use. Defaults to 754.

**KRB5_TRACE** 
           Debugging and tracing. (Introduced in release 1.9)

           E.g. *KRB5_TRACE=/dev/stdout kinit*

           The setting of this environment variable can be overridden by 
           the tracing behavior set by the application using either of the following API:

               -  :c:func:`krb5_set_trace_callback()` or
               -  :c:func:`krb5_set_trace_filename()`

------------------

Feedback


Please, provide your feedback on this document at krb5-bugs@mit.edu?subject=Documentation___env


