.. _edir_mod_realm_label:


eDir: Modifying a Kerberos realm
=================================

See :ref:`ldap_mod_realm_label`

The following are the eDirectory specific options


========================================= ================================================
-kdcdn *kdc_service_list*                   Specifies the list of KDC service objects serving the realm. The list contains the DNs of the KDC service objects separated by a colon (:). This list replaces the existing list. 
-clearkdcdn *kdc_service_list*               Specifies the list of KDC service objects that need to be removed from the existing list. The list contains the DNs of the KDC service objects separated by a colon (:). 
-addkdcdn *kdc_service_list*                 Specifies the list of KDC service objects that need to be added to the existing list. The list contains the DNs of the KDC service objects separated by a colon (:). 
-admindn *admin_service_list*               Specifies the list of Administration service objects serving the realm. The list contains the DNs of the Administration service objects separated by a colon (:). This list replaces the existing list. 
-clearadmindn *admin_service_list*          Specifies the list of Administration service objects that need to be removed from the existing list. The list contains the DNs of the Administration service objects separated by a colon (:). 
-addadmindn *admin_service_list*           Specifies the list of Administration service objects that need to be added to the existing list. The list contains the DNs of the Administration service objects separated by a colon (:). 
========================================= ================================================



------------

Feedback:

Please, provide your feedback at krb5-bugs@mit.edu?subject=Documentation___edir


