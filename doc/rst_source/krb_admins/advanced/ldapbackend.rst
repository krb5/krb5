.. _ldap_be_ubuntu:

LDAP backend on Ubuntu 10.4 (lucid)
====================================

Setting up Kerberos v1.9 with LDAP backend on Ubuntu 10.4 (lucid Lynx)

Prerequisites:
--------------

Install the following packages: *slapd, ldap-utils* and *libldap2-dev*

You can install the necessary packages with these commands::

   sudo apt-get install slapd
   sudo apt-get install ldap-utils
   sudo apt-get install libldap2-dev

Extend the user schema using schemas from standart OpenLDAP distribution: *cosine, mics, nis, inetcomperson* ::

   ldapadd -Y EXTERNAL -H ldapi:/// -f /etc/ldap/schema/cosine.ldif
   ldapadd -Y EXTERNAL -H ldapi:/// -f /etc/ldap/schema/mics.ldif
   ldapadd -Y EXTERNAL -H ldapi:/// -f /etc/ldap/schema/nis.ldif
   ldapadd -Y EXTERNAL -H ldapi:/// -f /etc/ldap/schema/inetcomperson.ldif
 
Building Kerberos from source:
------------------------------

::

   util/reconf
   ./configure –with-ldap
   make
   sudo make install

.. note:: in some environments one may need to suppress *rpath* linker option: *./configure –with-ldap –disable-rpath*

Setting up Kerberos:
--------------------------------

Configuration:
~~~~~~~~~~~~~~
 
Update Kerberos configuration files  with the backend information:

krb5.conf:: 

   [realms]
        EXAMPLE.COM = {
                database_module = LDAP
        }

   [dbdefaults]
        ldap_kerberos_container_dn = "cn=krbContainer,dc=example,dc=com"

   [dbmodules]
        LDAP = {
           db_library = kldap
           ldap_kerberos_container_dn = "cn=krbContainer,dc=example,dc=com"
           ldap_kdc_dn = cn=admin,dc=example,dc=com
           ldap_kadmind_dn = cn=admin,dc=example,dc=com
           ldap_service_password_file = /tmp/krb5kdc/admin.stash
           ldap_servers = ldapi:///
        }


kdc.conf::

   [realms]
        EXAMPLE.COM = {
                acl_file = /tmp/kadm5.acl

 
kadm5.acl::

   # See Kerberos V5 Installation Guide for detail of ACL setup and configuration
   */admin *

Setup run-time environment to point to the Kerberos configuration files::

   export KRB5_CONFIG=/tmp/krb5.conf
   export KRB5_KDC_PROFILE=/tmp/kdc.conf


Schema:
~~~~~~~

From the source tree copy *src/plugins/kdb/ldap/libkdb_ldap/kerberos.schema* into */etc/ldap/schema*

Warning:: it should be done after slapd is installed to avoid problems with slapd installation

To convert *kerberos.schema* to run-time configuration (cn=config) do the folowing:

#. create temporary file /tmp/schema_convert.conf with the following content::

     include /etc/ldap/schema/kerberos.schema

#. Create temporary directory  */tmp/krb5_ldif*

#. Run::
    
     slaptest -f /tmp/schema_convert.conf -F /tmp/krb5_ldif

   It should result into a  new file */tmp/krb5_ldif/cn=config/cn=schema/cn={0}kerberos.ldif*

#. Edit /tmp/krb5_ldif/cn=config/cn=schema/cn={0}kerberos.ldif by replacing lines::

     dn: cn={0}kerberos 
     cn: {0}kerberos

     with

     dn: cn=kerberos,cn=schema,cn=config
     cn: kerberos

   Also, remove following attribute-value pairs::
 
     structuralObjectClass: olcSchemaConfig
     entryUUID: ...
     creatorsName: cn=config
     createTimestamp: ...
     entryCSN: ...
     modifiersName: cn=config
     modifyTimestamp: ...

#. Load the new schema with ldapadd (with the proper authentication)::

     ldapadd -Y EXTERNAL -H ldapi:/// -f  /tmp/krb5_ldif/cn=config/cn=schema/cn={0}kerberos.ldif

  which should result into *adding new entry "cn=kerberos,cn=schema,cn=config"* message 
   

Create Kerberos database:
-------------------------

Using LDAP administrator credentials, create Kerberos database and stash::

     kdb5_ldap_util -D cn=admin,dc=example,dc=com -H ldapi:/// create

   
Stash the password::

   kdb5_ldap_util -D cn=admin,dc=example,dc=com -H ldapi:/// stashsrvpw cn=admin,dc=example,dc=com


Start kdc::   

   krb5kdc
 

To destroy database run::
 
   kdb5_ldap_util -D cn=admin,dc=example,dc=com -H ldapi:/// destroy -f


Useful references:
-------------------

* `Kerberos and LDAP <https://help.ubuntu.com/10.04/serverguide/C/kerberos-ldap.html>`_

------------------

Feedback:

Please, provide your feedback on this document at krb5-bugs@mit.edu?subject=Documentation___ldap_be_ubuntu


