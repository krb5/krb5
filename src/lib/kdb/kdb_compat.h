
/*
 * Note --- this structure cannot be modified without changing the
 * database version number in libkdb.a
 */
typedef struct _old_krb5_db_entry {
    old_krb5_principal principal;
    old_krb5_encrypted_keyblock key;
    krb5_kvno kvno;
    krb5_deltat	max_life;
    krb5_deltat	max_renewable_life;
    krb5_kvno mkvno;			/* master encryption key vno */
    
    krb5_timestamp expiration;		/* This is when the client expires */
    krb5_timestamp pw_expiration; 	/* This is when its password does */
    krb5_timestamp last_pwd_change; 	/* Last time of password change  */
    krb5_timestamp last_success;	/* Last successful password */
    
    krb5_timestamp last_failed;		/* Last failed password attempt */
    krb5_kvno fail_auth_count; 		/* # of failed password attempts */
    
    old_krb5_principal mod_name;
    krb5_timestamp mod_date;
    krb5_flags attributes;
    krb5_int32 salt_type:8,
 	       salt_length:24;
    krb5_octet *salt;
    krb5_encrypted_keyblock alt_key;
    krb5_int32 alt_salt_type:8,
 	       alt_salt_length:24;
    krb5_octet *alt_salt;
    
    krb5_int32 expansion[8];
} old_krb5_db_entry;

typedef struct _old_krb5_encrypted_keyblock {
    krb5_keytype keytype;
    int length;
    krb5_octet *contents;
} old_krb5_encrypted_keyblock;

typedef struct old_krb5_principal_data {
    krb5_magic magic;
    krb5_data realm;
    krb5_data *data;		/* An array of strings */
    krb5_int32 length;
    krb5_int32 type;
} old_krb5_principal_data;

typedef	old_krb5_principal_data *old_krb5_principal;

