#ifdef __STDC__
# define	P(s) s
#else
# define P(s) ()
#endif

/* in pepsy output, these are macros.  However, we need to pass them around
   as function pointers, and pepsy does generate in-lined macros for the
   functions, so we just disable the macros */

#undef encode_KRB5_Realm
#undef encode_KRB5_PrincipalName
#undef encode_KRB5_HostAddress
#undef encode_KRB5_HostAddresses
#undef encode_KRB5_AuthorizationData
#undef encode_KRB5_KDCOptions
#undef encode_KRB5_LastReq
#undef encode_KRB5_KerberosTime
#undef encode_KRB5_Ticket
#undef encode_KRB5_TransitedEncoding
#undef encode_KRB5_EncTicketPart
#undef encode_KRB5_Authenticator
#undef encode_KRB5_TicketFlags
#undef encode_KRB5_AS__REQ
#undef encode_KRB5_TGS__REQ
#undef encode_KRB5_PA__DATA
#undef encode_KRB5_KDC__REQ__BODY
#undef encode_KRB5_AS__REP
#undef encode_KRB5_TGS__REP
#undef encode_KRB5_EncASRepPart
#undef encode_KRB5_EncTGSRepPart
#undef encode_KRB5_AP__REQ
#undef encode_KRB5_APOptions
#undef encode_KRB5_AP__REP
#undef encode_KRB5_EncAPRepPart
#undef encode_KRB5_KRB__SAFE
#undef encode_KRB5_KRB__SAFE__BODY
#undef encode_KRB5_KRB__PRIV
#undef encode_KRB5_EncKrbPrivPart
#undef encode_KRB5_KRB__ERROR
#undef encode_KRB5_EncryptedData
#undef encode_KRB5_EncryptionKey
#undef encode_KRB5_Checksum
#undef encode_KRB5_METHOD__DATA
#undef decode_KRB5_Realm
#undef decode_KRB5_PrincipalName
#undef decode_KRB5_HostAddress
#undef decode_KRB5_HostAddresses
#undef decode_KRB5_AuthorizationData
#undef decode_KRB5_KDCOptions
#undef decode_KRB5_LastReq
#undef decode_KRB5_KerberosTime
#undef decode_KRB5_Ticket
#undef decode_KRB5_TransitedEncoding
#undef decode_KRB5_EncTicketPart
#undef decode_KRB5_Authenticator
#undef decode_KRB5_TicketFlags
#undef decode_KRB5_AS__REQ
#undef decode_KRB5_TGS__REQ
#undef decode_KRB5_PA__DATA
#undef decode_KRB5_KDC__REQ__BODY
#undef decode_KRB5_AS__REP
#undef decode_KRB5_TGS__REP
#undef decode_KRB5_EncASRepPart
#undef decode_KRB5_EncTGSRepPart
#undef decode_KRB5_AP__REQ
#undef decode_KRB5_APOptions
#undef decode_KRB5_AP__REP
#undef decode_KRB5_EncAPRepPart
#undef decode_KRB5_KRB__SAFE
#undef decode_KRB5_KRB__SAFE__BODY
#undef decode_KRB5_KRB__PRIV
#undef decode_KRB5_EncKrbPrivPart
#undef decode_KRB5_KRB__ERROR
#undef decode_KRB5_EncryptedData
#undef decode_KRB5_EncryptionKey
#undef decode_KRB5_Checksum
#undef decode_KRB5_METHOD__DATA
#undef free_KRB5_PrincipalName
#undef free_KRB5_HostAddress
#undef free_KRB5_HostAddresses
#undef free_KRB5_AuthorizationData
#undef free_KRB5_LastReq
#undef free_KRB5_Ticket
#undef free_KRB5_TransitedEncoding
#undef free_KRB5_EncTicketPart
#undef free_KRB5_Authenticator
#undef free_KRB5_AS__REQ
#undef free_KRB5_TGS__REQ
#undef free_KRB5_PA__DATA
#undef free_KRB5_KDC__REQ__BODY
#undef free_KRB5_AS__REP
#undef free_KRB5_TGS__REP
#undef free_KRB5_EncASRepPart
#undef free_KRB5_EncTGSRepPart
#undef free_KRB5_AP__REQ
#undef free_KRB5_AP__REP
#undef free_KRB5_EncAPRepPart
#undef free_KRB5_KRB__SAFE
#undef free_KRB5_KRB__SAFE__BODY
#undef free_KRB5_KRB__PRIV
#undef free_KRB5_EncKrbPrivPart
#undef free_KRB5_KRB__ERROR
#undef free_KRB5_EncryptedData
#undef free_KRB5_EncryptionKey
#undef free_KRB5_Checksum
#undef free_KRB5_METHOD__DATA

/* KRB5-types.c */
int encode_KRB5_Realm P((PE *, int , integer , char *, struct type_KRB5_Realm *));
int encode_KRB5_PrincipalName P((PE *, int , integer , char *, struct type_KRB5_PrincipalName *));
int encode_KRB5_HostAddress P((PE *, int , integer , char *, struct type_KRB5_HostAddress *));
int encode_KRB5_HostAddresses P((PE *, int , integer , char *, struct type_KRB5_HostAddresses *));
int encode_KRB5_AuthorizationData P((PE *, int , integer , char *, struct type_KRB5_AuthorizationData *));
int encode_KRB5_KDCOptions P((PE *, int , integer , char *, struct type_KRB5_KDCOptions *));
int encode_KRB5_LastReq P((PE *, int , integer , char *, struct type_KRB5_LastReq *));
int encode_KRB5_KerberosTime P((PE *, int , integer , char *, struct type_KRB5_KerberosTime *));
int encode_KRB5_Ticket P((PE *, int , integer , char *, struct type_KRB5_Ticket *));
int encode_KRB5_TransitedEncoding P((PE *, int , integer , char *, struct type_KRB5_TransitedEncoding *));
int encode_KRB5_EncTicketPart P((PE *, int , integer , char *, struct type_KRB5_EncTicketPart *));
int encode_KRB5_Authenticator P((PE *, int , integer , char *, struct type_KRB5_Authenticator *));
int encode_KRB5_TicketFlags P((PE *, int , integer , char *, struct type_KRB5_TicketFlags *));
int encode_KRB5_AS__REQ P((PE *, int , integer , char *, struct type_KRB5_AS__REQ *));
int encode_KRB5_TGS__REQ P((PE *, int , integer , char *, struct type_KRB5_TGS__REQ *));
int encode_KRB5_PA__DATA P((PE *, int , integer , char *, struct type_KRB5_PA__DATA *));
int encode_KRB5_KDC__REQ__BODY P((PE *, int , integer , char *, struct type_KRB5_KDC__REQ__BODY *));
int encode_KRB5_AS__REP P((PE *, int , integer , char *, struct type_KRB5_AS__REP *));
int encode_KRB5_TGS__REP P((PE *, int , integer , char *, struct type_KRB5_TGS__REP *));
int encode_KRB5_EncASRepPart P((PE *, int , integer , char *, struct type_KRB5_EncASRepPart *));
int encode_KRB5_EncTGSRepPart P((PE *, int , integer , char *, struct type_KRB5_EncTGSRepPart *));
int encode_KRB5_AP__REQ P((PE *, int , integer , char *, struct type_KRB5_AP__REQ *));
int encode_KRB5_APOptions P((PE *, int , integer , char *, struct type_KRB5_APOptions *));
int encode_KRB5_AP__REP P((PE *, int , integer , char *, struct type_KRB5_AP__REP *));
int encode_KRB5_EncAPRepPart P((PE *, int , integer , char *, struct type_KRB5_EncAPRepPart *));
int encode_KRB5_KRB__SAFE P((PE *, int , integer , char *, struct type_KRB5_KRB__SAFE *));
int encode_KRB5_KRB__SAFE__BODY P((PE *, int , integer , char *, struct type_KRB5_KRB__SAFE__BODY *));
int encode_KRB5_KRB__PRIV P((PE *, int , integer , char *, struct type_KRB5_KRB__PRIV *));
int encode_KRB5_EncKrbPrivPart P((PE *, int , integer , char *, struct type_KRB5_EncKrbPrivPart *));
int encode_KRB5_KRB__ERROR P((PE *, int , integer , char *, struct type_KRB5_KRB__ERROR *));
int encode_KRB5_EncryptedData P((PE *, int , integer , char *, struct type_KRB5_EncryptedData *));
int encode_KRB5_EncryptionKey P((PE *, int , integer , char *, struct type_KRB5_EncryptionKey *));
int encode_KRB5_Checksum P((PE *, int , integer , char *, struct type_KRB5_Checksum *));
int encode_KRB5_METHOD__DATA P((PE *, int , integer , char *, struct type_KRB5_METHOD__DATA *));
int decode_KRB5_Realm P((PE , int , integer *, char **, struct type_KRB5_Realm **));
int decode_KRB5_PrincipalName P((PE , int , integer *, char **, struct type_KRB5_PrincipalName **));
int decode_KRB5_HostAddress P((PE , int , integer *, char **, struct type_KRB5_HostAddress **));
int decode_KRB5_HostAddresses P((PE , int , integer *, char **, struct type_KRB5_HostAddresses **));
int decode_KRB5_AuthorizationData P((PE , int , integer *, char **, struct type_KRB5_AuthorizationData **));
int decode_KRB5_KDCOptions P((PE , int , integer *, char **, struct type_KRB5_KDCOptions **));
int decode_KRB5_LastReq P((PE , int , integer *, char **, struct type_KRB5_LastReq **));
int decode_KRB5_KerberosTime P((PE , int , integer *, char **, struct type_KRB5_KerberosTime **));
int decode_KRB5_Ticket P((PE , int , integer *, char **, struct type_KRB5_Ticket **));
int decode_KRB5_TransitedEncoding P((PE , int , integer *, char **, struct type_KRB5_TransitedEncoding **));
int decode_KRB5_EncTicketPart P((PE , int , integer *, char **, struct type_KRB5_EncTicketPart **));
int decode_KRB5_Authenticator P((PE , int , integer *, char **, struct type_KRB5_Authenticator **));
int decode_KRB5_TicketFlags P((PE , int , integer *, char **, struct type_KRB5_TicketFlags **));
int decode_KRB5_AS__REQ P((PE , int , integer *, char **, struct type_KRB5_AS__REQ **));
int decode_KRB5_TGS__REQ P((PE , int , integer *, char **, struct type_KRB5_TGS__REQ **));
int decode_KRB5_PA__DATA P((PE , int , integer *, char **, struct type_KRB5_PA__DATA **));
int decode_KRB5_KDC__REQ__BODY P((PE , int , integer *, char **, struct type_KRB5_KDC__REQ__BODY **));
int decode_KRB5_AS__REP P((PE , int , integer *, char **, struct type_KRB5_AS__REP **));
int decode_KRB5_TGS__REP P((PE , int , integer *, char **, struct type_KRB5_TGS__REP **));
int decode_KRB5_EncASRepPart P((PE , int , integer *, char **, struct type_KRB5_EncASRepPart **));
int decode_KRB5_EncTGSRepPart P((PE , int , integer *, char **, struct type_KRB5_EncTGSRepPart **));
int decode_KRB5_AP__REQ P((PE , int , integer *, char **, struct type_KRB5_AP__REQ **));
int decode_KRB5_APOptions P((PE , int , integer *, char **, struct type_KRB5_APOptions **));
int decode_KRB5_AP__REP P((PE , int , integer *, char **, struct type_KRB5_AP__REP **));
int decode_KRB5_EncAPRepPart P((PE , int , integer *, char **, struct type_KRB5_EncAPRepPart **));
int decode_KRB5_KRB__SAFE P((PE , int , integer *, char **, struct type_KRB5_KRB__SAFE **));
int decode_KRB5_KRB__SAFE__BODY P((PE , int , integer *, char **, struct type_KRB5_KRB__SAFE__BODY **));
int decode_KRB5_KRB__PRIV P((PE , int , integer *, char **, struct type_KRB5_KRB__PRIV **));
int decode_KRB5_EncKrbPrivPart P((PE , int , integer *, char **, struct type_KRB5_EncKrbPrivPart **));
int decode_KRB5_KRB__ERROR P((PE , int , integer *, char **, struct type_KRB5_KRB__ERROR **));
int decode_KRB5_EncryptedData P((PE , int , integer *, char **, struct type_KRB5_EncryptedData **));
int decode_KRB5_EncryptionKey P((PE , int , integer *, char **, struct type_KRB5_EncryptionKey **));
int decode_KRB5_Checksum P((PE , int , integer *, char **, struct type_KRB5_Checksum **));
int decode_KRB5_METHOD__DATA P((PE , int , integer *, char **, struct type_KRB5_METHOD__DATA **));

void free_KRB5_PrincipalName P((struct type_KRB5_PrincipalName *));
void free_KRB5_HostAddress P((struct type_KRB5_HostAddress *));
void free_KRB5_HostAddresses P((struct type_KRB5_HostAddresses *));
void free_KRB5_AuthorizationData P((struct type_KRB5_AuthorizationData *));
void free_KRB5_LastReq P((struct type_KRB5_LastReq *));
void free_KRB5_Ticket P((struct type_KRB5_Ticket *));
void free_KRB5_TransitedEncoding P((struct type_KRB5_TransitedEncoding *));
void free_KRB5_EncTicketPart P((struct type_KRB5_EncTicketPart *));
void free_KRB5_Authenticator P((struct type_KRB5_Authenticator *));
void free_KRB5_AS__REQ P((struct type_KRB5_AS__REQ *));
void free_KRB5_TGS__REQ P((struct type_KRB5_TGS__REQ *));
void free_KRB5_PA__DATA P((struct type_KRB5_PA__DATA *));
void free_KRB5_KDC__REQ__BODY P((struct type_KRB5_KDC__REQ__BODY *));
void free_KRB5_AS__REP P((struct type_KRB5_AS__REP *));
void free_KRB5_TGS__REP P((struct type_KRB5_TGS__REP *));
void free_KRB5_EncASRepPart P((struct type_KRB5_EncASRepPart *));
void free_KRB5_EncTGSRepPart P((struct type_KRB5_EncTGSRepPart *));
void free_KRB5_AP__REQ P((struct type_KRB5_AP__REQ *));
void free_KRB5_AP__REP P((struct type_KRB5_AP__REP *));
void free_KRB5_EncAPRepPart P((struct type_KRB5_EncAPRepPart *));
void free_KRB5_KRB__SAFE P((struct type_KRB5_KRB__SAFE *));
void free_KRB5_KRB__SAFE__BODY P((struct type_KRB5_KRB__SAFE__BODY *));
void free_KRB5_KRB__PRIV P((struct type_KRB5_KRB__PRIV *));
void free_KRB5_EncKrbPrivPart P((struct type_KRB5_EncKrbPrivPart *));
void free_KRB5_KRB__ERROR P((struct type_KRB5_KRB__ERROR *));
void free_KRB5_EncryptedData P((struct type_KRB5_EncryptedData *));
void free_KRB5_EncryptionKey P((struct type_KRB5_EncryptionKey *));
void free_KRB5_Checksum P((struct type_KRB5_Checksum *));
void free_KRB5_METHOD__DATA P((struct type_KRB5_METHOD__DATA *));

#undef P
