#ifdef __STDC__
# define	P(s) s
#else
# define P(s) ()
#endif


/* KRB5-types.c */
int encode_KRB5_Realm P((PE *pe , int explicit , integer len , char *buffer , struct type_KRB5_Realm *parm ));
int encode_KRB5_PrincipalName P((PE *pe , int explicit , integer len , char *buffer , struct type_KRB5_PrincipalName *parm ));
int encode_KRB5_EncryptedData P((PE *pe , int explicit , integer len , char *buffer , struct type_KRB5_EncryptedData *parm ));
int encode_KRB5_MessageType P((PE *pe , int explicit , integer len , char *buffer , struct type_KRB5_MessageType *parm ));
int encode_KRB5_AddressType P((PE *pe , int explicit , integer len , char *buffer , struct type_KRB5_AddressType *parm ));
int encode_KRB5_KeyType P((PE *pe , int explicit , integer len , char *buffer , struct type_KRB5_KeyType *parm ));
int encode_KRB5_EncryptionType P((PE *pe , int explicit , integer len , char *buffer , struct type_KRB5_EncryptionType *parm ));
int encode_KRB5_ChecksumType P((PE *pe , int explicit , integer len , char *buffer , struct type_KRB5_ChecksumType *parm ));
int encode_KRB5_EncryptionKey P((PE *pe , int explicit , integer len , char *buffer , struct type_KRB5_EncryptionKey *parm ));
int encode_KRB5_Checksum P((PE *pe , int explicit , integer len , char *buffer , struct type_KRB5_Checksum *parm ));
int encode_KRB5_Authenticator P((PE *pe , int explicit , integer len , char *buffer , struct type_KRB5_Authenticator *parm ));
int encode_KRB5_AuthenticatorVersion P((PE *pe , int explicit , integer len , char *buffer , struct type_KRB5_AuthenticatorVersion *parm ));
int encode_KRB5_EncTicketPart P((PE *pe , int explicit , integer len , char *buffer , struct type_KRB5_EncTicketPart *parm ));
int encode_KRB5_TicketFlags P((PE *pe , int explicit , integer len , char *buffer , struct type_KRB5_TicketFlags *parm ));
int encode_KRB5_HostAddresses P((PE *pe , int explicit , integer len , char *buffer , struct type_KRB5_HostAddresses *parm ));
int encode_KRB5_AuthorizationData P((PE *pe , int explicit , integer len , char *buffer , struct type_KRB5_AuthorizationData *parm ));
int encode_KRB5_KDCOptions P((PE *pe , int explicit , integer len , char *buffer , struct type_KRB5_KDCOptions *parm ));
int encode_KRB5_Ticket P((PE *pe , int explicit , integer len , char *buffer , struct type_KRB5_Ticket *parm ));
int encode_KRB5_AS__REQ P((PE *pe , int explicit , integer len , char *buffer , struct type_KRB5_AS__REQ *parm ));
int encode_KRB5_KDC__REP P((PE *pe , int explicit , integer len , char *buffer , struct type_KRB5_KDC__REP *parm ));
int encode_KRB5_EncKDCRepPart P((PE *pe , int explicit , integer len , char *buffer , struct type_KRB5_EncKDCRepPart *parm ));
int encode_KRB5_KRB__ERROR P((PE *pe , int explicit , integer len , char *buffer , struct type_KRB5_KRB__ERROR *parm ));
int encode_KRB5_LastReq P((PE *pe , int explicit , integer len , char *buffer , struct type_KRB5_LastReq *parm ));
int encode_KRB5_AP__REQ P((PE *pe , int explicit , integer len , char *buffer , struct type_KRB5_AP__REQ *parm ));
int encode_KRB5_APOptions P((PE *pe , int explicit , integer len , char *buffer , struct type_KRB5_APOptions *parm ));
int encode_KRB5_AP__REP P((PE *pe , int explicit , integer len , char *buffer , struct type_KRB5_AP__REP *parm ));
int encode_KRB5_EncAPRepPart P((PE *pe , int explicit , integer len , char *buffer , struct type_KRB5_EncAPRepPart *parm ));
int encode_KRB5_TGS__REQ P((PE *pe , int explicit , integer len , char *buffer , struct type_KRB5_TGS__REQ *parm ));
int encode_KRB5_RealTGS__REQ P((PE *pe , int explicit , integer len , char *buffer , struct type_KRB5_RealTGS__REQ *parm ));
int encode_KRB5_EncTgsReqPart P((PE *pe , int explicit , integer len , char *buffer , struct type_KRB5_EncTgsReqPart *parm ));
int encode_KRB5_KRB__SAFE P((PE *pe , int explicit , integer len , char *buffer , struct type_KRB5_KRB__SAFE *parm ));
int encode_KRB5_KRB__PRIV P((PE *pe , int explicit , integer len , char *buffer , struct type_KRB5_KRB__PRIV *parm ));
int encode_KRB5_EncKrbPrivPart P((PE *pe , int explicit , integer len , char *buffer , struct type_KRB5_EncKrbPrivPart *parm ));
int decode_KRB5_Realm P((PE pe , int explicit , integer *len , char **buffer , struct type_KRB5_Realm **parm ));
int decode_KRB5_PrincipalName P((PE pe , int explicit , integer *len , char **buffer , struct type_KRB5_PrincipalName **parm ));
int decode_KRB5_EncryptedData P((PE pe , int explicit , integer *len , char **buffer , struct type_KRB5_EncryptedData **parm ));
int decode_KRB5_MessageType P((PE pe , int explicit , integer *len , char **buffer , struct type_KRB5_MessageType **parm ));
int decode_KRB5_AddressType P((PE pe , int explicit , integer *len , char **buffer , struct type_KRB5_AddressType **parm ));
int decode_KRB5_KeyType P((PE pe , int explicit , integer *len , char **buffer , struct type_KRB5_KeyType **parm ));
int decode_KRB5_EncryptionType P((PE pe , int explicit , integer *len , char **buffer , struct type_KRB5_EncryptionType **parm ));
int decode_KRB5_ChecksumType P((PE pe , int explicit , integer *len , char **buffer , struct type_KRB5_ChecksumType **parm ));
int decode_KRB5_EncryptionKey P((PE pe , int explicit , integer *len , char **buffer , struct type_KRB5_EncryptionKey **parm ));
int decode_KRB5_Checksum P((PE pe , int explicit , integer *len , char **buffer , struct type_KRB5_Checksum **parm ));
int decode_KRB5_Authenticator P((PE pe , int explicit , integer *len , char **buffer , struct type_KRB5_Authenticator **parm ));
int decode_KRB5_AuthenticatorVersion P((PE pe , int explicit , integer *len , char **buffer , struct type_KRB5_AuthenticatorVersion **parm ));
int decode_KRB5_EncTicketPart P((PE pe , int explicit , integer *len , char **buffer , struct type_KRB5_EncTicketPart **parm ));
int decode_KRB5_TicketFlags P((PE pe , int explicit , integer *len , char **buffer , struct type_KRB5_TicketFlags **parm ));
int decode_KRB5_HostAddresses P((PE pe , int explicit , integer *len , char **buffer , struct type_KRB5_HostAddresses **parm ));
int decode_KRB5_AuthorizationData P((PE pe , int explicit , integer *len , char **buffer , struct type_KRB5_AuthorizationData **parm ));
int decode_KRB5_KDCOptions P((PE pe , int explicit , integer *len , char **buffer , struct type_KRB5_KDCOptions **parm ));
int decode_KRB5_Ticket P((PE pe , int explicit , integer *len , char **buffer , struct type_KRB5_Ticket **parm ));
int decode_KRB5_AS__REQ P((PE pe , int explicit , integer *len , char **buffer , struct type_KRB5_AS__REQ **parm ));
int decode_KRB5_KDC__REP P((PE pe , int explicit , integer *len , char **buffer , struct type_KRB5_KDC__REP **parm ));
int decode_KRB5_EncKDCRepPart P((PE pe , int explicit , integer *len , char **buffer , struct type_KRB5_EncKDCRepPart **parm ));
int decode_KRB5_KRB__ERROR P((PE pe , int explicit , integer *len , char **buffer , struct type_KRB5_KRB__ERROR **parm ));
int decode_KRB5_LastReq P((PE pe , int explicit , integer *len , char **buffer , struct type_KRB5_LastReq **parm ));
int decode_KRB5_AP__REQ P((PE pe , int explicit , integer *len , char **buffer , struct type_KRB5_AP__REQ **parm ));
int decode_KRB5_APOptions P((PE pe , int explicit , integer *len , char **buffer , struct type_KRB5_APOptions **parm ));
int decode_KRB5_AP__REP P((PE pe , int explicit , integer *len , char **buffer , struct type_KRB5_AP__REP **parm ));
int decode_KRB5_EncAPRepPart P((PE pe , int explicit , integer *len , char **buffer , struct type_KRB5_EncAPRepPart **parm ));
int decode_KRB5_TGS__REQ P((PE pe , int explicit , integer *len , char **buffer , struct type_KRB5_TGS__REQ **parm ));
int decode_KRB5_RealTGS__REQ P((PE pe , int explicit , integer *len , char **buffer , struct type_KRB5_RealTGS__REQ **parm ));
int decode_KRB5_EncTgsReqPart P((PE pe , int explicit , integer *len , char **buffer , struct type_KRB5_EncTgsReqPart **parm ));
int decode_KRB5_KRB__SAFE P((PE pe , int explicit , integer *len , char **buffer , struct type_KRB5_KRB__SAFE **parm ));
int decode_KRB5_KRB__PRIV P((PE pe , int explicit , integer *len , char **buffer , struct type_KRB5_KRB__PRIV **parm ));
int decode_KRB5_EncKrbPrivPart P((PE pe , int explicit , integer *len , char **buffer , struct type_KRB5_EncKrbPrivPart **parm ));
int free_KRB5_PrincipalName P((struct type_KRB5_PrincipalName *arg ));
int free_KRB5_MessageType P((struct type_KRB5_MessageType *arg ));
int free_KRB5_AddressType P((struct type_KRB5_AddressType *arg ));
int free_KRB5_KeyType P((struct type_KRB5_KeyType *arg ));
int free_KRB5_EncryptionType P((struct type_KRB5_EncryptionType *arg ));
int free_KRB5_ChecksumType P((struct type_KRB5_ChecksumType *arg ));
int free_KRB5_EncryptionKey P((struct type_KRB5_EncryptionKey *arg ));
int free_KRB5_Checksum P((struct type_KRB5_Checksum *arg ));
int free_KRB5_Authenticator P((struct type_KRB5_Authenticator *arg ));
int free_KRB5_AuthenticatorVersion P((struct type_KRB5_AuthenticatorVersion *arg ));
int free_KRB5_EncTicketPart P((struct type_KRB5_EncTicketPart *arg ));
int free_KRB5_HostAddresses P((struct type_KRB5_HostAddresses *arg ));
int free_KRB5_AuthorizationData P((struct type_KRB5_AuthorizationData *arg ));
int free_KRB5_Ticket P((struct type_KRB5_Ticket *arg ));
int free_KRB5_AS__REQ P((struct type_KRB5_AS__REQ *arg ));
int free_KRB5_KDC__REP P((struct type_KRB5_KDC__REP *arg ));
int free_KRB5_EncKDCRepPart P((struct type_KRB5_EncKDCRepPart *arg ));
int free_KRB5_KRB__ERROR P((struct type_KRB5_KRB__ERROR *arg ));
int free_KRB5_LastReq P((struct type_KRB5_LastReq *arg ));
int free_KRB5_AP__REQ P((struct type_KRB5_AP__REQ *arg ));
int free_KRB5_AP__REP P((struct type_KRB5_AP__REP *arg ));
int free_KRB5_EncAPRepPart P((struct type_KRB5_EncAPRepPart *arg ));
int free_KRB5_TGS__REQ P((struct type_KRB5_TGS__REQ *arg ));
int free_KRB5_RealTGS__REQ P((struct type_KRB5_RealTGS__REQ *arg ));
int free_KRB5_EncTgsReqPart P((struct type_KRB5_EncTgsReqPart *arg ));
int free_KRB5_KRB__SAFE P((struct type_KRB5_KRB__SAFE *arg ));
int free_KRB5_KRB__PRIV P((struct type_KRB5_KRB__PRIV *arg ));
int free_KRB5_EncKrbPrivPart P((struct type_KRB5_EncKrbPrivPart *arg ));

#undef P
