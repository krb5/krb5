#include "CGSSDocument.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

extern "C" {
#include <mit-sock.h>
}

#include "CGSSWindow.h"

const	ResIDT		wind_GSS			= 128;
const	PaneIDT		pane_Status			= 904;
const	PaneIDT		pane_QueryArgument	= 900;
const	PaneIDT		pbut_Query			= 901;
const	PaneIDT		text_Output			= 903;
// Message the Query button broadcasts
const	MessageT	msg_Query			= 'GSSq';
// AppleEvent reference number
const	long		ae_Query			= 4001;

CGSSDocument::CGSSDocument ()
{
	// Make us a window
	mWindow = CGSSWindow::CreateGSSWindow (wind_GSS, this);

	// A window, I said
	SignalIf_ (mWindow == nil);		
	mWindow -> Show ();

	// Listen to query button clicks 
	((LControl*) mWindow -> FindPaneByID (pbut_Query)) -> AddListener (this);
}

CGSSDocument::~CGSSDocument ()
{
}

void
CGSSDocument::HandleAppleEvent (
	const AppleEvent&	inAppleEvent,
	AppleEvent&			outAEReply,
	AEDesc&				outResult,
	long				inAENumber)
{
	switch (inAENumber) {

		case ae_Query:
			// extract the query string from the appleevent
			AEDesc	queryData;
			OSErr err = ::AEGetParamDesc (&inAppleEvent, keyDirectObject, typeChar, &queryData);
			char queryString [255];
			UInt8 dataSize;
			{
				StHandleLocker (queryData.dataHandle);
				dataSize = ::GetHandleSize (queryData.dataHandle);
				// Limited to 255 charactees
				SignalIf_ (dataSize > 255);
				::BlockMoveData (*(queryData.dataHandle), queryString, dataSize);
			}
			
			queryString [dataSize] = '\0';
							
			GSSQuery (queryString);
			::AEDisposeDesc (&queryData);
			break;

		default:
			LSingleDoc::HandleAppleEvent (inAppleEvent, outAEReply, outResult, inAENumber);
			break;
	}
}

Boolean
CGSSDocument::ObeyCommand(
	CommandT	inCommand,
	void		*ioParam)
{
	Boolean		cmdHandled = true;

	switch (inCommand) {
	
		// Deal with command messages
		// Any that you don't handle will be passed to LApplication
 			
		case msg_Query:
			Str255 theArgument = "\0";		
			(LEditField*) (mWindow -> FindPaneByID (pane_QueryArgument)) -> GetDescriptor (theArgument);
			P2CStr (theArgument);
			GSSQuery ((char*) theArgument);
			break;
			
		default:
			cmdHandled = LSingleDoc::ObeyCommand(inCommand, ioParam);
			break;
	}
	
	return cmdHandled;

}

void
CGSSDocument::DoAESave(
	FSSpec&	inFileSpec,
	OSType	inFileType)
{
	TEHandle teHandle = ((LTextEdit*) (mWindow -> FindPaneByID (text_Output))) -> GetMacTEH ();
	Handle textHandle = (*teHandle) -> hText;
	UInt32 textSize = ::GetHandleSize (textHandle);

	LFileStream saveStream (inFileSpec);
	try
	{
		// Try opening the file
		saveStream.OpenDataFork (fsRdWrPerm);
	}
	Catch_ (err)
	{
		// If opening failed, try creating the file
		saveStream.CreateNewDataFile ('CWIE', 'TEXT', smSystemScript);
		saveStream.OpenDataFork (fsRdWrPerm);
	}
	
	saveStream.SetLength (0); // Zap!
	
	StHandleLocker dataLock (textHandle);
	saveStream.WriteData (*textHandle, (*teHandle) -> teLength);
	SetModified (false);
}

void
CGSSDocument::ListenToMessage (
	MessageT	inMessage,
	void*		ioParam)
{
	switch (inMessage)
	{
		case msg_Query:
		// Respond to query button clicks by doing the query
			ObeyCommand (msg_Query, nil);
	}
}

// The following two append strings to the output TextEdit pane

void
CGSSDocument::AppendPString (
	ConstStringPtr	inString)
{
	TEHandle teHandle = ((LTextEdit*) (mWindow -> FindPaneByID (text_Output))) -> GetMacTEH ();
	Handle textHandle = (*teHandle) -> hText;
	UInt32 textSize = ::GetHandleSize (textHandle);
	::SetHandleSize (textHandle, textSize + inString [0]);

	{
		StHandleLocker textLock (textHandle);
		::BlockMoveData (inString + 1, *textHandle + textSize, inString [0]);
	}
	(*teHandle) -> teLength += inString [0];
	::TECalText (teHandle);
	
	mWindow -> Refresh ();
}	

void
CGSSDocument::AppendCString (
	char*	inString)
{
	C2PStr (inString);
	AppendPString ((ConstStringPtr) inString);
}

#pragma mark -
#pragma mark € GSS Functions €

void
CGSSDocument::GSSQuery (
	char*	inQueryString)
{
	Boolean validQuery = true;

	char serverHost [255];
	memset (serverHost, 0, 255);

	char serviceName [255];
	memset (serviceName, 0, 255);

	char theMessage [255];
	memset (theMessage, 0, 255);
	
	u_short serverPort = 4444;
	int useV2 = 0;
	char* walker;
	
	char* argWalker = inQueryString;
		
	// check all options
	while (*argWalker == '-')
	{
		// eat leading space
		while (*argWalker != '\0' && isspace (*argWalker))
			argWalker++;

		// check -v2 option
		if (!strncmp (argWalker, "-v2 ", 4))
		{
			useV2 = 1;
			argWalker += 4;
			continue;
		};

		// check -port option
		if (!strncmp (argWalker, "-port ", 6))
		{
			// skip "-port "
			argWalker +=6;
			// skip space
			while (*argWalker != '\0' && isspace (*argWalker))
				argWalker++;
			// copy the port number; recycle serverHost for this
			for (walker = serverHost; *argWalker != '\0' && !isspace (*argWalker); argWalker++, walker++)
				*walker = *argWalker;

			if (*serverHost == '\0')
				validQuery = false;
			serverPort = atoi (serverHost);
			memset (serverHost, 0, 255);
		}
	}

	// eat leading space
	while (*argWalker != '\0' && isspace (*argWalker))
		argWalker++;

	// Copy to serverHost
	for (walker = serverHost; (*argWalker != '\0' && !isspace (*argWalker)); argWalker++, walker++)
		*walker = *argWalker;
	if (*serverHost == '\0')
		validQuery = false;
			
	// eat leading space
	while (*argWalker != '\0' && isspace (*argWalker))
		argWalker++;

	// Copy to serviceName
	for (walker = serviceName; (*argWalker != '\0' && !isspace (*argWalker)); argWalker++, walker++)
		*walker = *argWalker;
	if (*serviceName == '\0')
		validQuery = false;

	// eat leading space
	while (*argWalker != '\0' && isspace (*argWalker))
		argWalker++;

	// Copy to theMessage
	for (walker = theMessage; (*argWalker != '\0' && !isspace (*argWalker)); argWalker++, walker++)
		*walker = *argWalker;
	if (*theMessage == '\0')
		validQuery = false;

	SetModified (true);

	if (!GSSCallServer(serverHost, serverPort, useV2, serviceName, theMessage) < 0)
		AppendPString ("\pQuery Complete =)");
}

/*
 * Function: call_server
 *
 * Purpose: Call the "sign" service.
 *
 * Arguments:
 *
 * 	host		(r) the host providing the service
 * 	port		(r) the port to connect to on host
 * 	service_name	(r) the GSS-API service name to authenticate to	
 * 	msg		(r) the message to have "signed"
 *
 * Returns: 0 on success, -1 on failure
 *
 * Effects:
 * 
 * call_server opens a TCP connection to <host:port> and establishes a
 * GSS-API context with service_name over the connection.  It then
 * seals msg in a GSS-API token with gss_seal, sends it to the server,
 * reads back a GSS-API signature block for msg from the server, and
 * verifies it with gss_verify.  -1 is returned if any step fails,
 * otherwise 0 is returned.
 */
 // meeroh: put this in CGSSDocument for easier access to Stderr
 // could have done in a different way; this simplifies the code
int
CGSSDocument::GSSCallServer (
	char *host,
	u_short port,
	int dov2,
	char *service_name,
	char *msg)
{
	gss_ctx_id_t context;
	gss_buffer_desc in_buf, out_buf, context_token;
	int state;
	int s;
	OM_uint32 maj_stat, min_stat;
	gss_name_t	src_name, targ_name;
	gss_buffer_desc sname, tname;
	OM_uint32 lifetime;
	gss_OID mechanism;
	int is_local;
#ifdef	GSSAPI_V2
	OM_uint32 context_flags;
	int is_open;
	gss_qop_t qop_state;
	gss_OID_set mech_names;
	gss_buffer_desc oid_name;
#else	/* GSSAPI_V2 */
	int context_flags;
#endif	/* GSSAPI_V2 */
	char msgString [255] = "\0";
     
	/* Open connection */
	if ((s = GSSConnectToServer (host, port)) == (int) -1)
		return -1;

	/* Establish context */
	if (GSSClientEstablishContext (s, service_name, &context) < 0)
		return -1;

#ifdef	GSSAPI_V2
	if (dov2)
	{
		/*
		 * Attempt to save and then restore the context.
		 */
		maj_stat = gss_export_sec_context (	&min_stat,
											&context,
											&context_token);
		if (maj_stat != GSS_S_COMPLETE)
		{
			GSSDisplayStatus("exporting context", maj_stat, min_stat);
			return -1;
		}
		maj_stat = gss_import_sec_context (	&min_stat,
											&context_token,
											&context);
		if (maj_stat != GSS_S_COMPLETE)
		{
			GSSDisplayStatus ("importing context", maj_stat, min_stat);
			return -1;
		}
		(void) gss_release_buffer (&min_stat, &context_token);
	}
#endif	/* GSSAPI_V2 */

	/* Get context information */
	maj_stat = gss_inquire_context (	&min_stat,
										context,
										&src_name,
										&targ_name,
										&lifetime,
										&mechanism,
										&context_flags,
										&is_local
#ifdef	GSSAPI_V2
										, &is_open
#endif	/* GSSAPI_V2 */
									);
	if (maj_stat != GSS_S_COMPLETE)
	{
		GSSDisplayStatus ("inquiring context", maj_stat, min_stat);
		return -1;
	}

	maj_stat = gss_display_name (	&min_stat,
									src_name,
									&sname,
									(gss_OID *) NULL);
	if (maj_stat != GSS_S_COMPLETE)
	{
		GSSDisplayStatus ("displaying context", maj_stat, min_stat);
		return -1;
	}
	maj_stat = gss_display_name (	&min_stat,
									targ_name,
									&tname,
									(gss_OID *) NULL);
	if (maj_stat != GSS_S_COMPLETE)
	{
		GSSDisplayStatus ("displaying context", maj_stat, min_stat);
		return -1;
	}

	sprintf (	msgString,
				"\"%s\" to \"%s\"\r   lifetime %d, flags %x, %s",
				sname.value,
				tname.value,
				lifetime,
				context_flags,
				(is_local) ? "locally initiated" : "remotely initiated");
	AppendCString (msgString);	     
#ifdef	GSSAPI_V2
	sprintf (msgString, " %s", (is_open) ? "open" : "closed");
	AppendCString (msgString);
#endif	/* GSSAPI_V2 */
	sprintf(msgString, "\r");
	AppendCString (msgString);

	(void) gss_release_name (&min_stat, &src_name);
	(void) gss_release_name (&min_stat, &targ_name);
	(void) gss_release_buffer (&min_stat, &sname);
	(void) gss_release_buffer(&min_stat, &tname);

#ifdef	GSSAPI_V2
	if (dov2)
	{
		size_t	i;

		/* Now get the names supported by the mechanism */
		maj_stat = gss_inquire_names_for_mech (	&min_stat,
												mechanism,
												&mech_names);
		if (maj_stat != GSS_S_COMPLETE)
		{
			GSSDisplayStatus ("inquiring mech names", maj_stat, min_stat);
			return -1;
		}

		maj_stat = gss_oid_to_str (	&min_stat,
									mechanism,
									&oid_name);
		if (maj_stat != GSS_S_COMPLETE)
		{
			GSSDisplayStatus ("converting oid->string", maj_stat, min_stat);
			return -1;
		}

		sprintf (	msgString,
					"Mechanism %s supports %d names\r",
					oid_name.value,
					mech_names->count);
		AppendCString (msgString);
		(void) gss_release_buffer(&min_stat, &oid_name);
		for (i=0; i<mech_names->count; i++)
		{
			gss_OID	tmpoid;
			int	is_present;

			maj_stat = gss_oid_to_str (	&min_stat,
										&mech_names->elements[i],
										&oid_name);
			if (maj_stat != GSS_S_COMPLETE)
			{
				GSSDisplayStatus ("converting oid->string", maj_stat, min_stat);
				return -1;
			}

			sprintf (msgString, "%d: %s\r", i, oid_name.value);
			AppendCString (msgString);

			maj_stat = gss_str_to_oid (	&min_stat,
										&oid_name,
										&tmpoid);
			if (maj_stat != GSS_S_COMPLETE)
			{
				GSSDisplayStatus (	"converting string->oid",
									maj_stat,
									min_stat);
				return -1;
			}

			maj_stat = gss_test_oid_set_member (	&min_stat,
													tmpoid,
													mech_names,
													&is_present);
			if (maj_stat != GSS_S_COMPLETE)
			{
				GSSDisplayStatus ("testing oid presence", maj_stat, min_stat);
				return -1;
			}
			if (!is_present)
			{
				sprintf (msgString, "%s is not present in list?\r", oid_name.value);
				AppendCString (msgString);
			}
			(void) gss_release_oid (&min_stat, &tmpoid);
			(void) gss_release_buffer (&min_stat, &oid_name);
		}

		(void) gss_release_oid_set (&min_stat, &mech_names);
		(void) gss_release_oid (&min_stat, &mechanism);
	}
#endif	/* GSSAPI_V2 */

	/* Seal the message */
	in_buf.value = msg;
	in_buf.length = strlen(msg) + 1;
#ifdef	GSSAPI_V2
	if (dov2)
		maj_stat = gss_wrap (	&min_stat,
								context,
								1,
								GSS_C_QOP_DEFAULT,
								&in_buf,
								&state,
								&out_buf);
	else
#endif	/* GSSAPI_V2 */
		maj_stat = gss_seal (	&min_stat,
								context,
								1,
								GSS_C_QOP_DEFAULT,
								&in_buf,
								&state,
								&out_buf);
	if (maj_stat != GSS_S_COMPLETE)
	{
		GSSDisplayStatus ( "sealing message", maj_stat, min_stat);
		return -1;
	}
	else
		if (!state)
		{
			sprintf (msgString, "Warning!  Message not encrypted.\r");
			AppendCString (msgString);
		}

	/* Send to server */
	if (GSSSendToken (s, &out_buf) < 0)
		return -1;
	(void) gss_release_buffer (&min_stat, &out_buf);

	/* Read signature block into out_buf */
	if (GSSReceiveToken (s, &out_buf) < 0)
		return -1;

	/* Verify signature block */
#ifdef	GSSAPI_V2
	if (dov2)
		maj_stat = gss_verify_mic (	&min_stat,
									context,
									&in_buf,
									&out_buf,
									&qop_state);
	else
#endif	/* GSSAPI_V2 */
		maj_stat = gss_verify (&min_stat, context, &in_buf, &out_buf, &state);
		if (maj_stat != GSS_S_COMPLETE)
		{
			GSSDisplayStatus ("verifying signature", maj_stat, min_stat);
			return -1;
		}
		(void) gss_release_buffer (&min_stat, &out_buf);

	AppendPString ("\pSignature verified.\r");

	/* Delete context */
	maj_stat = gss_delete_sec_context (&min_stat, &context, &out_buf);
	if (maj_stat != GSS_S_COMPLETE)
	{
		GSSDisplayStatus ("deleting context", maj_stat, min_stat);
		return -1;
	}
	(void) gss_release_buffer (&min_stat, &out_buf);
     
	close(s);
     
	return 0;
}

void
CGSSDocument::GSSDisplayStatus (
	char *m,
	OM_uint32 maj_stat,
	OM_uint32 min_stat)
{
    OM_uint32 my_maj_stat, my_min_stat;
    gss_buffer_desc msg;
    #ifdef GSSAPI_V2
        OM_uint32 msg_ctx;
    #else	/* GSSAPI_V2 */
        int msg_ctx;
    #endif	/* GSSAPI_V2 */

	Str255 msgString;

    msg_ctx = 0;
    while (1) {
        my_maj_stat = gss_display_status(
        	&my_min_stat, maj_stat, GSS_C_GSS_CODE, GSS_C_NULL_OID, &msg_ctx, &msg);

        sprintf ((char*) msgString, "GSS-API error %s: %s\r", m, (char *)msg.value);
		C2PStr ((char*) msgString);
	    AppendPString (msgString);

        (void) gss_release_buffer(&min_stat, &msg);

        if (!msg_ctx)
            break;
    }

    msg_ctx = 0;
    while (1) {
        my_maj_stat = gss_display_status(
        	&my_min_stat, min_stat, GSS_C_MECH_CODE, GSS_C_NULL_OID, &msg_ctx, &msg);

        sprintf ((char*) msgString, "GSS-API error %s: %s\r", m, (char *)msg.value);
		C2PStr ((char*) msgString);
	    AppendPString (msgString);

        (void) gss_release_buffer(&min_stat, &msg);

        if (!msg_ctx)
            break;
    }
}

/*
 * Function: connect_to_server
 *
 * Purpose: Opens a TCP connection to the name host and port.
 *
 * Arguments:
 *
 * 	host		(r) the target host name
 * 	port		(r) the target port, in host byte order
 *
 * Returns: the established socket file desciptor, or -1 on failure
 *
 * Effects:
 *
 * The host name is resolved with gethostbyname(), and the socket is
 * opened and connected.  If an error occurs, an error message is
 * displayed and -1 is returned.
 */
int CGSSDocument::GSSConnectToServer (
	char *host,
	u_short port)
{
	struct sockaddr_in saddr;
	struct hostent *hp;
	int s;
	char msgString [255];
	     
	if ((hp = gethostbyname (host)) == NULL)
	{
		sprintf (msgString, "Unknown host: %s\r", host);
		AppendCString (msgString);
		return (SOCKET) -1;
	}

	saddr.sin_family = hp->h_addrtype;
	memcpy ((char *) &saddr.sin_addr, hp -> h_addr, sizeof (saddr.sin_addr));
	saddr.sin_port = htons (port);

	if ((s = socket (AF_INET, SOCK_STREAM, 0)) == (SOCKET) -1)
	{
		sprintf (msgString, "Error creating socket\r");
		AppendCString (msgString);
		return (SOCKET) -1;
	}
	if (connect (s, (struct sockaddr *) &saddr, sizeof (saddr)) < 0)
	{
		sprintf (msgString, "Error connecting to server\r");
		AppendCString (msgString);
		return (SOCKET) -1;
	}
	return s;
}


/*
 * Function: client_establish_context
 *
 * Purpose: establishes a GSS-API context with a specified service and
 * returns the context handle
 *
 * Arguments:
 *
 * 	s		(r) an established TCP connection to the service
 * 	service_name	(r) the ASCII service name of the service
 * 	context		(w) the established GSS-API context
 *
 * Returns: 0 on success, -1 on failure
 *
 * Effects:
 * 
 * service_name is imported as a GSS-API name and a GSS-API context is
 * established with the corresponding service; the service should be
 * listening on the TCP connection s.  The default GSS-API mechanism
 * is used, and mutual authentication and replay detection are
 * requested.
 * 
 * If successful, the context handle is returned in context.  If
 * unsuccessful, the GSS-API error messages are displayed on stderr
 * and -1 is returned.
 */
int CGSSDocument::GSSClientEstablishContext (
	SOCKET s,
	char *service_name,
	gss_ctx_id_t *gss_context)
{
	gss_buffer_desc send_tok, recv_tok, *token_ptr;
	gss_name_t target_name;
	OM_uint32 maj_stat, min_stat;

	/*
	 * Import the name into target_name.  Use send_tok to save
	 * local variable space.
	 */
	send_tok.value = service_name;
	send_tok.length = strlen (service_name) + 1;
	maj_stat = gss_import_name (	&min_stat,
									&send_tok,
									(gss_OID) gss_nt_service_name,
									&target_name);
	if (maj_stat != GSS_S_COMPLETE)
	{
		GSSDisplayStatus ("parsing name", maj_stat, min_stat);
		return -1;
	}

	/*
	 * Perform the context-establishement loop.
	 *
	 * On each pass through the loop, token_ptr points to the token
	 * to send to the server (or GSS_C_NO_BUFFER on the first pass).
	 * Every generated token is stored in send_tok which is then
	 * transmitted to the server; every received token is stored in
	 * recv_tok, which token_ptr is then set to, to be processed by
	 * the next call to gss_init_sec_context.
	 * 
	 * GSS-API guarantees that send_tok's length will be non-zero
	 * if and only if the server is expecting another token from us,
	 * and that gss_init_sec_context returns GSS_S_CONTINUE_NEEDED if
	 * and only if the server has another token to send us.
	 */
	
	token_ptr = GSS_C_NO_BUFFER;
	*gss_context = GSS_C_NO_CONTEXT;

	do
	{
		maj_stat = gss_init_sec_context (	&min_stat,
											GSS_C_NO_CREDENTIAL,
											gss_context,
											target_name,
											GSS_C_NULL_OID,
											GSS_C_MUTUAL_FLAG | GSS_C_REPLAY_FLAG,
											0,
											NULL,	/* no channel bindings */
											token_ptr,
											NULL,	/* ignore mech type */
											&send_tok,
											NULL,	/* ignore ret_flags */
											NULL);	/* ignore time_rec */

		if (token_ptr != GSS_C_NO_BUFFER)
			(void) gss_release_buffer (&min_stat, &recv_tok);

		if (maj_stat!=GSS_S_COMPLETE && maj_stat!=GSS_S_CONTINUE_NEEDED)
		{
			GSSDisplayStatus ("initializing context", maj_stat, min_stat);
			(void) gss_release_name (&min_stat, &target_name);
			return -1;
		}

		if (send_tok.length != 0)
		{
			if (GSSSendToken(s, &send_tok) < 0)
			{
				(void) gss_release_buffer (&min_stat, &send_tok);
				(void) gss_release_name (&min_stat, &target_name);
				return -1;
			}
		}
		(void) gss_release_buffer (&min_stat, &send_tok);

		if (maj_stat == GSS_S_CONTINUE_NEEDED)
		{
			if (GSSReceiveToken (s, &recv_tok) < 0)
			{
				(void) gss_release_name (&min_stat, &target_name);
				return -1;
			}
			token_ptr = &recv_tok;
		}
	}
	while (maj_stat == GSS_S_CONTINUE_NEEDED);

	(void) gss_release_name (&min_stat, &target_name);
	return 0;
}

/*
 * Function: send_token
 *
 * Purpose: Writes a token to a file descriptor.
 *
 * Arguments:
 *
 *	s		(r) an open file descriptor
 *	tok		(r) the token to write
 *
 * Returns: 0 on success, -1 on failure
 *
 * Effects:
 *
 * send_token writes the token length (as a network long) and then the
 * token data to the file descriptor s.	 It returns 0 on success, and
 * -1 if an error occurs or if it could not write all the data.
 */

int CGSSDocument::GSSSendToken (
	SOCKET s,
	gss_buffer_t tok)
{
	size_t ret;
	char msgString [255];

	ret = socket_write (s, (char *) &tok -> length, 4);

	if (ret < 0)
	{
		sprintf (msgString, "Error sending token length\r");
		AppendCString (msgString);
		return -1;
	}
	else if (ret != 4)
	{
		sprintf (msgString, "sending token length: %d of %d bytes written\r", ret, 4);
		AppendCString (msgString);
		return -1;
	}

// meeroh: added the cast to char*
    ret = send(s, (char*) tok -> value, tok -> length, 0);

	if (ret < 0) {
		sprintf (msgString, "Error sending data\r");
		AppendCString (msgString);
		return -1;
	}
	else if (ret != tok->length)
	{
		sprintf (msgString, "sending token data: %d of %d bytes written\r", ret, tok -> length);
		AppendCString (msgString);
		return -1;
	}

    return 0;

} /* send_token */


/*
 * Function: recv_token
 *
 * Purpose: Reads a token from a file descriptor.
 *
 * Arguments:
 *
 *	s		(r) an open file descriptor
 *	tok		(w) the read token
 *
 * Returns: 0 on success, -1 on failure
 *
 * Effects:
 * 
 * recv_token reads the token length (as a network long), allocates
 * memory to hold the data, and then reads the token data from the
 * file descriptor s.  It blocks to read the length and data, if
 * necessary.  On a successful return, the token should be freed with
 * gss_release_buffer.	It returns 0 on success, and -1 if an error
 * occurs or if it could not read all the data.
 */

int
CGSSDocument::GSSReceiveToken (
	SOCKET s,
	gss_buffer_t tok)
{
	int ret;
    unsigned long len;
	char msgString [255];

	ret = socket_read(s, (char *) &len, 4);

	if (ret < 0)
	{
		sprintf (msgString, "Error reading token length\r");
		AppendCString (msgString);
		return -1;
	} 
	else if (ret != 4)
	{
		sprintf(msgString, "Error reading token length: %d of %d bytes read\r", ret, 4);
		AppendCString (msgString);
		return -1;
     }

	tok->length = (size_t) len;

	tok->value = (char *) malloc(tok->length);

	if (tok->value == NULL)
	{
		sprintf (msgString, "Out of memory allocating token data\r");
		AppendCString (msgString);
		return -1;
	}

	ret = socket_read (s, (char *) tok->value, tok->length);

	if (ret < 0)
	{
		sprintf (msgString, "Error reading token data\r");
		AppendCString (msgString);
		free (tok->value);
		return -1;
	}

	return 0;
} /* recv_token */
