// ===========================================================================
//	CGSSdocument.h
//	©1997 Massachusetts Institute of Technology, All Rights Reserved
//	By meeroh@mit.edu
//	Started 2/28/97
// ===========================================================================

#pragma once

#include <LSingleDoc.h>
#include "gss.h"

// AppleEvent reference number for the query event
const	long		ae_Query			= 4001;

class CGSSDocument:
	public LSingleDoc,
	public LListener
{
	public:
		// Constructors / destuctors
		CGSSDocument ();
		~CGSSDocument ();
		
		// Overrides from LListener
		
		virtual	void	ListenToMessage (
					MessageT	inMessage,
					void*		ioParam);
					
		// Overrides from LSingleDoc
		
		virtual	Boolean	ObeyCommand (
					CommandT	inCommand,
					void		*ioParam);
		virtual	void	HandleAppleEvent (
					const AppleEvent&	inAppleEvent,
					AppleEvent&			outAEReply,
					AEDesc&				outResult,
					long				inAENumber);
		virtual	void	DoAESave(
					FSSpec&	inFileSpec,
					OSType	inFileType);
					
		// Interface to GSS
		// The query string has the format:
		// [-port port] [-v2] host service msg
		// e.g.,
		// -port 13136 dcl.mit.edu sample@dcl.mit.edu hi
		
		void	GSSQuery (
					char*				inQueryString);

	private:
		// GSS calls
		int		GSSCallServer	(
					char *host,
					u_short port,
					int dov2,
					char *service_name,
					char *msg);
		void	GSSDisplayStatus (
					char *msg,
					OM_uint32 maj_stat,
					OM_uint32 min_stat);
		int		GSSClientEstablishContext (
					SOCKET s,
					char *service_name,
					gss_ctx_id_t *gss_context);
		SOCKET	GSSConnectToServer (
					char *host,
					u_short port);		
		int		GSSSendToken(
					SOCKET s,
					gss_buffer_t tok);
		int		GSSReceiveToken (
					SOCKET s,
					gss_buffer_t tok);
					
		// String display utilities
		void	AppendPString (
					ConstStringPtr		inString);
		void	AppendCString (
					char*				inString);
};