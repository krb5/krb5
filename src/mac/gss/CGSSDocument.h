#include <LSingleDoc.h>
#include "gss.h"

class CGSSDocument:
	public LSingleDoc,
	public LListener
{
	public:
		CGSSDocument ();
		~CGSSDocument ();
		void	ListenToMessage (
					MessageT	inMessage,
					void*		ioParam);
		Boolean	ObeyCommand (
					CommandT	inCommand,
					void		*ioParam);
		void	GSSQuery (
					char*				inQueryString);
		void	HandleAppleEvent (
					const AppleEvent&	inAppleEvent,
					AppleEvent&			outAEReply,
					AEDesc&				outResult,
					long				inAENumber);
		void	DoAESave(
					FSSpec&	inFileSpec,
					OSType	inFileType);


	private:
		void	AppendPString (
					ConstStringPtr		inString);
		void	AppendCString (
					char*				inString);
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
};