#ifndef __WorkItem
#define __WorkItem

#include <list>
#include "windows.h"

extern "C" {
    #include "cci_stream.h"
    #include "ccs_pipe.h"
    }

class WorkItem {
private:
    cci_stream_t	_buf;
    WIN_PIPE*		_pipe;
    const long		_rpcmsg;
    const long		_sst;
public:
    WorkItem(  cci_stream_t  buf, 
              WIN_PIPE*     pipe, 
              const long    type, 
              const long    serverStartTime);
    WorkItem(	const         WorkItem&);
    WorkItem();
    ~WorkItem();

    const cci_stream_t  payload()       const   {return _buf;}
    const cci_stream_t  take_payload();
          WIN_PIPE*     take_pipe();
          WIN_PIPE*     pipe()          const   {return _pipe;}
    const long          type()          const   {return _rpcmsg;}
    const long          sst()           const   {return _sst;}
    char*               print(char* buf);
    };

class WorkList {
private:
    std::list <WorkItem*>   wl;
    CRITICAL_SECTION        cs;
public:
    WorkList();
    ~WorkList();
    int		add(WorkItem*);
    int		remove(WorkItem**);
    bool	isEmpty();
    };

#endif  // __WorkItem