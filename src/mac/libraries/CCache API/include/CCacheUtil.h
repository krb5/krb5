#include "CCache.h"

#define kCredsMatch 1
#define kCredsDiffer 0

// ----- Prototypes for Private Functions ------------------
cred_union **	newCredBuffer(ccache_p *nc);
int credBufferInsert(ccache_p* nc,  cred_union creds);
int credBufferRemove(ccache_p* nc, const cred_union cred_to_remove);

char credcmp (cred_union a, cred_union b);

char isLockOurs(const ccache_p *nc);

int copyDataObj(cc_data *obj, cc_data src);
int copyV5Cred(cred_union src, cred_union **dest);
int copyV4Cred(cred_union src, cred_union **dest);
int dupNC(ccache_p* src, ccache_p** dest);
void copyDataArray(cc_data **src, cc_data ***dest);

void disposeDataArray(cc_data **base);
int cc_free_cred_internals(cred_union *creds);
int freeNCList(apiCB *cntrlBlock);
int disposeCredBuffer(apiCB *cc_ctx, ccache_p *nc);

Ptr NewSafePtr(long size);
Ptr NewSafePtrSys(long size);
void DisposeSafePtr(Ptr safeP);
