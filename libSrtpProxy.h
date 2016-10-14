#ifndef LibSrtpProxy_Class_H
#define LibSrtpProxy_Class_H
#include <list>
#include "rtp_priv.h"
class Session;
class LibSrtpProxy
{

private:
    std::list<Session*> session_list_;
    static LibSrtpProxy proxy_;

    LibSrtpProxy();
    LibSrtpProxy(const LibSrtpProxy& rhs);
    ~LibSrtpProxy();
public:
    static const LibSrtpProxy& GetInstance();

    void Init();

    Session* CreateSrtpSession(srtp_policy_t plicy,unsigned char* key);

    void RemoveSession(Session* ses);

    void Protected(void *buf,Session* ses);

    void UnProtected(void *buf,Session* ses);

};

#endif
