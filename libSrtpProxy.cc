#include "libSrtpProxy.h"
#include "crypto_types.h"
#include "rtp_priv.h"
#include "SrtpCall.h"

LibSrtpProxy LibSrtpProxy::proxy_;

LibSrtpProxy::LibSrtpProxy()
{

}

LibSrtpProxy::~LibSrtpProxy()
{

}

const LibSrtpProxy &LibSrtpProxy::GetInstance()
{
    return proxy_;
}

void LibSrtpProxy::Init()
{
   err_status_t status=srtp_init();
}

Session* LibSrtpProxy::CreateSrtpSession(srtp_policy_t plicy,unsigned char* key)
{
    Session* sess=new Session();
    sess->SetPolicy(&plicy);
    session_list_.push_back(sess);
    return sess;
}

void LibSrtpProxy::Protected(void* buf,Session* ses)
{
    int len;
    ses->Protect(buf,len);
}

void LibSrtpProxy::UnProtected(void *buf,Session* ses)
{
    int len;
}
