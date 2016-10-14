
#include "rtp_priv.h"
#ifndef Session_Class_H
#define Session_Class_H
class Session
{
    srtp_t srtp_session;//send_session
    srtp_policy_t *policy_;
public:
    Session();
    ~Session();

    void SetPolicy(srtp_policy_t* policy);
    bool Protect(void* hdr,int &len);
    void UnProtect(void*hdr,int &len);
};
#endif
