
#include <stdio.h>          /* for printf, fprintf */
#include <stdlib.h>         /* for atoi()          */
#include <errno.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>


#include <unistd.h>         /* for close()         */
#include <sys/socket.h>

# include <arpa/inet.h>
#include "crypto_types.h"
#include "rtp_priv.h"

#include "SrtpCall.h"


Session::Session():policy_(0)
{

}

Session::~Session()
{

}

//java use this function to set policy
void Session::SetPolicy(srtp_policy_t* policy)
{
    //convert java class policy param to cpp policy param
    err_status_t status= srtp_create(&srtp_session,policy);
}

//protect function
bool Session::Protect(void* hdr,int &len)
{
    //copy data to manage buff
    //protect
     err_status_t status=srtp_protect(srtp_session,hdr,&len);
     if(status)
     {

     }
     return true;
     //apply databuf and copy data to enc_data_buff then return
}

void Session::UnProtect(void *hdr, int &len)
{
    err_status_t status=srtp_unprotect(srtp_session,hdr,&len);
}




