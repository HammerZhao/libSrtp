

#include <stdio.h>          /* for printf, fprintf */
#include <stdlib.h>         /* for atoi()          */
#include <errno.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

# include <arpa/inet.h>
#include "crypto_types.h"
#include "rtp_priv.h"
#include "SrtpCall.h"
#include "libSrtpProxy.h"

unsigned char test_key[46] = {
    0xe1, 0xf9, 0x7a, 0x0d, 0x3e, 0x01, 0x8b, 0xe0,
    0xd6, 0x4f, 0xa3, 0x2c, 0x06, 0xde, 0x41, 0x39,
    0x0e, 0xc6, 0x75, 0xad, 0x49, 0x8a, 0xfe, 0xeb,
    0xb6, 0x96, 0x0b, 0x3a, 0xab, 0xe6, 0xc1, 0x73,
    0xc3, 0x17, 0xf2, 0xda, 0xbe, 0x35, 0x77, 0x93,
    0xb6, 0x96, 0x0b, 0x3a, 0xab, 0xe6
};

srtp_policy_t default_policy = {
  { ssrc_specific, 0xdecafbad },  /* SSRC                           */
  {                      /* SRTP policy                    */
    AES_128_ICM,            /* cipher type                 */
    30,                     /* cipher key length in octets */
    HMAC_SHA1,              /* authentication func type    */
    16,                     /* auth key length in octets   */
    10,                     /* auth tag length in octets   */
    sec_serv_conf_and_auth  /* security services flag      */
  },
  {                      /* SRTCP policy                   */
    AES_128_ICM,            /* cipher type                 */
    30,                     /* cipher key length in octets */
    HMAC_SHA1,              /* authentication func type    */
    16,                     /* auth key length in octets   */
    10,                     /* auth tag length in octets   */
    sec_serv_conf_and_auth  /* security services flag      */
  },
  test_key,
  NULL,        /* indicates that EKT is not in use */
  128,         /* replay window size */
  0,           /* retransmission not allowed */
  NULL
};


int main(int argc, char *argv[])
{
    LibSrtpProxy::GetInstance().Init();
    LibSrtpProxy::CreateSrtpSession(&default_policy,test_key);


    //LibSrtpProxy::
    //Session rtpsession;
    //err_status_t status=srtp_init();
    //rtpsession.SetPolicy(&default_policy);
    return 0;
}

