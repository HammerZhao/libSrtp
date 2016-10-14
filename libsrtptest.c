



#include <stdio.h>          /* for printf, fprintf */
#include <stdlib.h>         /* for atoi()          */
#include <errno.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>




#include <unistd.h>         /* for close()         */
# include <sys/socket.h>



# include <arpa/inet.h>
#include "crypto_types.h"
#include "rtp_priv.h"







static char* intput_k="c1eec3717da76195bb878578790af71c4ee9f859e197a414a78d5abc7451";

int base64_string_to_octet_string(char *out, int *pad, char *in, int len);
static err_status_t srtp_session_print_policy(srtp_t srtp);
static err_status_t srtp_print_policy(const srtp_policy_t *policy);


int
init(rtp_msg_t* message,
        unsigned int ssrc) {

  /* set header values */

  message->header.ssrc    = htonl(ssrc);
  message->header.ts      = 0;
  message->header.seq     = (uint16_t) rand();
  message->header.m       = 0;
  message->header.pt      = 0x1;
  message->header.version = 2;
  message->header.p       = 0;
  message->header.x       = 0;
  message->header.cc      = 0;
  /* set other stuff */
  return 0;
}


/*
 * srtp policy definitions - these definitions are used above
 */

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

srtp_hdr_t *
srtp_create_test_packet (int pkt_octet_len, uint32_t ssrc);

err_status_t my_srtp_test( const srtp_policy_t *policy, int extension_header);

int main (int argc, char *argv[])
{
    err_status_t status=srtp_init();

    my_srtp_test(&default_policy,0);

}


err_status_t my_srtp_test( const srtp_policy_t *policy, int extension_header)
{
    int i;
    srtp_t srtp_sender;//send_session
    srtp_t srtp_rcvr;//recv_session
    err_status_t status = err_status_ok;
    srtp_hdr_t *hdr, *hdr2;
    uint8_t hdr_enc[64];
    uint8_t *pkt_end;
    int msg_len_octets, msg_len_enc;
    int len;
    int tag_length = policy->rtp.auth_tag_len;
    uint32_t ssrc;
    srtp_policy_t *rcvr_policy;
    srtp_policy_t tmp_policy;
    int header = 1;
    ssrc = 0xdecafbad;

    status=srtp_create(&srtp_sender, policy);
    if(status)
    {
        printf("create session error");
    }

    /*
     * initialize data buffer, using the ssrc in the policy unless that
     * value is a wildcard, in which case we'll just use an arbitrary
     * one
     */
    if (policy->ssrc.type != ssrc_specific) {
        ssrc = 0xdecafbad;
    } else{
        ssrc = policy->ssrc.value;
    }
    msg_len_octets = 28;

    //create test package
    hdr = srtp_create_test_packet(msg_len_octets, ssrc);
    hdr2 = srtp_create_test_packet(msg_len_octets, ssrc);


    if (hdr == NULL) {
        free(hdr2);
        return err_status_fail;
    }
    if (hdr2 == NULL) {
        free(hdr);
        return err_status_fail;
    }
    len = msg_len_octets;

    status=srtp_protect(srtp_sender, hdr, &len);

    /* save protected message and length */
    memcpy(hdr_enc, hdr, len);
    msg_len_enc = len;
    /*
     * check for overrun of the srtp_protect() function
     *
     * The packet is followed by a value of 0xfffff; if the value of the
     * data following the packet is different, then we know that the
     * protect function is overwriting the end of the packet.
     */
    pkt_end = (uint8_t*)hdr + sizeof(srtp_hdr_t)
              + msg_len_octets + tag_length;
    for (i = 0; i < 4; i++) {
        if (pkt_end[i] != 0xff) {
            fprintf(stdout, "overwrite in srtp_protect() function "
                    "(expected %x, found %x in trailing octet %d)\n",
                    0xff, ((uint8_t*)hdr)[i], i);
            free(hdr);
            free(hdr2);
            return err_status_fail;
        }
    }


    /*
     * if the policy uses a 'wildcard' ssrc, then we need to make a copy
     * of the policy that changes the direction to inbound
     *
     * we always copy the policy into the rcvr_policy, since otherwise
     * the compiler would fret about the constness of the policy
     */
    rcvr_policy = (srtp_policy_t*) malloc(sizeof(srtp_policy_t));
    if (rcvr_policy == NULL) {
      free(hdr);
      free(hdr2);
      return err_status_alloc_fail;
    }
    memcpy(rcvr_policy, policy, sizeof(srtp_policy_t));
    if (policy->ssrc.type == ssrc_any_outbound) {
      rcvr_policy->ssrc.type = ssrc_any_inbound;
    }
    srtp_create(&srtp_rcvr, rcvr_policy);
    srtp_unprotect(srtp_rcvr, hdr, &len);
    /* verify that the unprotected packet matches the origial one */
    for (i=0; i < msg_len_octets; i++)
      if (((uint8_t *)hdr)[i] != ((uint8_t *)hdr2)[i]) {
        fprintf(stdout, "mismatch at octet %d\n", i);
        status = err_status_algo_fail;
      }
    if (status) {
      free(hdr);
      free(hdr2);
      free(rcvr_policy);
      return status;
    }


    return status;
}



static void TestAnother()
{
    err_status_t status=0;

    srtp_policy_t policy;

    sec_serv_t sec_servs = sec_serv_none;

    uint32_t ssrc = 0xdeadbeef; /* ssrc value hardcoded for now */

    char key[96];
    status = srtp_init();

    sec_servs |= sec_serv_conf;
    sec_servs |= sec_serv_auth;



    crypto_policy_set_rtp_default(&policy.rtp);
    crypto_policy_set_rtcp_default(&policy.rtcp);


    policy.ssrc.type  = ssrc_specific;
    policy.ssrc.value = ssrc;
    policy.key  = (uint8_t *) key;
    policy.ekt  = NULL;
    policy.next = NULL;
    policy.window_size = 128;
    policy.allow_repeat_tx = 0;
    policy.rtp.sec_serv = sec_servs;
    policy.rtcp.sec_serv = sec_serv_none;  /* we don't do RTCP anyway */

    srtp_t session;
   // srtp_ctx_t  *p_srtp_cxt=(srtp_ctx_t*)malloc(sizeof(srtp_ctx_t));

    status=srtp_create(&session,&policy);
    if(status)
    {
        printf("create srtp session error");
    }
    int expected_len = policy.rtp.cipher_key_len*2;
    int pad=0;
    int len=hex_string_to_octet_string(key,intput_k,expected_len);
    //int len = hex_string_to_octet_string(key, &pad, intput_k, expected_len);
    rtp_msg_t msg;

    //send process
    char *src="AA";
    /* marshal data */
    strncpy(msg.body,src,2);

    int pkt_len = 2 + RTP_HEADER_LEN;
    /* update header */
    msg.header.seq = ntohs(msg.header.seq) + 1;
    msg.header.seq = htons(msg.header.seq);
    msg.header.ts = ntohl(msg.header.ts) + 1;
    msg.header.ts = htonl(msg.header.ts);

    status = srtp_protect(session, &msg.header, &pkt_len);
    if(status)
    {
        printf("protect error");
    }
}



static err_status_t srtp_session_print_policy(srtp_t srtp) {
  char *serv_descr[4] = {
    "none",
    "confidentiality",
    "authentication",
    "confidentiality and authentication"
  };
  char *direction[3] = {
    "unknown",
    "outbound",
    "inbound"
  };
  srtp_stream_t stream;

  /* sanity checking */
  if (srtp == NULL)
    return err_status_fail;

  /* if there's a template stream, print it out */
  if (srtp->stream_template != NULL) {
    stream = srtp->stream_template;
    printf("# SSRC:          any %s\r\n"
       "# rtp cipher:    %s\r\n"
       "# rtp auth:      %s\r\n"
       "# rtp services:  %s\r\n"
           "# rtcp cipher:   %s\r\n"
       "# rtcp auth:     %s\r\n"
       "# rtcp services: %s\r\n"
       "# window size:   %lu\r\n"
       "# tx rtx allowed:%s\r\n",
       direction[stream->direction],
       stream->rtp_cipher->type->description,
       stream->rtp_auth->type->description,
       serv_descr[stream->rtp_services],
       stream->rtcp_cipher->type->description,
       stream->rtcp_auth->type->description,
       serv_descr[stream->rtcp_services],
       rdbx_get_window_size(&stream->rtp_rdbx),
       stream->allow_repeat_tx ? "true" : "false");
  }

  /* loop over streams in session, printing the policy of each */
  stream = srtp->stream_list;
  while (stream != NULL) {
    if (stream->rtp_services > sec_serv_conf_and_auth)
      return err_status_bad_param;

    printf("# SSRC:          0x%08x\r\n"
       "# rtp cipher:    %s\r\n"
       "# rtp auth:      %s\r\n"
       "# rtp services:  %s\r\n"
           "# rtcp cipher:   %s\r\n"
       "# rtcp auth:     %s\r\n"
       "# rtcp services: %s\r\n"
       "# window size:   %lu\r\n"
       "# tx rtx allowed:%s\r\n",
       stream->ssrc,
       stream->rtp_cipher->type->description,
       stream->rtp_auth->type->description,
       serv_descr[stream->rtp_services],
       stream->rtcp_cipher->type->description,
       stream->rtcp_auth->type->description,
       serv_descr[stream->rtcp_services],
       rdbx_get_window_size(&stream->rtp_rdbx),
       stream->allow_repeat_tx ? "true" : "false");

    /* advance to next stream in the list */
    stream = stream->next;
  }
  return err_status_ok;
}

static err_status_t srtp_print_policy(const srtp_policy_t *policy) {
  err_status_t status;
  srtp_t session;

  status = srtp_create(&session, policy);
  if (status)
    return status;
  status = srtp_session_print_policy(session);
  if (status)
    return status;
  status = srtp_dealloc(session);
  if (status)
    return status;
  return err_status_ok;
}



/*
 * srtp_create_test_packet(len, ssrc) returns a pointer to a
 * (malloced) example RTP packet whose data field has the length given
 * by pkt_octet_len and the SSRC value ssrc.  The total length of the
 * packet is twelve octets longer, since the header is at the
 * beginning.  There is room at the end of the packet for a trailer,
 * and the four octets following the packet are filled with 0xff
 * values to enable testing for overwrites.
 *
 * note that the location of the test packet can (and should) be
 * deallocated with the free() call once it is no longer needed.
 */

srtp_hdr_t *
srtp_create_test_packet (int pkt_octet_len, uint32_t ssrc)
{
    int i;
    uint8_t *buffer;
    srtp_hdr_t *hdr;
    int bytes_in_hdr = 12;

    /* allocate memory for test packet */
    hdr = (srtp_hdr_t*)malloc(pkt_octet_len + bytes_in_hdr
                              + SRTP_MAX_TRAILER_LEN + 4);
    if (!hdr) {
        return NULL;
    }

    hdr->version = 2;              /* RTP version two     */
    hdr->p    = 0;                 /* no padding needed   */
    hdr->x    = 0;                 /* no header extension */
    hdr->cc   = 0;                 /* no CSRCs            */
    hdr->m    = 0;                 /* marker bit          */
    hdr->pt   = 0xf;               /* payload type        */
    hdr->seq  = htons(0x1234);     /* sequence number     */
    hdr->ts   = htonl(0xdecafbad); /* timestamp           */
    hdr->ssrc = htonl(ssrc);       /* synch. source       */

    buffer = (uint8_t*)hdr;
    buffer += bytes_in_hdr;

    /* set RTP data to 0xab */
    for (i = 0; i < pkt_octet_len; i++) {
        *buffer++ = 0xab;
    }

    /* set post-data value to 0xffff to enable overrun checking */
    for (i = 0; i < SRTP_MAX_TRAILER_LEN + 4; i++) {
        *buffer++ = 0xff;
    }

    return hdr;
}

static  char b64chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
  "abcdefghijklmnopqrstuvwxyz0123456789+/";

static int base64_block_to_octet_triple(char *out, char *in) {
  unsigned char sextets[4] = {};
  int j = 0;
  int i;

  for (i = 0; i < 4; i++) {
    char *p = strchr(b64chars, in[i]);
    if (p != NULL) sextets[i] = p - b64chars;
    else j++;
  }

  out[0] = (sextets[0]<<2)|(sextets[1]>>4);
  if (j < 2) out[1] = (sextets[1]<<4)|(sextets[2]>>2);
  if (j < 1) out[2] = (sextets[2]<<6)|sextets[3];
  return j;
}

int base64_string_to_octet_string(char *out, int *pad, char *in, int len) {
  int k = 0;
  int i = 0;
  int j = 0;
  if (len % 4 != 0) return 0;

  while (i < len && j == 0) {
    j = base64_block_to_octet_triple(out + k, in + i);
    k += 3;
    i += 4;
  }
  *pad = j;
  return i;
}



