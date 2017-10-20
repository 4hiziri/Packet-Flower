#include <stdio.h>
#include <libnet.h>
#include <errno.h>

struct t_pack
{
   struct libnet_ipv4_hdr ip;
   struct libnet_tcp_hdr tcp;
};


void usage(char *name)
{
   fprintf(stderr,"usage: %s -t target_ip.target_port\n", name);
}


int main(int argc, char **argv)
{
   libnet_t *libfd;
   libnet_ptag_t tcp_ptag;
   libnet_ptag_t ip_ptag;
   int options;
   int retval;
   char *cp;
   char errbuf[LIBNET_ERRBUF_SIZE];

   uint32_t dst_ip = 0;
   uint32_t src_ip = 0;
   uint16_t dst_prt = 0;
   uint16_t src_prt = 0;

   libfd = libnet_init(LIBNET_RAW4, NULL, errbuf);

   if (libfd == NULL){
      fprintf(stderr, "libnet_init() failed: %s\n", errbuf);
      exit(EXIT_FAILURE);
   }

   while((options = getopt(argc, argv, "t:")) != EOF){
      switch (options){
         case 't':
            if(!(cp = strrchr(optarg, '.'))){
               usage(argv[0]);
               exit(EXIT_FAILURE);
            }
            *cp++ = 0;
            dst_prt = (uint16_t)atoi(cp);
            if((dst_ip = libnet_name2addr4
                (libfd, optarg, LIBNET_RESOLVE)) == -1){
               fprintf(stderr, "Bad IP address: %s\n", optarg);
               exit(EXIT_FAILURE);
            }
            printf("getoptpt_t:%x\n", dst_ip);
            break;
         default:
            usage(argv[0]);
            exit(EXIT_FAILURE);
      }
   }

   if(!dst_prt || !dst_ip){
      usage(argv[0]);
      exit(EXIT_FAILURE);
   }

   libnet_seed_prand(libfd);
   tcp_ptag = LIBNET_PTAG_INITIALIZER;

   tcp_ptag = libnet_build_tcp(
        src_prt = libnet_get_prand(LIBNET_PRu16),  //source port
        dst_prt,  //destination port
        libnet_get_prand(LIBNET_PRu32),  //sequense number
        libnet_get_prand(LIBNET_PRu32),  //acknoeledge number
        TH_SYN,   //control
        libnet_get_prand(LIBNET_PRu16),  //windowsize
        0,  //checksum
        0,  //urgent pointer
        LIBNET_TCP_H,  //length
        NULL,  //payload
        0,  //payload size
        libfd,  //libfd
        tcp_ptag);  //ptag

   ip_ptag = LIBNET_PTAG_INITIALIZER;
   ip_ptag = libnet_build_ipv4(
      LIBNET_TCP_H + LIBNET_IPV4_H,  //length
      0,  //type of service
      libnet_get_prand(LIBNET_PRu16),  //id
      0,  //frag
      libnet_get_prand(LIBNET_PR8),  //ttl
      IPPROTO_TCP,  //protocol
      0,  //checksum
      src_ip = libnet_get_prand(LIBNET_PRu32),  //source IP
      dst_ip,  //destination IP
      NULL,  //payload
      0,  //payload size
      libfd,  //libfd
      0);  //ptag

   retval = libnet_write(libfd);
   if(retval == -1){
      fprintf(stderr, "libnet_write: %s\n", libnet_geterror(libfd));
      exit(EXIT_FAILURE);
   }

   libnet_destroy(libfd);
   exit(EXIT_SUCCESS);
   return 0;
}
