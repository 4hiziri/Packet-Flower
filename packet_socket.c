#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netpacket/packet.h>
#include <linux/if_ether.h>
#include <netinet/ip_icmp.h>

//RFC 1071
int checksum(unsigned short *buf, int bufsize) {
    unsigned long sum = 0;
    
    while(bufsize > 1) {
        sum += *buf++;
        bufsize -= 2;
    }

    if(bufsize > 0) {
        sum += *(unsigned char*)buf;
    }

    while(sum >> 16) {
        sum = (sum & 0xffff) + (sum >> 16);
    }

    return ~sum;
}


int main(int argc, char** argv) {
    struct sockaddr_ll addr;
    int i, sockfd;
    char buf[4096];
    struct ethhdr* ethheader;
    struct iphdr* ipheader;
    struct icmphdr* icmpheader;
    char* interface = "wlp2s0"; //インターフェース
    char* sipaddr = ""; //送信元ipアドレス (例えば"192.168.1.1")
    char* dipaddr = ""; //宛先ipアドレス
    char* shwaddr = "\xff\xff\xff\xff\xff\xff"; //送信元macアドレス (例えば"\x00\x00\x00\x00\x00\x00")
    char* dhwaddr = ""; //宛先macアドレス

    if((sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) == -1) {
        perror("sockfd");
        exit(1);
    }

    ethheader = (struct ethhdr*)buf;
    ipheader = (struct iphdr*)(buf + ETH_HLEN);
    icmpheader = (struct icmphdr*)(buf + ETH_HLEN + sizeof(struct iphdr));
    
    memcpy(ethheader->h_dest, dhwaddr, ETH_ALEN);
    memcpy(ethheader->h_source, shwaddr, ETH_ALEN);
    
    ethheader->h_proto = htons(0x0800);

    ipheader->version = 4;
    ipheader->ihl = 5;
    ipheader->tos = 0;
    ipheader->tot_len = htons(sizeof(struct iphdr) + sizeof(struct icmphdr));
    ipheader->id = htons(1);
    ipheader->frag_off = htons(0x4000);
    ipheader->ttl = 32;
    ipheader->protocol = 1;
    inet_pton(AF_INET, sipaddr, &ipheader->saddr);
    inet_pton(AF_INET, dipaddr, &ipheader->daddr);
    
    ipheader->check = checksum((unsigned short*)ipheader, sizeof(struct iphdr));
    
    icmpheader->type = ICMP_ECHO;
    icmpheader->code = 8;
    icmpheader->checksum = 0;
    icmpheader->un.echo.id = 0;
    icmpheader->un.echo.sequence = 0;

    icmpheader->checksum = checksum((unsigned short*)icmpheader, sizeof(struct icmphdr));

    memset(&addr, 0, sizeof(addr));

    addr.sll_family = AF_PACKET;
    addr.sll_protocol = htons(ETH_P_ALL);
    addr.sll_ifindex = if_nametoindex(interface);
    addr.sll_halen = IFHWADDRLEN;

    if((sendto(sockfd, (char*)ethheader, ETH_HLEN + sizeof(struct iphdr) + sizeof(struct icmphdr), 0, (struct sockaddr*)&addr, sizeof(addr))) == -1) {
        perror("sendto");
        exit(1);
    }

    close(sockfd);

    return 0;
}
