#include <stdio.h>
#include "libnet.h"
#include <stdint.h>
#include "print.h"

void mac_print(struct libnet_ethernet_hdr *eth) {
    int i;
    printf("src mac : ");
    for(i=0; i<5;i++){
        printf("%02x:", eth->ether_shost[i]);
    }
    printf("%02x", eth->ether_shost[i]);
    printf("\n");

    printf("dst mac : ");
    for(i=0; i<5;i++){
        printf("%02x:", eth->ether_dhost[i]);
    }
    printf("%02x", eth->ether_dhost[i]);
    printf("\n");
}

void ip_print(struct libnet_ipv4_hdr* ip) {
    int i;
    printf("src ip : ");
    for(i=0; i<3;i++){
        printf("%d.", ip->ip_src[i]);
    }
    printf("%d", ip->ip_src[i]);
    printf("\n");

    printf("dst ip : ");
    for(i=0; i<3;i++){
        printf("%d.", ip->ip_dst[i]);
    }
    printf("%d", ip->ip_dst[i]);
    printf("\n");
}

void port_print(struct libnet_tcp_hdr* tcp) {
    int i;
    uint16_t src, dst;

    printf("src port : ");
    src = ntohs(tcp->th_sport);
    printf("%u", src);
    printf("\n");

    printf("dst port : ");
    dst = ntohs(tcp->th_dport);
    printf("%u", dst);
    printf("\n");
}
