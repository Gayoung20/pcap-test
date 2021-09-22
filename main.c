#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdint.h>
#include "libnet.h"
#include <arpa/inet.h>
#include "print.h"

void usage() {
    printf("syntax: pcap-test <interface>\n");
    printf("sample: pcap-test wlan0\n");
}

typedef struct {
    char* dev_;
} Param;

Param param = {
    .dev_ = NULL
};

bool parse(Param* param, int argc, char* argv[]) {
    if(argc != 2) {
        usage();
        return false;
    }
    param->dev_ = argv[1];
    return true;
}

int main(int argc, char* argv[]) {
    if(!parse(&param, argc, argv)) 
        return -1;

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
    if(pcap == NULL) {
        fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
        return -1;
    } 

    int j = 0;
    while(true) {
        j++;
        printf("%d\n", j);

        struct pcap_pkthdr* header;
        const u_char* packet;
        uint32_t packet_location = 0;

        int res = pcap_next_ex(pcap, &header, &packet);
        if(res == 0) continue;
        if(res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
            break;
        }
        
        // ethernet
        struct libnet_ethernet_hdr* eth;
	    char ethchar[14];
        int i;

        for(i=0; i<14; i++) {
            ethchar[i] = packet[packet_location];
            packet_location++;        
        }

	    eth = (struct libnet_etherent_hdr*) ethchar;

        if((eth->ether_type) != 0x0008) {
            printf("it's not ipv4\n\n");
            continue;
        }

        //ipv4
        struct libnet_ipv4_hdr* ip;
	    char ipchar[20];

        for(i=0; i<20; i++) {
            ipchar[i] = packet[packet_location];
            packet_location++;
        }

	    ip = (struct libnet_ipv4_hdr*)ipchar;

        if((ip->ip_p) != 0x06) {
            printf("it's not TCP\n\n");
            continue;
        }

        //tcp
        struct libnet_tcp_hdr* tcp;
	    char tcpchar[20];

        for(i=0; i<20; i++) {
            tcpchar[i] = packet[packet_location];
            packet_location++;
        }

	    tcp = (struct libnet_tcp_hdr*)tcpchar;

        mac_print(eth);
        ip_print(ip);
        port_print(tcp);

        //data
        packet_location = packet_location - 20;
        packet_location = packet_location + (tcp->th_off)*4;
        int gap = (header->caplen) - packet_location;
        if(gap > 8) {
            for(i=0; i<8; i++) {
                printf("%02x", packet[packet_location]);
                packet_location++;
            }
            printf("\n");
        } else if (gap == 0) {
            printf("no data\n");
        } else if ((gap <= 8) && (gap > 0)) {
            for(i=0; i<gap; i++) {
                printf("%02x", packet[packet_location]);
                packet_location++;
            }
            printf("\n");
        }
        printf("\n");
    }
    
    pcap_close(pcap);
}
