#pragma once
#include "libnet.h"

void mac_print(struct libnet_ethernet_hdr *eth);
void ip_print(struct libnet_ipv4_hdr* ip);
void port_print(struct libnet_tcp_hdr* tcp);
