#include "arprequestpacket.h"
#include "string.h"
#include <assert.h>

ArpRequestPacket::ArpRequestPacket()
{
    bzero(data_, 60);
}

void ArpRequestPacket::buildPacket(const char *src_ip_address,
                                   const char *dst_ip_address,
                                   const char *src_mac_address)
{
    ether_header *ether_protocol;
    ether_protocol = (ether_header*)data_;

    u_int8_t broadcast[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
    memcpy(ether_protocol->ether_dhost, broadcast, 6);

    u_int8_t shost[6];
    int rt = ascTomac(src_mac_address, shost);
    assert(rt == 0);
    memcpy(ether_protocol->ether_shost, shost, 6);

    ether_protocol->ether_type = htons(ETHERTYPE_ARP);

    arp_header *arp_protocol;
    arp_protocol = (arp_header*)(data_ + sizeof(ether_header));
    arp_protocol->arp_hardware_type = htons(ARPHRD_ETHER);
    arp_protocol->arp_protocol_type = htons(ETHERTYPE_IP);
    arp_protocol->arp_hardware_length = 6;
    arp_protocol->arp_protocol_length = 4;
    arp_protocol->arp_operation_code = htons(ARPOP_REQUEST);

    memcpy(arp_protocol->arp_source_ethernet_address, shost, 6);
    memcpy(arp_protocol->arp_destination_ethernet_address, broadcast, 6);

    int32_t src_ip = ipTonet(src_ip_address);
    memcpy(arp_protocol->arp_source_ip_address, &src_ip, 4);

    int32_t dst_ip = ipTonet(dst_ip_address);
    memcpy(arp_protocol->arp_destination_ip_address, &dst_ip, 4);


}
