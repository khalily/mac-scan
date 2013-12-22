#ifndef COMHDR_H
#define COMHDR_H

#include <pcap.h>
#include <arpa/inet.h> // htons
#include <errno.h> // errno
#include <string.h> // strerror()
#include <stdlib.h> // exit()
#include <QDebug>

#define ETH_P_ARP 0x0806
#define ETHERTYPE_ARP 0x0806
#define ARPHRD_ETHER 1
#define ETHERTYPE_IP 0x0800
#define ARPOP_REQUEST 1

struct arp_header
{
    u_int16_t arp_hardware_type;
    /* 硬件地址类型 */
    u_int16_t arp_protocol_type;
    /* 协议地址类型 */
    u_int8_t arp_hardware_length;
    /* 硬件地址长度 */
    u_int8_t arp_protocol_length;
    /* 协议地址长度 */
    u_int16_t arp_operation_code;
    /* 操作类型 */
    u_int8_t arp_source_ethernet_address[6];
    /* 源以太网地址 */
    u_int8_t arp_source_ip_address[4];
    /* 源IP地址 */
    u_int8_t arp_destination_ethernet_address[6];
    /* 目的以太网地址 */
    u_int8_t arp_destination_ip_address[4];
    /* 目的IP地址 */
};

struct ether_header
{
    u_int8_t ether_dhost[6];
    /* 目的以太网地址 */
    u_int8_t ether_shost[6];
    /* 源以太网地址 */
    u_int16_t ether_type;
    /* 以太网类型 */
};

const char * strErr();

#endif // COMHDR_H
