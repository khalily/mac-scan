#ifndef ARPREQUESTPACKET_H
#define ARPREQUESTPACKET_H

#include "comhdr.h"
#include <stdlib.h>

class ArpRequestPacket
{
public:
    ArpRequestPacket();

    const u_char* data() {
        return data_;
    }

    void buildPacket(const char* src_ip_address,
                     const char* dst_ip_address,
                     const char* src_mac_address);

    static int32_t ipTonet(const char* ip_address) {
        struct in_addr addr;
        inet_aton(ip_address, &addr);
        return addr.s_addr;
    }

    static int ascTomac(const char* src_mac_address, u_int8_t mac[6]) {
        if (src_mac_address == NULL)
            return -1;
        char *endptr = NULL;
        const char *src = src_mac_address;
        for (int i = 0; i < 6; ++i) {
            mac[i] = src ? strtoul(src, &endptr, 16) : 0;
            if (src) {
                src = *endptr ? endptr + 1 : endptr;
            }
        }
        return 0;
    }

private:
    u_char data_[60];
};

#endif // ARPREQUESTPACKET_H
