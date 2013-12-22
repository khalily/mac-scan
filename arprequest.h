#ifndef ARPREQUEST_H
#define ARPREQUEST_H

#include "arprequestpacket.h"
#include "comhdr.h"
#include "sys/socket.h"
#include "unistd.h"

#include <set>
#include <string>

class ARPRequest
{
public:
    ARPRequest(const char* device,
               const char* local_ip,
               const char* local_mac);
    ~ARPRequest() {
        close(fd_);
    }

    void sendAllRequest(std::set<std::string> addrs);

private:
    void sendOnceRequest(const char* addr);

    const char* local_ip_;
    const char* local_mac_;
    int fd_;
    sockaddr sa_;
    ArpRequestPacket pkt_;
};

#endif // ARPREQUEST_H
