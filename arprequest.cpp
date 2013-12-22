#include "arprequest.h"
#include "strings.h"
#include "assert.h"
#include <iostream>

using namespace std;

ARPRequest::ARPRequest(const char *device, const char *local_ip, const char *local_mac)
{
    assert(local_ip);
    local_ip_ = local_ip;
    assert(local_mac);
    local_mac_ = local_mac;
    assert(device);
    bzero(&sa_, sizeof(sa_));
    strcpy(sa_.sa_data, device);
    fd_ = socket(AF_INET, SOCK_PACKET, htons(ETH_P_ARP));
    if (fd_ < 0) {
        cout << "create socket error: " << strErr();
        exit(-1);
    }
}

void ARPRequest::sendAllRequest(std::set<string> addrs)
{
    for (auto addr: addrs) {
        sendOnceRequest(addr.c_str());
    }
}

void ARPRequest::sendOnceRequest(const char *addr)
{
    pkt_.buildPacket(local_ip_, addr, local_mac_);
    const u_char* data = pkt_.data();
    ssize_t n = sendto(fd_, data, 60, 0, &sa_, sizeof(sa_));
    if (n != 60) {
        cout << "send error: " << strErr();
        exit(-1);
    }
}


