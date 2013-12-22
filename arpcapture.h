#ifndef ARPCAPTURE_H
#define ARPCAPTURE_H

#include "comhdr.h"
#include "queue.hpp"

class ARPCapture
{
public:
    ARPCapture();
    void setDevice(const char* device) {
        net_interface_ = device;
    }
    void setFilter(const char* filter) {
        bpf_filter_string_ = filter;
    }
    void setPromisc(int promisc) {
        promisc_ = promisc;
    }
    void setPacketCallback(pcap_handler cb) {
        packetCallback_ = cb;
    }
    void init();
    void loopCapture(int count);

private:
    pcap_handler packetCallback_;

    char error_content_[PCAP_ERRBUF_SIZE];
    const char *net_interface_;
    const char *bpf_filter_string_;
    int promisc_;

    static void arpProtocolPacketCallback(u_char *argument,
                                          const pcap_pkthdr *packet_header,
                                          const u_char *packet_content);

    static void ethernetProtocolPacketCallback(u_char *argument,
                                               const pcap_pkthdr *packet_header,
                                               const u_char *packet_content);

    static bool isArpReply_;
    static bool isArp_;
public:
    static Queue<arp_header> arp_queue;

    pcap_t *pcap_handle_;
};

#endif // ARPCAPTURE_H
