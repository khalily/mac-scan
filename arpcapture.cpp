#include "arpcapture.h"

#include "comhdr.h"

#include "string.h"
#include "assert.h"

bool ARPCapture::isArp_ = false;
bool ARPCapture::isArpReply_ = false;

Queue<arp_header> ARPCapture::arp_queue;

ARPCapture::ARPCapture()
{
    packetCallback_ = arpProtocolPacketCallback;
    net_interface_ = NULL;
    pcap_handle_ = NULL;
    bpf_filter_string_ = "arp";
    promisc_ = 0;

}

void ARPCapture::init()
{
    bpf_u_int32 net_ip;
    bpf_u_int32 net_mask;
    assert(net_interface_);
    if (pcap_lookupnet(net_interface_, &net_ip, &net_mask, error_content_) == -1) {
        net_ip = 0;
        net_mask = 0;
        qDebug() << "Couldn't get mask for device " << net_interface_;
        return;
    }

    pcap_handle_ = pcap_open_live(net_interface_, BUFSIZ, promisc_, -1, error_content_);
    if (pcap_handle_ == NULL) {
        qDebug() << "Couldn't open device " << net_interface_ << ": " << error_content_;
        return;
    }

    assert(bpf_filter_string_);
    struct bpf_program bpf_filter;
    if (pcap_compile(pcap_handle_, &bpf_filter, bpf_filter_string_, 0, net_mask) == -1) {
        qDebug() << "Counldn't parse filter " <<
                    bpf_filter_string_ << ": " << pcap_geterr(pcap_handle_);
        return;
    }

    if (pcap_setfilter(pcap_handle_, &bpf_filter) == -1) {
        qDebug() << "Couldn't install filter " <<
                    bpf_filter_string_ << ": " << pcap_geterr(pcap_handle_);
        return;
    }

    if (pcap_datalink(pcap_handle_) != DLT_EN10MB) {
        qDebug() << "Device " << net_interface_
                 << "does't provide Ethernet headers - not supported";
        return;
    }
}

void ARPCapture::loopCapture(int count)
{
    if (pcap_loop(pcap_handle_, count, packetCallback_, NULL) == -1) {
        qDebug() << "pcap_loop occur an error: " << pcap_geterr(pcap_handle_);
        return;
    }
}

void ARPCapture::arpProtocolPacketCallback(u_char *argument,
                                           const pcap_pkthdr *packet_header,
                                           const u_char *packet_content)
{
    ethernetProtocolPacketCallback(argument, packet_header, packet_content);
    if (!isArp_) {
        return;
    }

    struct arp_header *arp_protocol;
    arp_protocol = (struct arp_header*)(packet_content + 14);

    u_short operation_code = ntohs(arp_protocol->arp_operation_code);

    switch (operation_code) /* 根据操作码进行判断是ARP什么类型协议 */
    {
        case 1:
//            qDebug() << "ARP Request Protocol";
            break;
            /* 是ARP查询协议 */
        case 2:
//            qDebug() << "ARP Reply Protocol";
            isArpReply_ = true;
            break;
            /* 是ARP应答协议 */
        case 3:
            qDebug() << "RARP Request Protocol";
            break;
            /* 是RARP查询协议 */
        case 4:
            qDebug() << "RARP Reply Protocol";
            break;
            /* 是RARP应答协议 */
        default:
            qDebug() << operation_code << "unknow protocol";
            break;
    }

    if (!isArpReply_)
        return;

    struct arp_header arp;
    memcpy(&arp, arp_protocol, sizeof(struct arp_header));
    arp_queue.enqueue(arp);
    isArpReply_ = false;
    isArp_ = false;
}

void ARPCapture::ethernetProtocolPacketCallback(u_char *argument,
                                                const pcap_pkthdr *packet_header,
                                                const u_char *packet_content)
{
    ether_header *ether_protocol;
    u_int16_t ether_type;

    ether_protocol = (ether_header*)packet_content;
    ether_type = ntohs(ether_protocol->ether_type);

    switch (ether_type) {
        case 0x0800:
            qDebug() << "The network layer is IP protocol";
            break;
        case 0x0806:
//            qDebug() << "The network layer is ARP protocol";
            isArp_ = true;
            break;
        case 0x8035:
            qDebug() << "The network layer is RARP protocol";
            break;
        default:
            qDebug() << ether_type << "unknow protocol";
            break;
    }

}
