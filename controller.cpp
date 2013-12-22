#include "controller.h"

#include "comhdr.h"
#include "arpcapture.h"
#include <stdio.h>
#include <iostream>
#include <thread>

using namespace std;

atomic<bool> Controller::isOk_(false);
ARPCapture* Controller::p_arpCapture = NULL;

std::set<string> Controller::ip_addrs_;
map<string, string> Controller::ip_mac_addrs_;

void Controller::init()
{

}

void Controller::run()
{
    thread t_arpCapture(startARPCapture, device_);
    while (p_arpCapture == NULL) {
        sleep(1);
    }
    thread t_collectResult(startCollectResult);

    ARPRequest arpRequest(device_, local_ip_, local_mac_);
    int tryCount = 0;
    arpRequest.sendAllRequest(ip_addrs_);
    for(;;) {
        sleep(1);

        if (isOk_) {
            pcap_breakloop(p_arpCapture->pcap_handle_);
            printResult();
            exit(0);
        }

        tryCount++;
        if (tryCount >= 3) {
            pcap_breakloop(p_arpCapture->pcap_handle_);
            printResult();
            exit(0);
        }
    }
}

void Controller::printResult()
{
    cout << "\nADDRESS" << endl;
    cout << "==================================================" << endl;
    cout << "\n\n    IP\t\t\t      MAC\n" << endl;
    for (auto iter: ip_mac_addrs_) {
           cout << iter.first << "\t\t" << iter.second << endl;
    }
    cout << "\n\n";
}

void Controller::startARPCapture(const char* device)
{
    ARPCapture arpCapture;
    arpCapture.setDevice(device);
    arpCapture.init();
    p_arpCapture = &arpCapture;
    arpCapture.loopCapture(-1);
}

void hexToMac(u_int8_t hex[6], char* mac) {
    sprintf(mac, "%02x:%02x:%02x:%02x:%02x:%02x", hex[0], hex[1], hex[2],
            hex[3], hex[4], hex[5]);
}

void Controller::startCollectResult()
{
    while (true) {
        arp_header hdr = p_arpCapture->arp_queue.dequeue();

        in_addr addr;
        addr.s_addr = *(u_int32_t*)hdr.arp_source_ip_address;
        const char* ip = inet_ntoa(addr);

        char mac[20];
        hexToMac(hdr.arp_source_ethernet_address, mac);


        if (ip_addrs_.find(ip) != ip_addrs_.end()) {
            ip_addrs_.erase(ip);
            ip_mac_addrs_.insert(make_pair<string, string>(ip, mac));
        }

        if (ip_addrs_.empty()) {
            isOk_ = true;
            return;
        }
    }
}
