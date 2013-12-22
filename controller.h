#ifndef CONTROLLER_H
#define CONTROLLER_H

#include "queue.hpp"
#include <set>
#include <map>
#include <string>
#include <atomic>

#include <arprequest.h>

class ARPCapture;

class Controller
{
public:
    Controller(const char* local_ip,
               const char* local_mac,
               const char* device) :
        local_ip_(local_ip),
        local_mac_(local_mac),
        device_(device)
    {
    }

    void setDevice(const char* device) {
       device_ = device;
    }

    void setIPaddrs(const std::set<std::string>& ip_addrs) {
        ip_addrs_ = ip_addrs;
    }

    void init();

    void run();

private:
    void printResult();
    void sendARPRequest();

    static void startARPCapture(const char* device);
    static void startCollectResult();

    const char* local_ip_;
    const char* local_mac_;
    const char* device_;

    static std::atomic<bool> isOk_;
    static ARPCapture* p_arpCapture;

    static std::condition_variable cond_;

    static std::set<std::string> ip_addrs_;

    static std::map<std::string, std::string> ip_mac_addrs_;
};

#endif // CONTROLLER_H
