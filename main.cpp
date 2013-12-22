#include <iostream>
#include <stdio.h>

#include <set>
#include <string>

#include "controller.h"

#include "sys/socket.h"
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <net/if.h>

#include <QRegExp>
#include <QString>


using namespace std;


static const char* opt_string = "i:g:h?";



QString ipPattern = "((2[0-4]\\d|25[0-5]|[01]?\\d\\d?)\\.){3}(2[0-4]\\d|25[0-5]|[01]?\\d\\d?)";

void display_usage() {
    puts("Usage: mac-scan [-igh?] host\n");
    puts("\t-i name,\t\t\tinterface name\n");
    puts("\t-g 192.168.1.0/24\n");
    puts("\t-g 192.168.1.1-192.168.1.100,\tip address range\n");
    puts("\t-h\n\t-?,\t\t\t\tdisplay help information\n");
    puts("Example:\n");
    puts("\tmac-scan -i eth0 192.168.1.101\n");
    puts("\tmac-scan -i eth0 -g 192.168.1.0/24");
    exit(-1);
}

int get_local_mac(const char *dev, char *mac)
{
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    struct ifreq req;
    int err;
    strcpy(req.ifr_name, dev);
    err = ioctl(s, SIOCGIFHWADDR, &req);
    close(s);
    if (err == -1)
        return err;

    unsigned char mac_tmp[6];
    memcpy(mac_tmp, req.ifr_hwaddr.sa_data,6);

    sprintf(mac, "%02x:%02x:%02x:%02x:%02x:%02x",
            mac_tmp[0], mac_tmp[1], mac_tmp[2],
            mac_tmp[3], mac_tmp[4], mac_tmp[5]);
    return 0;
}

int get_local_ip(const char *dev, char *ip)
{
    int s;
    struct ifreq req;
    int err;
    strcpy(req.ifr_name, dev);
    if ((s = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
    {
        perror("socket()");
        exit(1);
    }
    err = ioctl(s, SIOCGIFADDR, &req);
    close(s);
    if (err == -1)
        return err;
    in_addr in = ((struct sockaddr_in*)&req.ifr_addr)->sin_addr;
    char* ip_tmp = inet_ntoa(in);
    memcpy(ip, ip_tmp, strlen(ip_tmp) + 1);
    return 0;
}

u_int32_t ip2long(const char* ip) {
    u_int8_t ip_val[4];
    char *endptr = NULL;
    const char *src = ip;
    for (int i = 0; i < 4; ++i) {
        ip_val[i] = src ? strtoul(src, &endptr, 10) : 0;
        if (src) {
            src = *endptr ? endptr + 1 : endptr;
        }
    }

    u_int32_t value = 0;
    value += ip_val[0] * 0x1000000;
    value += ip_val[1] * 0x10000;
    value += ip_val[2] * 0x100;
    value += ip_val[3];
    return value;
}

int long2ip(u_int32_t val, char *ip) {
    return sprintf(ip, "%d.%d.%d.%d", val>>24, val<<8>>24, val<<16>>24, val<<24>>24);
}



int main(int argc, char **argv)
{
    char* ip_range = NULL;
    char* host = NULL;

    const char* device;

    int opt = getopt(argc, argv, opt_string);
    if (opt == -1) {
        display_usage();
    }
    while (opt != -1) {
        switch (opt) {
            case 'i':
                device = optarg;
                break;
            case 'g':
                ip_range = optarg;
                break;
            case 'h':
            case '?':
                display_usage();
                break;
            default:
                break;
        }
        opt = getopt(argc, argv, opt_string);
    }

    set<string> ip_addrs;

    if (ip_range == NULL) {
        host = argv[optind];
        QRegExp rx("^"+ipPattern+"$");

        if (!rx.exactMatch(host)) {
            puts("ip syntax error");
            exit(-1);
        }

        ip_addrs.insert(host);
    } else {
        QRegExp rx("^"+ipPattern+"-"+ipPattern+"$");
        if (!rx.exactMatch(ip_range)) {
            puts("ip syntax error");
            exit(-1);
        }
        char *ip_first, *ip_last;
        const char* split = "-";
        ip_first = strtok(ip_range, split);
        ip_last = strtok(NULL, split);

        u_int32_t ip_start_val = ip2long(ip_first);
        u_int32_t ip_end_val = ip2long(ip_last);
        for (u_int32_t ip_val = ip_start_val; ip_val < ip_end_val + 1; ++ip_val) {
            if (ip_val << 24 >> 24 == 255)
                continue;
            char ip[20];
            long2ip(ip_val, ip);
            ip_addrs.insert(ip);
        }
    }

    char mac[20];
    get_local_mac(device, mac);

    char ip[20];
    get_local_ip(device, ip);

    Controller contr(ip, mac, device);
    contr.init();
    contr.setIPaddrs(ip_addrs);
    contr.run();

    return 0;
}

