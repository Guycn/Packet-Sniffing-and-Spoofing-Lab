#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>


unsigned short checksum(unsigned short *buffer, int lenght)
{
    unsigned long check_sum=0;
    while (lenght > 1)
    {
        check_sum += *buffer++;
        lenght  -= sizeof(unsigned short);
    }
    if (lenght)
    {
        check_sum += *(char*)buffer;
    }
    check_sum = (check_sum >> 16) + (check_sum & 0xffff);
    check_sum += (check_sum >>16);
    return (unsigned short)(~check_sum);
}

int main(int argc, char **argv)
{
    struct ip ip;
    struct udphdr udp;
    struct icmp icmp;
    int sd;
    const int on = 1;
    struct sockaddr_in sin;
    u_char *packet;
    packet = (u_char *)malloc(60);
    ip.ip_hl = 5;
    ip.ip_v = 4;
    ip.ip_ttl = 20;
    ip.ip_p = IPPROTO_ICMP;
    ip.ip_src.s_addr = inet_addr("10.0.2.4");
    ip.ip_dst.s_addr = inet_addr("1.1.1.1");
    ip.ip_sum = checksum((unsigned short *)&ip, sizeof(ip));
    memcpy(packet, &ip, sizeof(ip));
    icmp.icmp_type = 8;
    icmp.icmp_code = 0;
    icmp.icmp_id = htons(50179);
    icmp.icmp_cksum = 0;
    memcpy(packet + 20, &icmp, 8);
    
    if ((sd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0)
    {
        perror("raw socket");
        exit(1);
    }

    if (setsockopt(sd, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on)) < 0)
    {
        perror("setsockopt");
        exit(1);
    }
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = ip.ip_dst.s_addr;
    
    if (sendto(sd, packet, 60, 0, (struct sockaddr *)&sin,
               sizeof(struct sockaddr)) < 0)
    {
        perror("sendto");
        exit(1);
    }

    return 0;
}
