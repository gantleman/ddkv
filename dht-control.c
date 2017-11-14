/* This example code was written by Juliusz Chroboczek.
   You are free to cut'n'paste from it to your heart's content. */

/* For crypt */
#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>
#ifndef _WIN32
#include <unistd.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <sys/signal.h>
#define MY_FILE int
#else
#include <ws2tcpip.h>
#include <time.h>
#include <windows.h>
#pragma comment(lib,"ws2_32.lib")
#include "getopt.h"
#endif

#define CCMD "[control]"
#define SCCMD  sizeof(CCMD) - 1
static char buf[4096] = { CCMD };
static char* pbuf = buf + SCCMD;

int
main(int argc, char **argv)
{
    int s = -1, s6 = -1, port = 0;
    int opt;
    int ipv4 = 1, ipv6 = 1;
    struct sockaddr_in sin;
    struct sockaddr_in6 sin6;

#ifdef _WIN32

	// Load Winsock
	int retval;
	WSADATA wsaData;
	if ((retval = WSAStartup(MAKEWORD(2, 2), &wsaData)) != 0)
	{
		WSACleanup();
		return 0;
	}
#endif // _WIN32

    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;

    memset(&sin6, 0, sizeof(sin6));
    sin6.sin6_family = AF_INET6;

    while(1) {
        opt = getopt(argc, argv, "46b:p:");
        if(opt < 0)
            break;

        switch(opt) {
        case '4': ipv6 = 0; break;
        case '6': ipv4 = 0; break;
        case 'b': {
            char buf[16];
            int rc;
            rc = inet_pton(AF_INET, optarg, buf);
            if(rc == 1) {
                memcpy(&sin.sin_addr, buf, 4);
                break;
            }
            rc = inet_pton(AF_INET6, optarg, buf);
            if(rc == 1) {
                memcpy(&sin6.sin6_addr, buf, 16);
                break;
            }
            goto usage;
        }
		break;
		case 'p':{
			port = atoi(optarg);
		}
		break;
        default:
            goto usage;
        }
    }

    /* We need an IPv4 and an IPv6 socket, bound to a stable port.  Rumour
       has it that uTorrent works better when it is the same as your
       Bittorrent port. */

    if(ipv4) {
        s = socket(PF_INET, SOCK_DGRAM, 0);
        if(s < 0) {
            perror("socket(IPv4)");
        }
    }

    if(ipv6) {
        s6 = socket(PF_INET6, SOCK_DGRAM, 0);
        if(s6 < 0) {
            perror("socket(IPv6)");
        }
    }

    if(s < 0 && s6 < 0) {
        fprintf(stderr, "Eek!");
        exit(1);
    }


    if(s >= 0) {
        sin.sin_port = htons(port);
    }

    if(s6 >= 0) {
        int rc;
        int val = 1;

        rc = setsockopt(s6, IPPROTO_IPV6, IPV6_V6ONLY,
                        (char *)&val, sizeof(val));
        if(rc < 0) {
            perror("setsockopt(IPV6_V6ONLY)");
            exit(1);
        }

        /* BEP-32 mandates that we should bind this socket to one of our
           global IPv6 addresses.  In this simple example, this only
           happens if the user used the -b flag. */

        sin6.sin6_port = htons(port);
    }


	while (1) {
		gets(pbuf);

		if (s >= 0)
		{
			sendto(s, buf, strlen(buf)+1, 0, (struct sockaddr*)&sin, sizeof(sin));
		}
		if (s6 >= 0)
		{
			sendto(s6, buf, strlen(buf)+1, 0, (struct sockaddr*)&sin6, sizeof(sin6));
		}
		
	}
    
 usage:
    printf("Usage: client [-4] [-6] [-b address] [-p port]\n");
    exit(1);
}


