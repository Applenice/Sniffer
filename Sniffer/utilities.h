#pragma once
#include "afxcmn.h"
#include "afxwin.h"
#include <malloc.h> 
#include <Winsock2.h>
#include "Protocol.h"

/*链路层*/
int analyze_frame(const u_char * pkt, struct datapkt * data, struct pktcount *npakcet);

/*网络层*/
int analyze_ip(const u_char* pkt, struct datapkt *data, struct pktcount *npakcet);
int analyze_ip6(const u_char* pkt, struct datapkt *data, struct pktcount *npakcet);
int analyze_arp(const u_char* pkt, struct datapkt *data, struct pktcount *npakcet);

/*传输层*/
int analyze_icmp(const u_char* pkt, struct datapkt *data, struct pktcount *npakcet);
int analyze_icmp6(const u_char* pkt, struct datapkt *data, struct pktcount *npakcet);

int analyze_tcp(const u_char* pkt, struct datapkt *data, struct pktcount *npakcet);
int analyze_udp(const u_char* pkt, struct datapkt *dtat, struct pktcount *npakcet);

/*应用层*/
int analyze_http(const u_char* pkt, struct datapkt *data, struct pktcount *npakcet);

/*十六进制方式打印*/
void print_packet_hex(const u_char* pkt, int size_pkt, CString *buf);