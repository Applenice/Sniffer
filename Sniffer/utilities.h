#pragma once
#include "afxcmn.h"
#include "afxwin.h"
#include <malloc.h> 
#include <Winsock2.h>
#include "Protocol.h"

/*��·��*/
int analyze_frame(const u_char * pkt, struct datapkt * data, struct pktcount *npakcet);

/*�����*/
int analyze_ip(const u_char* pkt, struct datapkt *data, struct pktcount *npakcet);
int analyze_ip6(const u_char* pkt, struct datapkt *data, struct pktcount *npakcet);
int analyze_arp(const u_char* pkt, struct datapkt *data, struct pktcount *npakcet);

/*�����*/
int analyze_icmp(const u_char* pkt, struct datapkt *data, struct pktcount *npakcet);
int analyze_icmp6(const u_char* pkt, struct datapkt *data, struct pktcount *npakcet);

int analyze_tcp(const u_char* pkt, struct datapkt *data, struct pktcount *npakcet);
int analyze_udp(const u_char* pkt, struct datapkt *dtat, struct pktcount *npakcet);

/*Ӧ�ò�*/
int analyze_http(const u_char* pkt, struct datapkt *data, struct pktcount *npakcet);

/*ʮ�����Ʒ�ʽ��ӡ*/
void print_packet_hex(const u_char* pkt, int size_pkt, CString *buf);