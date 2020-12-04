// dns_client_demo.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

//DNS Query Program

//Header Files
#include "winsock2.h"
#include "windows.h"
#include <stdio.h>
#include "conio.h"
#include <iostream>
#include <ws2tcpip.h>
#include <WS2tcpip.h>

#pragma warning(disable : 4996)
#pragma comment(lib,"ws2_32.lib") //Winsock Library

//List of DNS Servers registered on the system
char dns_servers[10][100];

//Type field of Query and Answer
#define T_A 1 /* host address */
#define T_NS 2 /* authoritative server */
#define T_CNAME 5 /* canonical name */
#define T_SOA 6 /* start of authority zone */
#define T_PTR 12 /* domain name pointer */
#define T_MX 15 /* mail routing information */

//Function Declarations
void ngethostbyname(unsigned char*);
void ChangetoDnsNameFormat(unsigned char*, unsigned char*);
unsigned char* ReadName(unsigned char*, unsigned char*, int*);
void RetrieveDnsServersFromRegistry(void);
unsigned char* PrepareDnsQueryPacket(unsigned char*);

//DNS header structure
struct DNS_HEADER
{
	unsigned short id; // identification number

	unsigned char rd : 1; // recursion desired
	unsigned char tc : 1; // truncated message
	unsigned char aa : 1; // authoritive answer
	unsigned char opcode : 4; // purpose of message
	unsigned char qr : 1; // query/response flag

	unsigned char rcode : 4; // response code
	unsigned char cd : 1; // checking disabled
	unsigned char ad : 1; // authenticated data
	unsigned char z : 1; // its z! reserved
	unsigned char ra : 1; // recursion available

	unsigned short q_count; // number of question entries
	unsigned short ans_count; // number of answer entries
	unsigned short auth_count; // number of authority entries
	unsigned short add_count; // number of resource entries
};

//Constant sized fields of query structure
struct QUESTION
{
	unsigned short qtype;
	unsigned short qclass;
};

//Constant sized fields of the resource record structure
#pragma pack(push, 1)
struct R_DATA
{
	unsigned short type;
	unsigned short _class;
	unsigned int ttl;
	unsigned short data_len;
};
#pragma pack(pop)

//Pointers to resource record contents
struct RES_RECORD
{
	unsigned char* name;
	struct R_DATA* resource;
	unsigned char* rdata;
};

//Structure of a Query
typedef struct
{
	unsigned char* name;
	struct QUESTION* ques;
} QUERY;

int main(int argc, char** argv) //do you know what is int main() ?
{
	unsigned char hostname[100];

	//RetrieveDnsServersFromRegistry();

	WSADATA firstsock;
	printf("\nInitialising Winsock...");
	if (WSAStartup(MAKEWORD(2, 2), &firstsock) != 0)
	{
		printf("Failed. Error Code : %d", WSAGetLastError());
		return 1;
	}
	printf("Initialised.");

	printf("\nEnter Hostname to Lookup : ");
	
	std::cin >> hostname;
	
	ngethostbyname(hostname);

	system("pause");

	return 0;
}

void ngethostbyname(unsigned char* host)
{
	unsigned char buf[65536], * qname, * reader;
	int i, j, stop;

	SOCKET s;
	struct sockaddr_in a;

	struct RES_RECORD answers[20], auth[20], addit[20]; //the replies from the DNS server
	struct sockaddr_in dest;

	struct DNS_HEADER* dns = NULL;
	struct QUESTION* qinfo = NULL;

	s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP); //UDP packet for DNS queries

	//Configure the sockaddress structure with information of DNS server
	dest.sin_family = AF_INET;
	dest.sin_port = htons(53);
	//Set the dns server
	if (strlen(dns_servers[0]) > 0)
	{
		//Use the dns server found on system
		//dest.sin_addr.s_addr = inet_addr(dns_servers[0]);
		inet_pton(AF_INET, dns_servers[0], &dest.sin_addr);
	}
	else
	{
		//Use the open dns servers - 8.8.8.8, 8.8.4.4 Google or 77.88.8.8, 77.88.8.7(with blocking censored content) Yandex
		//dest.sin_addr.s_addr = inet_addr("8.8.8.8");
		printf("Try to access google DNS, ip 8.8.8.8 ...");
		inet_pton(AF_INET, "8.8.8.8", &dest.sin_addr);
	}

	//Set the DNS structure to standard queries
	dns = (struct DNS_HEADER*) & buf;

	printf("\nDNS request header id: %d", GetCurrentProcessId());

	dns->id = (unsigned short)htons(GetCurrentProcessId());
	dns->qr = 0; //This is a query
	dns->opcode = 0; //This is a standard query
	dns->aa = 0; //Not Authoritative
	dns->tc = 0; //This message is not truncated
	dns->rd = 1; //Recursion Desired
	dns->ra = 0; //Recursion not available! hey we dont have it (lol)
	dns->z = 0;
	dns->ad = 0;
	dns->cd = 0;
	dns->rcode = 0;
	dns->q_count = htons(1); //we have only 1 question
	dns->ans_count = 0;
	dns->auth_count = 0;
	dns->add_count = 0;

	//point to the query portion
	qname = (unsigned char*)&buf[sizeof(struct DNS_HEADER)];

	ChangetoDnsNameFormat(qname, host);
	qinfo = (struct QUESTION*) & buf[sizeof(struct DNS_HEADER) + (strlen((const char*)qname) + 1)]; //fill it

	qinfo->qtype = htons(1); //we are requesting the ipv4 address
	qinfo->qclass = htons(1); //type IN (Internet)

	printf("\nSending Packet...");
	if (sendto(s, (char*)buf, sizeof(struct DNS_HEADER) + (strlen((const char*)qname) + 1) + sizeof(struct QUESTION), 0, (struct sockaddr*) & dest, sizeof(dest)) == SOCKET_ERROR)
	{
		printf("%d error", WSAGetLastError());
	}
	printf("Sent");

	i = sizeof(dest);
	printf("\nReceiving answer...");
	if (recvfrom(s, (char*)buf, 65536, 0, (struct sockaddr*) & dest, &i) == SOCKET_ERROR)
	{
		printf("Failed. Error Code : %d", WSAGetLastError());
	}
	printf("Received.");

	dns = (struct DNS_HEADER*)buf;

	//move ahead of the dns header and the query field
	reader = &buf[sizeof(struct DNS_HEADER) + (strlen((const char*)qname) + 1) + sizeof(struct QUESTION)];

	printf("\nDNS header contains : ");
	printf("\n id: %d", ntohs(dns->id));
	printf("\n rd: %d", (dns->rd));
	printf("\n tc: %d", (dns->tc));
	printf("\n aa: %d", (dns->aa));
	printf("\n opcode: %d", (dns->opcode));
	printf("\n qr: %d", (dns->qr));
	printf("\n rcode: %d", (dns->rcode));
	printf("\n cd: %d", (dns->cd));
	printf("\n ad: %d", (dns->ad));
	printf("\n ra: %d", (dns->ra));

	printf("\nThe response contains : ");
	printf("\n %d Questions.", ntohs(dns->q_count));
	printf("\n %d Answers.", ntohs(dns->ans_count));
	printf("\n %d Authoritative Servers.", ntohs(dns->auth_count));
	printf("\n %d Additional records.\n\n", ntohs(dns->add_count));

	//reading answers
	stop = 0;

	for (i = 0; i < ntohs(dns->ans_count); i++)
	{
		answers[i].name = ReadName(reader, buf, &stop);
		reader += stop;

		answers[i].resource = (struct R_DATA*)(reader);
		reader += sizeof(struct R_DATA);

		if (ntohs(answers[i].resource->type) == T_A) //if its an ipv4 address
		{
			answers[i].rdata = (unsigned char*)malloc(ntohs(answers[i].resource->data_len));

			for (j = 0; j < ntohs(answers[i].resource->data_len); j++)
				answers[i].rdata[j] = reader[j];

			answers[i].rdata[ntohs(answers[i].resource->data_len)] = '\0';

			reader += ntohs(answers[i].resource->data_len);

		}
		else
		{
			answers[i].rdata = ReadName(reader, buf, &stop);
			reader += stop;
		}

	}

	//read authorities
	for (i = 0; i < ntohs(dns->auth_count); i++)
	{
		auth[i].name = ReadName(reader, buf, &stop);
		reader += stop;

		auth[i].resource = (struct R_DATA*)(reader);
		reader += sizeof(struct R_DATA);

		auth[i].rdata = ReadName(reader, buf, &stop);
		reader += stop;
	}

	//read additional
	for (i = 0; i < ntohs(dns->add_count); i++)
	{
		addit[i].name = ReadName(reader, buf, &stop);
		reader += stop;

		addit[i].resource = (struct R_DATA*)(reader);
		reader += sizeof(struct R_DATA);

		if (ntohs(addit[i].resource->type) == T_A)
		{
			addit[i].rdata = (unsigned char*)malloc(ntohs(addit[i].resource->data_len));
			for (j = 0; j < ntohs(addit[i].resource->data_len); j++)
				addit[i].rdata[j] = reader[j];

			addit[i].rdata[ntohs(addit[i].resource->data_len)] = '\0';
			reader += ntohs(addit[i].resource->data_len);

		}
		else
		{
			addit[i].rdata = ReadName(reader, buf, &stop);
			reader += stop;
		}
	}

	//print answers
	for (i = 0; i < ntohs(dns->ans_count); i++)
	{
		printf("\nAnswer : %d",i+1);
		printf("\nName : %s ", answers[i].name);

		if (ntohs(answers[i].resource->type) == T_A) //IPv4 address
		{
			long* p;
			p = (long*)answers[i].rdata;
			a.sin_addr.s_addr = (*p); //working without ntohl
			char buf[100];
			inet_ntop(AF_INET, &a.sin_addr, buf, sizeof(buf));
			printf("has IPv4 address : %s",  buf);
		} else 
		if (ntohs(answers[i].resource->type) == T_CNAME) //Canonical name for an alias
		{
			printf("has alias name : %s", answers[i].rdata);
		}else
		{
			printf("-> %s", answers[i].rdata);
		}

		printf("\n");
	}

	//print authorities
	for (i = 0; i < ntohs(dns->auth_count); i++)
	{
		printf("\nAuthorities : %d",i+1);
		printf("\nName : %s ", auth[i].name);
		if (ntohs(auth[i].resource->type) == T_NS)
		{
			printf("has authoritative nameserver : %s", auth[i].rdata);
		}
		printf("\n");
	}

	//print additional resource records
	for (i = 0; i < ntohs(dns->add_count); i++)
	{
		printf("\nAdditional : %d",i+1);
		printf("\nName : %s ", addit[i].name);
		if (ntohs(addit[i].resource->type) == T_A)
		{
			long* p;
			p = (long*)addit[i].rdata;
			a.sin_addr.s_addr = (*p); //working without ntohl
			char buf[100];
			inet_ntop(AF_INET, &a.sin_addr, buf, sizeof(buf));
			printf("has IPv4 address : %s", buf);
		}
		printf("\n");
	}

	return;
}

unsigned char* ReadName(unsigned char* reader, unsigned char* buffer, int* count)
{
	unsigned char* name;
	unsigned int p = 0, jumped = 0, offset;
	int i, j;

	*count = 1;
	name = (unsigned char*)malloc(256);

	name[0] = '\0';

	//read the names in 3www6google3com format
	while (*reader != 0)
	{
		if (*reader >= 192)
		{
			// http://www.tcpipguide.com/free/t_DNSNameNotationandMessageCompressionTechnique-2.htm
			offset = (*reader) * 256 + *(reader + 1) - 49152; //49152 = 11000000 00000000
			reader = buffer + offset - 1;
			jumped = 1; //we have jumped to another location so counting wont go up!
		}
		else
		{
			name[p++] = *reader;
		}

		reader = reader + 1;

		if (jumped == 0) *count = *count + 1; //if we havent jumped to another location then we can count up
	}

	name[p] = '\0'; //string complete
	if (jumped == 1)
	{
		*count = *count + 1; //number of steps we actually moved forward in the packet
	}

	//now convert 3www6google3com0 to www.google.com
	for (i = 0; i < (int)strlen((const char*)name); i++)
	{
		p = name[i];
		for (j = 0; j < (int)p; j++)
		{
			name[i] = name[i + 1];
			i = i + 1;
		}
		name[i] = '.';
	}

	name[i - 1] = '\0'; //remove the last dot

	return name;
}

//Retrieve the DNS servers from the registry
void RetrieveDnsServersFromRegistry()
{
	HKEY hkey = 0;
	char name[256];

	const char path[] = "SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces";

	char* fullpath[256];
	unsigned long s = sizeof(name);
	int dns_count = 0, err, i, j;
	HKEY inter;
	unsigned long count;

	//Open the registry folder
	RegOpenKeyExA(HKEY_LOCAL_MACHINE, path, 0, KEY_READ, &hkey);

	//how many interfaces
	RegQueryInfoKey(hkey, 0, 0, 0, &count, 0, 0, 0, 0, 0, 0, 0);

	for (i = 0; i < count; i++)
	{
		s = 256;
		//Get the interface subkey name
		RegEnumKeyExA(hkey, i, (char*)name, &s, 0, 0, 0, 0);

		//Make the full path
		strcpy((char*)fullpath, path);
		strcat((char*)fullpath, "\\");
		strcat((char*)fullpath, name);

		//Open the full path name
		RegOpenKeyExA(HKEY_LOCAL_MACHINE, (const char*)fullpath, 0, KEY_READ, &inter);

		//Extract the value in Nameserver field
		s = 256;
		err = RegQueryValueExA(inter, "NameServer", 0, 0, (unsigned char*)name, &s);

		if (err == ERROR_SUCCESS && strlen(name) > 0)
		{
			strcpy(dns_servers[dns_count++], name);
		}
	}

	for (i = 0; i < dns_count; i++)
	{
		for (j = 0; j < strlen(dns_servers[i]); j++)
		{
			if (dns_servers[i][j] == ',' || dns_servers[i][j] == ' ')
			{
				strcpy(dns_servers[dns_count++], dns_servers[i] + j + 1);
				dns_servers[i][j] = 0;
			}
		}
	}

	printf("\nThe following DNS Servers were found on your system...");
	for (i = 0; i < dns_count; i++)
	{
		printf("\n%d) %s", i + 1, dns_servers[i]);
	}
}

//this will convert www.google.com to 3www6google3com ;
void ChangetoDnsNameFormat(unsigned char* dns, unsigned char* host)
{
	int lock = 0, i;

	strcat((char*)host, ".");

	for (i = 0; i < (int)strlen((char*)host); ++i)
	{
		if (host[i] == '.')
		{
			*dns++ = i - lock;
			for (; lock < i; ++lock)
			{
				*dns++ = host[lock];
			}
			lock++; //or lock=i+1;
		}
	}
	*dns++ = '\0';
}

// Run program: Ctrl + F5 or Debug > Start Without Debugging menu
// Debug program: F5 or Debug > Start Debugging menu

// Tips for Getting Started: 
//   1. Use the Solution Explorer window to add/manage files
//   2. Use the Team Explorer window to connect to source control
//   3. Use the Output window to see build output and other messages
//   4. Use the Error List window to view errors
//   5. Go to Project > Add New Item to create new code files, or Project > Add Existing Item to add existing code files to the project
//   6. In the future, to open this project again, go to File > Open > Project and select the .sln file
