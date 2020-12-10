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

#include "dnsheader.h"
#include "query.h"
#include "response.h"

#include <boost/program_options.hpp>
namespace po = boost::program_options;

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

//Max size of UDP package
static const size_t DEF_BUF_SIZE = 512;

//Default UDP port
static const size_t DEF_PORT = 53;

// Google DNS which using bu default
static const std::string DEF_DNS_GOOGLE = "8.8.8.8";
// Yandex DNS server 77.88.8.7(with blocking censored content)
static const std::string DEF_DNS_YANDEX = "77.88.8.7";

//Function Declarations
void printUsage(char*);
void ChangetoDnsNameFormat(unsigned char*, unsigned char*);
unsigned char* ReadName(unsigned char*, unsigned char*, int*);
unsigned char* PrepareDnsQueryPacket(unsigned char*);
void handleDNSData(unsigned char*);
void listen(const std::string &);

void printUsage(char* programName) {
	printf("\nUsage:\n"
		"%s [-d dns_server] hostname\n"
		"------\n", programName);
}

po::variables_map parse_args(int argc, char** argv, po::options_description& desc) {

	desc.add_options()
		("help,h", "Produce help message")
		("dns_server,d"
			, po::value<std::string>()->default_value(DEF_DNS_GOOGLE), 
			"IPv4 address of DNS server to send the DNS request to. If not set the DNS request will be sent to the google DNS 8.8.8.8 ")
		;

	po::variables_map vm;
	const auto& parsed = po::command_line_parser(argc, argv)
		.options(desc)
		.run();
	po::store(parsed, vm);
	po::notify(vm);

	return vm;
	
}

unsigned char* ReadName(unsigned char* reader, unsigned char* buffer, int* count)
{
	unsigned char* name = (unsigned char*)malloc(256);
	unsigned int p = 0, jumped = 0, offset;
	int i, j;

	*count = 1;

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

//reading answers
void handleDNSData(unsigned char* buf) {

	//the replies from the DNS server
	struct RES_RECORD	answers[20],
						auth[20],
						addit[20];

	struct sockaddr_in a;

	struct DNS_HEADER* dns = NULL;
	struct QUESTION* qinfo = NULL;

	unsigned char * reader;

	dns = (struct DNS_HEADER*)buf;
	printDNSHeaderInfo(dns);

	int sizeName = 0;

	reader = &buf[sizeof(struct DNS_HEADER)];
	unsigned char* name = ReadName(reader, buf, &sizeName);

	//Point to the query portion. 
	//Also you can handle it to filter packages by record type or data
	qinfo = (struct QUESTION*) & buf[sizeof(struct DNS_HEADER) + sizeName];

	printQuestionData(name, qinfo);

	reader += sizeName + sizeof(struct QUESTION);

	if (dns->ans_count || dns->auth_count || dns->add_count)
	{
		printf("\n=============ANSWER=============");

		int i, j;
		int stop = 0;

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
			printf("\nAnswer : %d", i + 1);
			printf("\nName : %s ", answers[i].name);

			if (ntohs(answers[i].resource->type) == T_A) //IPv4 address
			{
				long* p;
				p = (long*)answers[i].rdata;
				a.sin_addr.s_addr = (*p); //working without ntohl
				char buf[100];
				inet_ntop(AF_INET, &a.sin_addr, buf, sizeof(buf));
				printf("has IPv4 address : %s", buf);
			}
			else
				if (ntohs(answers[i].resource->type) == T_CNAME) //Canonical name for an alias
				{
					printf("has alias name : %s", answers[i].rdata);
				}
				else
				{
					printf("-> %s", answers[i].rdata);
				}

			printf("\n");
		}

		//print authorities
		for (i = 0; i < ntohs(dns->auth_count); i++)
		{
			printf("\nAuthorities : %d", i + 1);
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
			printf("\nAdditional : %d", i + 1);
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

		printf("================================\n");
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

void listen(const std::string& dns_server)
{
	unsigned char buf[DEF_BUF_SIZE];

	SOCKET sSock, cSock;
	struct sockaddr_in servAddr, recvAddr;

	//socket for queries to DNS
	struct sockaddr_in dest;

	int servLen{ sizeof(servAddr) };
	int recvLen;
	int sizeName;

	//Just to show recieved IP address
	char recv_ip[256];
	recv_ip[sizeof(recv_ip) - 1] = '\0';

	char proxy_ip[256];
	proxy_ip[sizeof(proxy_ip) - 1] = '\0';

	struct DNS_HEADER* dns = NULL;
	unsigned char* qname;
	unsigned char* name;
	struct QUERY* query = NULL;


	//Create a socket
	if ((sSock = socket(AF_INET, SOCK_DGRAM, 0)) == INVALID_SOCKET)
	{
		printf("Could not create socket : %d", WSAGetLastError());
	}
	printf("Listen Socket created.");

	char *host = NULL;
	struct hostent* host_entry = gethostbyname(host); //find host information
	const char * IP = inet_ntoa(*((struct in_addr*) host_entry->h_addr_list[0])); //Convert into IP string

	//Prepare the sockaddr_in structure
	servAddr.sin_family = AF_INET;
	servAddr.sin_addr.s_addr = INADDR_ANY;
	servAddr.sin_port = htons(DEF_PORT);

	//Bind
	if (bind(sSock, (struct sockaddr*) & servAddr, sizeof(servAddr)) == SOCKET_ERROR)
	{
		printf("Bind failed with error code : %d", WSAGetLastError());
		exit(EXIT_FAILURE);
	}
	puts("Bind done");

	inet_ntop(AF_INET, &servAddr.sin_addr, proxy_ip, sizeof(proxy_ip));

	printf( "\n======= PROXY ADDR ======="
			"\n===     %s:%d "
			"\n=========================="
			, proxy_ip, htons(servAddr.sin_port));

	//keep listening for data
	while (1)
	{
		printf("\nWaiting for data...");
		fflush(stdout);

		//clear the buffer by filling null, it might have previously received data
		ZeroMemory(buf, sizeof(buf));

		//try to receive some data, this is a blocking call
		if ((recvLen = recvfrom(sSock, (char*)buf, DEF_BUF_SIZE, 0, (struct sockaddr*) &recvAddr, &servLen)) == SOCKET_ERROR)
		{
			printf("recvfrom() failed with error code : %d", WSAGetLastError());
			exit(EXIT_FAILURE);
		}

		//print details of the client and the data received
		inet_ntop(AF_INET, &recvAddr.sin_addr, recv_ip, sizeof(recv_ip));
		printf("\nReceived packet from %s:%d", recv_ip, ntohs(recvAddr.sin_port));
		printf("\nReceived data: ");
		handleDNSData(buf);

		//Just save dns id for identifying after resiving package from the server
		dns = (struct DNS_HEADER*) & buf;
		unsigned short nPackageId = ntohs(dns->id);

		//Create a socket which send information to DNS server
		cSock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP); //UDP socket for DNS queries

		dest.sin_family = AF_INET;
		dest.sin_port = htons(DEF_PORT);

		inet_pton(AF_INET, dns_server.c_str(), &dest.sin_addr);

		printf("\nSending Packet to DNS server...");

		if (sendto(cSock, (char*)buf, recvLen, 0, (struct sockaddr*) & dest, sizeof(dest)) == SOCKET_ERROR)
		{
			printf("sendto() failed with error code : %d", WSAGetLastError());
			exit(EXIT_FAILURE);
		}
		printf("Succesfuly sent");

		int i = sizeof(dest);
		printf("\nReceiving answer...");
		if (recvfrom(cSock, (char*)buf, DEF_BUF_SIZE, 0, (struct sockaddr*) & dest, &i) == SOCKET_ERROR)
		{
			printf("Failed. Error Code : %d", WSAGetLastError());
		}

		inet_ntop(AF_INET, &dest.sin_addr, recv_ip, sizeof(recv_ip));
		printf("\nRecive package from %s:%d", recv_ip, ntohs(dest.sin_port));

		dns = (struct DNS_HEADER*) & buf;
		if (nPackageId != ntohs(dns->id))
		{
			printf("Error while receiving package : dns header id not the same");
			continue;
		}

		printf("\nDNS response data: ");
		handleDNSData(buf);

		printf("\nSending Packet back from Proxy to client %s:%d...", recv_ip, ntohs(dest.sin_port));

		//now reply the client with the same data
		if (sendto(sSock, (char*)buf, recvLen, 0, (struct sockaddr*) & recvAddr, servLen) == SOCKET_ERROR)
		{
			printf("\nsendto() failed with error code : %d", WSAGetLastError());
			exit(EXIT_FAILURE);
		}
		printf("Succesfuly sent\n");
	}

	closesocket(sSock);
	closesocket(cSock);

	return;
}

int main(int argc, char** argv)
{
	po::options_description desc("Allowed options");
	po::variables_map vm;

	try {
		vm = parse_args(argc, argv, desc);
	}
	catch (std::exception & e) {
		std::cout << "Error: " << e.what() << std::endl;
		printUsage(argv[0]);
		std::cout << desc << std::endl;
		return 1;
	}

	if (vm.count("help")) {
		printUsage(argv[0]);
		std::cout << desc << "\n";
		return 1;
	}

	std::string strDNSServer = vm["dns_server"].as<std::string>();

	WSADATA firstsock;
	printf("\nInitialising Winsock...");
	if (WSAStartup(MAKEWORD(2, 2), &firstsock) != 0)
	{
		printf("Failed. Error Code : %d", WSAGetLastError());
		return 1;
	}
	printf("Initialised.");

	listen(strDNSServer);

	WSACleanup();

	return 0;
}
