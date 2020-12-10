#pragma once

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

void printDNSHeaderInfo(const DNS_HEADER* dns) {

	printf("\n================================== ");
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

	printf("\nQuery contains : ");
	printf("\n %d Questions.", ntohs(dns->q_count));
	printf("\n %d Answers.", ntohs(dns->ans_count));
	printf("\n %d Authoritative Servers.", ntohs(dns->auth_count));
	printf("\n %d Additional records.", ntohs(dns->add_count));
	printf("\n==================================\n");

}