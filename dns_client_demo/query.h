#pragma once
#include <iostream>

//Type field of Query and Answer
#define T_A 1 /* ipv4 host address */
#define T_AAAA 28 /* ipv6 */
#define T_NS 2 /* authoritative server */
#define T_CNAME 5 /* canonical name */
#define T_SOA 6 /* start of authority zone */
#define T_PTR 12 /* domain name pointer */
#define T_MX 15 /* mail routing information */

//Constant sized fields of query structure
struct QUESTION
{
	unsigned short qtype;
	unsigned short qclass;
};

//Structure of a Query
struct QUERY
{
	unsigned char* name;
	struct QUESTION* ques;
};

void printQuestionData(unsigned char* name, QUESTION* q)
{
	std::string strType;

	switch (ntohs(q->qtype))
	{
	case T_A: strType = "A"; break;
	case T_AAAA: strType = "AAAA"; break;
	case T_NS: strType = "NS"; break;
	case T_CNAME: strType = "CNAME"; break;
	case T_SOA: strType = "SOA"; break;
	case T_PTR: strType = "PTR"; break;
	case T_MX: strType = "15"; break;
	default:
		break;
	}
	printf( "\n============QUESTION============"
			"\nRecord name: %s"
			"\nRecord type: %s"
			"\nRecord class: %d"
			"\n================================\n"
			, name
			, strType.c_str()
			, htons(q->qclass));
}