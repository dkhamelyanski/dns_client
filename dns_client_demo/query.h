#pragma once

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
	printf( "\n============QUESTION============"
			"\nRecord name: %s"
			"\nRecord type: %d"
			"\nRecord class: %d"
			"\n================================\n"
			, name
			, ntohs(q->qtype)
			, htons(q->qclass));
}