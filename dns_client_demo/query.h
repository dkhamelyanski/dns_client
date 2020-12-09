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