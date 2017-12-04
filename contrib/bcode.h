#pragma once
#include <map>
#include <string>
#include <vector>
#include <sstream>
#include <list>
#include <memory.h>

class b_element
{
public:
	int type;
	std::vector<char> buf;
	std::list<b_element>::iterator iterl;
	std::string key;
	b_element() :type(0){};
	~b_element();
};

void b_parse(const char* buf, int len, int &cur, b_element& out);
void b_package(b_element* e, std::string& o);
int b_insert(b_element* e, const char* key, unsigned char* i, int len);
void b_next(b_element* e, b_element** o);
//dictionary
void b_find(b_element* e, const char* key, unsigned char** o, int& len);
void b_find(b_element* e, const char* key, b_element** o);
void b_insertd(b_element* e, const char* key, b_element** o);
void b_deld(b_element* e, const char* key);
//list
void b_insertl(b_element* e, const char* key, b_element** o);
void b_get(b_element* e, int cur, unsigned char** o, int& len);
void b_get(b_element* e, int cur, b_element** o);
void b_dell(b_element* e, b_element* i);