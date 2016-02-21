#include "pkcs7.h"

int main(int argc, char **argv)
{
	char name[512];
	if (argc >= 2)
		strcpy(name, argv[1]);
	else {
		printf("Plearse input file name:");
		scanf("%s", name);
	}
	pkcs7 test;
	if (test.open_file(name)) {
		test.print();
		//test.change_contentType(1);
		//test.add_data((unsigned char *)"hello world", strlen("hello world"), 0);
		printf("MD5: %s\n", test.get_MD5());
	}
	
}