
#ifndef __PKCS7__
#define __PKCS7__

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "3rd/md5/md5.h"
#include "3rd/zlib/unzip.h"
#include "3rd/zlib/zip.h"

#ifdef  _WIN32
#	define 	STRCASECMP		stricmp
#	define  FUNCTION_NAME	__FUNCTION__
#else
#	define 	STRCASECMP 		strcasecmp
#	define  FUNCTION_NAME  __func__
#endif

#ifdef  _WIN32
#pragma warning(disable:4996)
#endif 

#define TAG_INTEGER 	0x02
#define TAG_BITSTRING	0x03
#define TAG_OCTETSTRING 0x04
#define TAG_OBJECTID	0x06
#define TAG_UTCTIME		0x17
#define TAG_GENERALIZEDTIME 0x18   
#define TAG_SEQUENCE	0x30
#define TAG_SET			0x31

#define TAG_OPTIONAL	0xA0


#define NAME_LEN 	63

typedef struct element {
	unsigned char tag;
	char name[NAME_LEN];
	int begin;
	int len;
	int level;
	struct element *next;
}element;

class pkcs7 {
	public:
		pkcs7();
		~pkcs7();
		bool open_file(char *file_name);
		void print();
		char* get_MD5();
		
		bool add_data(unsigned char *data, int len, int tail = 1, const char * save_name = NULL);
		bool change_contentType(int type = 1);

	private:
		int  len_num(unsigned char lenbyte);
		int  num_from_len(int len);
		int  tag_offset(element *p);

		int  get_length(unsigned char lenbyte, int pos);
		int  put_length(unsigned char* buffer, int length);

		bool get_from_apk(char *file_name);
		bool get_content(char *file_name);
		
		int create_element(unsigned char tag, char *name, int level);
		element *get_element(const char *name, element *begin);

		bool parse_content(int level);
		bool parse_pkcs7();
		bool parse_certificate(int level);
		bool parse_signerInfo(int level);
		
		bool parse_time(element *p_val);

		bool save_apk(unsigned char *buffer, int length, const char *save_name);
		
		
		
	private:
		unsigned char *	m_content;
		int 			m_length;
		int 			m_pos;
		struct element *head;
		struct element *tail;
		struct element *p_cert;
		struct element *p_signer;

		char *apk_file;
		char *cert_file;
};



#endif //__PKCS7__