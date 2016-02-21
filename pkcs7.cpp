/*PKCS7结构
*contentInfo : SEQUENCE
*	contentType : ObjectIdentifier  {data|signedData|envelopedData|signedAndEnvelopedData|digestedData|encryptedData}
* 	content		#内容由contentType决定
*
*contentInfo : SEQUENCE
*	contentType : ObjectIdentifier  {data}
	content : OCTETSTRING
*
*contentInfo : SEQUENCE
*	contentType : ObjectIdentifier  {signedData}
*	content[optional] : SEQUENCE 							#CERT.RSA是属于signedData类型
*		version : INTEGER 
*		digestAlgorithms : SET : DigestAlgorithmIdentifier  #消息摘要的算法
*		contentInfo : SEQUENCE   							#整个文件也是contentInfo结构
*		certificates[optional] : SEQUENCE 					#证书信息
*			tbsCertificate : SEQUENCE #
*				version : INTEGER
*				serialNumber : INTEGER  					#证书的序列号，由证书颁布者和序列号可以唯一确定证书
*				signature ： SEQUENCE : AlgorithmIdentifier
*				issuer : SET 								#证书颁布者
*				validity : SEQUENCE    						#证书的有效期
*				subject : SET #证书主体
*				subjectPublicKeyInfo : SEQUENCE 			#公钥相关信息，包含有加密算法和公钥
*				issuerUniqueID[optional] : BITSTRING 
*				subjectUniqueID[optional] : BITSTRING 
*				extensions[optional] : SEQUENCE  			#保存有证书扩展信息
*			signatureAlgorithm : AlgorithmIdentifier 		#签名算法 ，如常用的有 SHA256withRSA
*			signatureValue : BITSTRING 						#这是tbsCertificate部分的数字签名信息，防止tbsCertificate内容被修改
*		crls[optional] : SET 								#证书吊销列表
*		signerInfos : SET
			signerInfo : SEQUENCE							#签名者信息
*				version : INTEGER
*				issuerAndSerialNumber : SEQUENCE 			#证书的颁布者和序列号
*				digestAlgorithmId : SEQUENCE : DigestAlgorithmIdentifier #消息摘要的算法
*				authenticatedAttributes[optional] 
*				digestEncryptionAlgorithmId : SEQUENCE 			#签名算法
*				encryptedDigest : OCTETSTRING   			#私钥加密后的数据
*				unauthenticatedAttributes[optional] 
*
*每项的保存形式为{tag，length，content}
*/

#include "pkcs7.h"

/**
 * 构造函数，必须提供签名证书文件或者apk文件
 */
pkcs7::pkcs7()
{
	m_content = NULL;
	head = tail = NULL;
	p_cert = p_signer = NULL;
	m_pos = m_length = 0;
	apk_file = cert_file = NULL;
	
}

bool pkcs7::open_file(char *file_name)
{
	bool ret = get_content(file_name);
	if (ret == false) {
		printf("The file format is error!\n");
		return ret;
	}
	ret = parse_pkcs7();
	if (ret == false) {
		printf("parse the pkcs7 format error!\n");
		print();
		return ret;
	}
	return true;
}

pkcs7::~pkcs7()
{
	element *p = head;
	while (p != NULL) {
		head = p->next;
		free(p);
		p = head;
	}
	free(m_content);
	if (apk_file != NULL)
		free(apk_file);
	if (cert_file != NULL)
		free(cert_file);
}

/**
 * 该函数用于从apk中获取签名证书文件，  META-INF/*.[RSA|DSA|EC]。
 * 若找到将该文件内容保存在m_content中，m_length为其长度
 *
 * 使用minizip库， 1）unzOpen64 打开apk文件；
 *                 2）unzGetGlobalInfo64 获取文件总数；
                   3）unzGoFirstFile 和 unzGoToNextFile 遍历文件；
				   4）unzGetCurrentFileInfo64 获取当前文件信息，对比找到签名证书文件；
				   5）unzOpenCurrentFilePass 打开当前文件；
				   6）unzReadCurrentFile 读取当前文件内容；
				   7）unzCloseCurrentFile 关闭当前文件；
				   8）unzClose 关闭apk文件。
 */
bool pkcs7::get_from_apk(char *file_name)
{
	unzFile uf = NULL;
	unz_file_info64 file_info;
	char filename_inzip[256];
	int err;
	
	uf = unzOpen64(file_name);
	if (uf == NULL) {
		printf("open apk file error!\n");
		return false;
	}
	apk_file = (char *)malloc(sizeof(char) * (strlen(file_name) + 1));
	strcpy(apk_file, file_name);

	unz_global_info64 gi;
	err = unzGetGlobalInfo64(uf, &gi); 
	if (err != UNZ_OK) {
		printf("error %d with zipfile in unzGetGlobalInfo \n", err);
		return false;
	}
	err = unzGoToFirstFile(uf);
	int i;
	for (i = 0; i< gi.number_entry; i++) {
		if (err != UNZ_OK) {
			printf("get file error!\n");
			return false;
		}
		if (unzGetCurrentFileInfo64(uf, &file_info, filename_inzip, sizeof(filename_inzip), NULL, 0, NULL, 0))
		{
			printf("get file infomation error!\n");
			return false;
		}
		int name_len = strlen(filename_inzip);
		if (name_len != file_info.size_filename) {
			printf("file name length is not right!\n");
			return false;
		}
		if (name_len > 13) {// "META-INF/*.RSA"
			if ((!strncmp(filename_inzip, "META-INF/", 9)) &&
				(!STRCASECMP(filename_inzip + name_len - 4, ".RSA") ||
				!STRCASECMP(filename_inzip + name_len - 4, ".DSA") ||
				!STRCASECMP(filename_inzip + name_len - 3, ".EC")))
			{
				cert_file = (char *)malloc(sizeof(char) * (name_len + 1));
				strcpy(cert_file, filename_inzip);
				break;
			}
		}
		err = unzGoToNextFile(uf);
	}
	if (i == gi.number_entry) {
		printf("cannot find the file!\n");
		return false;
	}

	err = unzOpenCurrentFilePassword(uf, NULL);
	if (err != UNZ_OK) {
		printf("open current error!\n");
		return  false;
	}
	/*获取文件内容*/
	m_length = file_info.uncompressed_size;
	if (m_length <= 0)
		return false;
	m_content = (unsigned char *)malloc((size_t)(m_length));
	err = unzReadCurrentFile(uf, m_content, m_length);
	if (err != file_info.uncompressed_size) {
		printf("read content error!\n");
		return false;
	}
	unzCloseCurrentFile(uf);
	unzClose(uf);
	return true;
}

/**
 * 获取签名文件内容，支持：1）直接提供的是签名文件；2）apk压缩文件。
 */

bool pkcs7::get_content(char *file_name)
{
	int name_len = strlen(file_name);
	if (name_len < 4)
		return false;
	if (!STRCASECMP(file_name + name_len - 4, ".RSA") ||
		!STRCASECMP(file_name + name_len - 4, ".DSA") ||
		!STRCASECMP(file_name + name_len - 3, ".EC")) {
			FILE *f = fopen(file_name, "rb");
			if (f == NULL)
				return false;
			fseek(f, 0, SEEK_END);
			m_length = ftell(f);
			if (m_length == -1)
				return false;
			fseek(f, 0, SEEK_SET);
			m_content = (unsigned char *)malloc(sizeof(unsigned char) * m_length);
			if (fread(m_content, 1, m_length, f) != m_length)
				return false;
			return true;
		}
	return get_from_apk(file_name);
}

/**
 * 根据lenbyte计算出 length所占的字节个数， 1）字节最高位为1，则低7位长度字节数；2）最高位为0，则lenbyte表示长度
 */
int pkcs7::len_num(unsigned char lenbyte)
{
	int num = 1;
	if (lenbyte & 0x80) {
		num += lenbyte & 0x7f;
	}
	return num;
}
/**
 * 将长度信息转化成ASN.1长度格式
 * len <= 0x7f       1
 * len >= 0x80       1 + 非零字节数
 */
int pkcs7::num_from_len(int len)
{
	int num = 0;
	int tmp = len;
	while (tmp) {
		num++;
		tmp >>= 8;
	}
	if ((num == 1 && len >= 0x80) || (num > 1))
		num += 1;
	return num;
}

/**
 *每个element元素都是{tag, length, data}三元组，tag和length分别由tag和len保存，data是由[begin, begin+len)保存。
 *
 *该函数是从data位置计算出到tag位置的偏移值
 */
int pkcs7::tag_offset(element *p)
{
	if (p == NULL)
		return 0;
	int offset = num_from_len(p->len);
	if (m_content[p->begin - offset - 1] == p->tag)
		return offset + 1;
	else	
		return 0;
}

/**
 * 将length转化DER结构的长度表示，存放在buffer位置
 *
 * 返回 写入字节的个数
*/
int pkcs7::put_length(unsigned char *buffer, int length)
{
	int lenbyte = num_from_len(length);
	int ret = lenbyte;
	if (lenbyte == 1) 
		buffer[0] = length;
	else {
		lenbyte--;
		buffer[0] = 0x80 | lenbyte;
		while (lenbyte) {
			buffer[lenbyte] = length & 0xff;
			lenbyte--;
			length >>= 8;
		}
	}
	return ret;
}

/**
 * 根据lenbyte计算长度信息，算法是 lenbyte最高位为1， 则lenbyte & 0x7F表示length的字节长度，后续字节使用大端方式存放
 * 最高位为0， lenbyte直接表示长度
 *
 * 1)若 0x82 0x34 0x45 0x22 ....  0x82是lenbyte， 高位为1，0x82 & 0x7F == 2，则后续两个字节是高端存放的长度信息
    则长度信息为 0x3445
   2)若 lenbyte == 0x34， 最高位为0， 则长度信息是0x34
*/
int pkcs7::get_length(unsigned char lenbyte, int offset)
{
	int len = 0, num;
	unsigned char tmp;
	if (lenbyte & 0x80) {
		num = lenbyte & 0x7f;
		if (num < 0 || num > 4) {
			printf("its too long !\n");
			return 0;
		}
		while (num) {
			len <<= 8;
			tmp = m_content[offset++];
			len += (tmp & 0xff);
			num--;
		}
	} else {
		len = lenbyte & 0xff;
	}
	return len;
}

/**
 * 解析证书中的日期信息
 */
bool pkcs7::parse_time(element *p_val)
{
	if (p_val == NULL || strcmp(p_val->name, "validity") || p_val->tag != TAG_SEQUENCE)
		return false;
	int pos = p_val->begin;
	unsigned char tag;
	int len, base;
	int year, month, day, hour, minute, second;
	for (int i = 0; i < 2; i++) {
		tag = m_content[pos++];
		len = m_content[pos++];
		base = pos;
		if (tag != TAG_UTCTIME && tag != TAG_GENERALIZEDTIME)
			return false;
		if (tag == TAG_UTCTIME) {
			if (len < 11 || len > 17)
				return false;
			year = 10 * (m_content[pos++] - '0');
			year += (m_content[pos++] - '0');
			if (year < 50)
				year += 2000;
			else 
				year += 1900;
			
		} 
		else if (tag == TAG_GENERALIZEDTIME) {
			if (len < 13 || len > 23)
				return false;
			year = 1000 * (m_content[pos++] - '0');
			year += (100 * (m_content[pos++] - '0'));
			year += (10 * (m_content[pos++] - '0'));
			year += (m_content[pos++] - '0');
		} 
		month = 10 * (m_content[pos++] - '0');
		month += (m_content[pos++] - '0');
		
		day = 10 * (m_content[pos++] - '0');
		day += (m_content[pos++] - '0');
		
		hour = 10 * (m_content[pos++] - '0');
		hour += (m_content[pos++] - '0');
		
		minute = 10 * (m_content[pos++] - '0');
		minute += (m_content[pos++] - '0');
		
		if (len - pos + base > 2) {
			second = 10 *(m_content[pos++] - '0');
			second += (m_content[pos++] - '0');
		}
		pos = base + len;
		if (i == 0) 
			printf("Not Before: ");
		else
			printf("Not After : ");
		printf("%d-%02d-%02d %02d:%02d:%02d\n", year, month, day, hour, minute, second);
	} 
	return true;
}

/**
 *根据名字找到pkcs7中的元素, 若没有找到返回NULL.
 *name: 名字，可以只提供元素名字前面的字符
 *begin: 查找的开始位置
 */
element *pkcs7::get_element(const char *name, element *begin)
{
	if (begin == NULL)
		begin = head;
	element *p = begin;
	while (p != NULL) {
		if (strncmp(p->name, name, strlen(name)) == 0)
			return p;
		p = p->next;
	}
	printf("not found the \"%s\"\n", name);
	return p;
}

/**
 * 创建element.pkcs7中的每个元素都有对应element.
 */
int pkcs7::create_element(unsigned char tag, char *name, int level)
{
	unsigned char get_tag = m_content[m_pos++];
	if (get_tag != tag) {
		m_pos--;
		return -1;
	}
	unsigned char lenbyte = m_content[m_pos];
	int len = get_length(lenbyte, m_pos + 1);
	m_pos += len_num(lenbyte);
	
	element *node = (element *)malloc(sizeof(element));
	node->tag = get_tag;
	strcpy(node->name, name);
	node->begin = m_pos;
	node->len = len;
	node->level = level;
	node->next = NULL;
	
	if (head == NULL) {
		head = tail = node;
	} else {
		tail->next = node;
		tail = node;
	}
	return len;
}

/**
 * 解析证书信息
 */
bool  pkcs7::parse_certificate(int level)
{
	char *names[] = {
		"tbsCertificate",
				"version",
				"serialNumber",
				"signature",
				"issuer",
				"validity",
				"subject",
				"subjectPublicKeyInfo",
				"issuerUniqueID-[optional]",
				"subjectUniqueID-[optional]",
				"extensions-[optional]",
		"signatureAlgorithm",
		"signatureValue" };
	int len = 0;
	unsigned char tag;
	bool have_version = false;
	len = create_element(TAG_SEQUENCE, names[0], level);
	if (len == -1 || m_pos + len > m_length) {
		return false;
	}
	//version
	tag = m_content[m_pos];
	if (((tag & 0xc0) == 0x80) && ((tag & 0x1f) == 0)) {
		m_pos += 1;
		m_pos += len_num(m_content[m_pos]);
		len = create_element(TAG_INTEGER, names[1], level + 1);
		if (len == -1 || m_pos + len > m_length) {
			return false;
		}
		m_pos += len;
		have_version = true;
	}

	for (int i = 2; i < 11; i++) {
		switch (i) {
			case 2: 
					tag = TAG_INTEGER;
					break;
			case 8:	
					tag = 0xA1;
					break;
			case 9:	
					tag = 0xA2;
					break;
			case 10:
					tag = 0xA3;
					break;
			default:
					tag = TAG_SEQUENCE;
		}
		len = create_element(tag, names[i], level + 1);
		if (i < 8 && len == -1) {
			return false;
		}
		if (len != -1)
			m_pos += len;
	}
	//signatureAlgorithm
	len = create_element(TAG_SEQUENCE, names[11], level);
	if (len == -1 || m_pos + len > m_length) {
		return false;
	}
	m_pos += len;
	//signatureValue
	len = create_element(TAG_BITSTRING, names[12], level);
	if (len == -1 || m_pos + len > m_length) {
		return false;
	}
	m_pos += len;
	return true;
}

/**
 * 解析签名者信息
 */
bool pkcs7::parse_signerInfo(int level)
{
	char *names[] = {
		"version",
		"issuerAndSerialNumber",
		"digestAlgorithmId",
		"authenticatedAttributes-[optional]",
		"digestEncryptionAlgorithmId",
		"encryptedDigest",
		"unauthenticatedAttributes-[optional]" };
	int len;
	unsigned char tag;
	for (int i = 0; i < sizeof(names)/sizeof(names[0]); i++) {
		switch (i) {
			case 0:
					tag = TAG_INTEGER;
					break;
			case 3:
					tag = 0xA0;
					break;
			case 5:
					tag = TAG_OCTETSTRING;
					break;
			case 6:
					tag = 0xA1;
					break;
			default:
					tag = TAG_SEQUENCE;
			
		}
		len = create_element(tag, names[i], level);
		if (len == -1 || m_pos + len > m_length) {
			if (i == 3 || i == 6)
				continue;
			return false;
		}
		m_pos += len;
	}
	int ret = (m_pos == m_length ? 1 : 0);
	return true;
}

/**
 * 解析 contentType == signedData 的content部分
 */
bool pkcs7::parse_content(int level)
{
	
	char *names[] = {"version", 
					"DigestAlgorithms",
					"contentInfo",
					"certificates-[optional]",
					"crls-[optional]",
					"signerInfos",
					"signerInfo"};

	unsigned char tag;
	int len = 0;	
	element *p = NULL;
	//version
	len = create_element(TAG_INTEGER, names[0], level);
	if (len == -1 || m_pos + len > m_length) {
		return false;
	}
	m_pos += len;
	//DigestAlgorithms
	len = create_element(TAG_SET, names[1], level);
	if (len == -1 || m_pos + len > m_length) {
		return false;
	}
	m_pos += len;
	//contentInfo
	len = create_element(TAG_SEQUENCE, names[2], level);
	if (len == -1 || m_pos + len > m_length) {
		return false;
	}
	m_pos += len;
	//certificates-[optional]
	tag = m_content[m_pos];
	if (tag == TAG_OPTIONAL) {
		m_pos++;
		m_pos += len_num(m_content[m_pos]);
		len = create_element(TAG_SEQUENCE, names[3], level);
		if (len == -1 || m_pos + len > m_length) {
			return false;
		}
		p_cert = tail;
		bool ret = parse_certificate(level + 1);
		if (ret == false) {
			return ret;
		}
	}
	//crls-[optional]
	tag = m_content[m_pos];
	if (tag == 0xA1) {
		m_pos++;
		m_pos += len_num(m_content[m_pos]);
		len = create_element(TAG_SEQUENCE, names[4], level);
		if (len == -1 || m_pos + len > m_length) {
			return false;
		}
		m_pos += len;
	}
	//signerInfos
	tag = m_content[m_pos];
	if (tag != TAG_SET) {
		return false;
	} 
	len = create_element(TAG_SET, names[5], level);
	if (len == -1 || m_pos + len > m_length) {
		return false;
	}
	//signerInfo
	len = create_element(TAG_SEQUENCE, names[6], level + 1);
	if (len == -1 || m_pos + len > m_length) {
			return false;
		}
	p_signer = tail;
	return parse_signerInfo(level + 2);
}

/**
 * 解析文件开始函数
 */
bool pkcs7::parse_pkcs7()
{
	unsigned char tag, lenbyte;
	int len = 0;
	int level = 0;
	tag = m_content[m_pos++];
	if (tag != TAG_SEQUENCE) {
		printf("not found the Tag indicating an ASN.1!\n");
		return false;
	}
	lenbyte = m_content[m_pos];
	len = get_length(lenbyte, m_pos + 1);
	m_pos += len_num(lenbyte);
	if (m_pos + len > m_length)
		return false;
	//contentType 
	len = create_element(TAG_OBJECTID, "contentType", level);
	if (len == -1) {
		printf("not found the ContentType!\n");
		return false;
	}
	m_pos += len;	
	//optional
	tag = m_content[m_pos++];
	lenbyte = m_content[m_pos];
	m_pos += len_num(lenbyte);
	//content-[optional]
	len = create_element(TAG_SEQUENCE, "content-[optional]", level);
	if (len == -1) {
		printf("not found the content!\n");
		return false;
	}
	return parse_content(level + 1);
}

/**
 * 打印输出各个部分的文件偏移以及长度
*/
void pkcs7::print()
{
	printf("-----------------------------------------------------------------------\n");
	printf(" name                                          offset        length\n");
	printf(" ======================================== =============== =============\n");
	element *p = head;
	while (p != NULL) {
		for (int i = 0; i < p->level; i++)
			printf("    ");
		printf(" %s", p->name);
		for (int i = 0; i < 40 - strlen(p->name) - 4*p->level; i++)
			printf(" ");
		printf("%6d(0x%02x)", p->begin, p->begin);
		int num = 0;
		int size = p->begin;
		while (size) {
			num += 1;
			size >>= 4;
		}
		if (num < 2) num = 2;
		for (int i = 0; i < 8 - num; i++)
			printf(" ");
		printf("%4d(0x%02x)\n", p->len, p->len);
		p = p->next;
	}
	printf("-----------------------------------------------------------------------\n");
}


/**
 * 获取证书信息的MD5
 */
char *pkcs7::get_MD5()
{
	if (p_cert == NULL) 
		return NULL;
	static char ret_md5[33]; //静态字符数组，被放入在全局数据区，只申请一次，不用担心内存泄露
	unsigned char md5[16];
	int offset = tag_offset(p_cert);
	if (offset == 0) {
		printf("get offset error!\n");
		return NULL;
	}
	mbedtls_md5(m_content + p_cert->begin - offset, p_cert->len + offset, md5);
	for (int i = 0; i < 16; i++) {
		unsigned char byte = md5[i];
		char high = (((byte >> 4) >= 10) ? ((byte >> 4) - 10 + 'A') : ((byte >> 4) + '0'));
		char low = (((byte & 0x0F) >= 10) ? ((byte & 0x0F) - 10 + 'A') : ((byte & 0x0F) + '0'));
		ret_md5[i*2] = high;
		ret_md5[i*2+1] = low;
	}
	ret_md5[32] = '\0';
	return ret_md5;
}

/**
 * 对签名证书修改后，重新打包生成新的apk
 *
 * minizip中没有删除文件的功能，因此就需要重新创建压缩文件，将之前的文件添加进去
 *       zipOpen64                  创建新的apk文件；
 *       zipOpenNewFileInZip64      添加新的文件；
 *       zipWriteInFileInZip        写入文件内容；
 *       zipCloseFileInZip          关闭当前文件；
 *       zipClose                   关闭apk文件。
 */
bool pkcs7::save_apk(unsigned char *buffer, int length,  const char *save_name)
{
	
	unsigned char *tmp = (unsigned char *)malloc(102400);   //10M
	int tmp_size = 102400;
	zipFile zf = zipOpen64(save_name, APPEND_STATUS_CREATE);
	char filename_inzip[256];
	unz_file_info64 file_info;
	if (zf != NULL) {
		unzFile uf = unzOpen64(apk_file);
		if (uf == NULL) {
			printf("open apk file error!\n");

			return false;
		}
		int err = unzGoToFirstFile(uf);
		while (err == UNZ_OK) {
			if (UNZ_OK != unzGetCurrentFileInfo64(uf, &file_info, filename_inzip, sizeof(filename_inzip), NULL, 0, NULL, 0))
			{
				printf("get file infomation error!\n");
				free(tmp);
				return false;
			}
			if (!strcmp(filename_inzip, cert_file)) {
				zipOpenNewFileInZip64(zf, cert_file, NULL, NULL, 0, NULL, 0, NULL, Z_DEFLATED, Z_BEST_COMPRESSION, 0);
				zipWriteInFileInZip(zf, buffer, length);
				zipCloseFileInZip(zf);
			}
			else {
				err = unzOpenCurrentFile(uf);
				if (err != UNZ_OK) {
					free(tmp);
					return false;
				}
				if (file_info.uncompressed_size > tmp_size) {
					free(tmp);
					tmp_size = file_info.uncompressed_size;
					tmp = (unsigned char *)malloc(tmp_size);	
				}
				err = unzReadCurrentFile(uf, tmp, file_info.uncompressed_size);
				if (err != file_info.uncompressed_size) {
					printf("read content error!\n");
					free(tmp);
					return false;
				}
				unzCloseCurrentFile(uf);
				zipOpenNewFileInZip64(zf, filename_inzip, NULL, NULL, 0, NULL, 0, NULL, Z_DEFLATED, Z_BEST_SPEED, 0);
				zipWriteInFileInZip(zf, tmp, file_info.uncompressed_size);
				zipCloseFileInZip(zf);
			}
			err = unzGoToNextFile(uf);
		}
		zipClose(zf, NULL);
		free(tmp);
		return true;
	}
	free(tmp);
	return false;
}

/**
 * 更改签名证书文件内部contentInfo的 contentType，默认是DATA_OID，可以更改为OLD_DATA_OID
 *
 * DATA_OID = {1, 2, 840, 113549, 1, 7, 1}
 * OLD_DATA_OID = {1, 2, 840, 1113549, 1, 7, 1}
 *
 * type = 0 设置成DATA_OID  签名证书文件默认为这个
 * type = 1 设置成OLD_DATA_OID
 */

bool pkcs7::change_contentType(int type)
{
	int data_oid[] = { 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 01 };
	int old_data_oid[] = { 0x2A, 0x86, 0x48, 0xC3, 0xFB, 0x4D, 0x01, 0x07, 0x01 };
	element *p = get_element("contentInfo", NULL);
	if (p == NULL) {
		printf("not found 'contentInfo'\n");
		return false;
	}
	if (m_content[p->begin + 1] != 0x09) {
		printf("length not match!\n");
		return false;
	}
	int *p_data = (type == 0 ? data_oid : old_data_oid);
	for (int i = 0; i < 0x09; i++) {
		m_content[p->begin + 2 + i] = p_data[i];
	}

	bool ret = false;
	char file[256] = { 0 };
	if (apk_file == NULL) {
		strcpy(file, cert_file);
		strcat(file, ".add");
		FILE *f = fopen(file, "wb");
		if (f != NULL) {
			fwrite(m_content, m_length , 1, f);
			fclose(f);
		}
	}
	else {
		if (strlen(apk_file) <= 4) {
			strcpy(file, apk_file);
			strcat(file, ".apk");
		}
		else {
			strncpy(file, apk_file, strlen(apk_file) - 4);
			file[strlen(apk_file) - 4] = '\0';
			strcat(file, "-change.apk");
		}
		ret = save_apk(m_content, m_length, file);
	}
	return ret;
	
}

/**
 *	证书文件添加内容
 *  data: 数据缓冲区
 *  len: 数据缓冲区长度
 *  tail: 添加数据缓冲区的位置，若为1，添加到末尾；为0，添加到ContentInfo中
 *  save_name: 修改后的保存名，可以为NULL, 若为NULL, example.apk会被保存为example-add.apk
 */
bool pkcs7::add_data(unsigned char *data, int len, int tail, const char *save_name)
{
	if (head == NULL || data == NULL || len == 0)
		return false;
	unsigned char *new_content = NULL; 
	int add_len;
	if (tail == 1) {
		add_len = len;
		new_content = (unsigned char *)malloc(sizeof(unsigned char)* (m_length + len));
		memcpy(new_content, m_content, m_length);
		memcpy(new_content + m_length, data, len);
	}
	else {
		element *p = get_element("contentInfo", NULL);
		if (p == NULL)
			return false;
		if (p->len != 0x0B) {
			printf("Already have data!\n");
			return false;
		}
		add_len = len;      //contentInfo.content - data 
		add_len += num_from_len(len); // contentInfo.content - lenbyte
		add_len += 1;      // contentInfo.content - tag
		add_len += num_from_len(add_len);	// optional - lenbyte
		add_len += 1;		//optional - tag
		
		int contentInfo_len = p->len + add_len;  //contentInfo
		add_len += num_from_len(contentInfo_len) - num_from_len(p->len); 
		p = get_element("content-", NULL);
		if (p == NULL) {
			return false;
		}
		int content_len = p->len + add_len;
		add_len += num_from_len(content_len) - num_from_len(p->len);
		p = get_element("contentType", NULL);
		if (p == NULL)
			return false;
		int optional_len = get_length(m_content[p->begin + p->len + 1], p->begin + p->len + 2);
		optional_len += add_len;
		add_len += num_from_len(optional_len) - num_from_len(optional_len - add_len);
		int total_len = get_length(m_content[1], 2);
		total_len += add_len;
		add_len += num_from_len(total_len) - num_from_len(total_len - add_len);
		new_content = (unsigned char *)malloc(sizeof(unsigned char)* (m_length + add_len));
		int i = 0;
		new_content[i++] = TAG_SEQUENCE;
		i += put_length(new_content + i, total_len);
		memcpy(new_content + i, m_content + p->begin - tag_offset(p), p->len + tag_offset(p));
		i += p->len + tag_offset(p);
		new_content[i++] = 0xA0;
		i += put_length(new_content + i, optional_len);
		new_content[i++] = TAG_SEQUENCE;
		i += put_length(new_content + i, content_len);
		p = get_element("version", NULL);
		if (p == NULL)
			return false;
		memcpy(new_content + i, m_content + p->begin - tag_offset(p), p->len + tag_offset(p));
		i += p->len + tag_offset(p);
		p = get_element("DigestAlgorithms", NULL);
		if (p == NULL)
			return false;
		memcpy(new_content + i, m_content + p->begin - tag_offset(p), p->len + tag_offset(p));
		i += p->len + tag_offset(p);
		new_content[i++] = TAG_SEQUENCE;
		i += put_length(new_content + i, contentInfo_len);
		p = get_element("contentInfo", NULL);
		if (p == NULL)
			return false;
		memcpy(new_content + i, m_content + p->begin, p->len);
		i += p->len;
		new_content[i++] = 0xA0;
		i += put_length(new_content + i, len + num_from_len(len) + 1);
		new_content[i++] = TAG_OCTETSTRING;
		i += put_length(new_content + i, len);
		memcpy(new_content + i, data, len);
		i += len;
		memcpy(new_content + i, m_content + p->begin + p->len, m_length - p->begin - p->len);
	}
	bool ret = false;
	char file[256] = { 0 };
	if (apk_file == NULL) {
		if (save_name == NULL) {
			strcpy(file, cert_file);
			strcat(file, ".add");
		}
		else
			strcpy(file, save_name);
		FILE *f = fopen(file, "wb");
		if (f != NULL) {
			fwrite(new_content, m_length + add_len, 1, f);
			fclose(f);
		}
	}
	else {
			if (save_name == NULL) {
				if (strlen(apk_file) <= 4) {
					strcpy(file, apk_file);
					strcat(file, ".apk");
				}
				else {
					strncpy(file, apk_file, strlen(apk_file) - 4);
					file[strlen(apk_file) - 4] = '\0';
					strcat(file, "-add.apk");
				}
			}
			else
				strcpy(file, save_name);
			ret = save_apk(new_content, m_length + add_len, file);
		}
	free(new_content);
	return ret;
}
