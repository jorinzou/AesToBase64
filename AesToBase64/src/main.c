#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "polarssl/des.h"
#include "polarssl/base64.h"
#include "polarssl/entropy.h"
#include "polarssl/ctr_drbg.h"
#include "polarssl/rsa.h"
#include "polarssl/aes.h"

#define AES_KEY_SIZE 128
#define IV_SIZE    16
#define AES_KEY_LEN 16

#define DEBUG_INFO(fmt, args...) printf("\033[33m[%s:%s:%d]\033[0m "#fmt"\r\n", __FILE__,__FUNCTION__, __LINE__, ##args)

//aes加密，base64输出
void AesEncryptAndOutBase64(const unsigned char *InBuf,int InBufLen,const unsigned char *AesKey,unsigned char *OutBuf)
{
	unsigned char iv[IV_SIZE] = {0};
	memcpy(iv,AesKey,IV_SIZE);
	
	aes_context aes_enc;
	aes_init(&aes_enc);
	
	unsigned char pt_buf[8000] = {0};
	int i = 0;
	for(i; i < InBufLen; i++)
	{
		pt_buf[i] = InBuf[i];
	}


    //不够16字节的剩余部分，填充
	int index = InBufLen;
	int pading = 16 - (index % 16);
	for(i = 0; i < pading; i++)
	{
		pt_buf[index + i] = pading;
	}

	int ret = -1;
	ret = aes_setkey_enc(&aes_enc,AesKey,AES_KEY_SIZE);
	if (ret != 0)
	{
		DEBUG_INFO("set aes key failed,ret=%d",ret);
		return;
	}

	ret = aes_crypt_cbc(&aes_enc,AES_ENCRYPT,index+pading,iv,pt_buf,pt_buf);
	if (ret != 0)
	{
		DEBUG_INFO("aes cbc en failed,ret=%d",ret);
		return;
	}

    #if 1
	printf("aes en after:");
	for(i = 0; i < index + pading; i++)
	{
		printf("%02x",pt_buf[i]);
	}
	printf("\n");
    #endif

	size_t n = 0;
    //第一个参数为NULL，表示获取密文长度
	base64_encode(NULL,&n,pt_buf,index + pading);
    //第二次真正解码
	ret = base64_encode(OutBuf,&n,pt_buf,index + pading);
	if (ret != 0)
	{
		DEBUG_INFO("baae64 encode failed,ret=%d",ret);
		return;
	}
    DEBUG_INFO("aes en,base64 encode out:%s",OutBuf);
}

//base解码，aes解密
int DecryptBas64Aes(const unsigned char *Base64 ,const unsigned char* AesKey , unsigned char * OutBuf)
{
	size_t n = 0;
	int ret = -1;
	unsigned char base64_de_out[8000] = {0};
    //第一个参数为NULL，表示获取密文长度
	base64_decode(NULL,&n,Base64,strlen(Base64));
    //第二次真正解码
	ret = base64_decode(base64_de_out,&n,Base64,strlen(Base64));
	if (ret != 0)
	{
		DEBUG_INFO("base de failed,ret=%d",ret);
		return -1;
	}

    #if 1
	DEBUG_INFO("base de after:");
	int i = 0;
	for(i = 0; i < n; i++)
	{
		printf("%02x",base64_de_out[i]);
	}
	printf("\n");
    #endif

	unsigned char iv[IV_SIZE] = {0};
	memcpy(iv,AesKey,IV_SIZE);
	aes_context aes_dec;
	aes_init(&aes_dec);
	ret = aes_setkey_dec(&aes_dec,AesKey,AES_KEY_SIZE);
	if (ret != 0)
	{
		DEBUG_INFO("set aes key dec failed,ret=%d",ret);
		return -1;
	}

    //aes解密
	ret = aes_crypt_cbc(&aes_dec,AES_DECRYPT,n,iv,base64_de_out,OutBuf);
	if (ret != 0)
	{
		DEBUG_INFO("aes en failed,ret=%d",ret);
		return -1;
	}

    //有时解密失败，会导致填充部分的index异常(大于整个数组长度，或者小于0)，为了防止数组越界，这里作一下判断
	if(OutBuf[n-1] > n || OutBuf[n-1] < 0)
	{
		OutBuf[0]='\0';
		return -1;
	}

    //最后一个字符填充'\0',不然用strcmp不能比较
	int Num = n-OutBuf[n-1];
    OutBuf[Num]='\0';
	DEBUG_INFO("aes de %s",OutBuf);
	return Num;
}


//测试
void TestAes(void)
{
    char AesKey[17] = {"1234567887654321"};
    char *InBuf = "abcdef明文";
    char EnOutBuf[1024] = {0};
    char DeOutBuf[1024] = {0};
    AesEncryptAndOutBase64(InBuf,strlen(InBuf),AesKey,EnOutBuf);
    DecryptBas64Aes(EnOutBuf,AesKey,DeOutBuf);
    DEBUG_INFO("%s",DeOutBuf);
}

int main(void)
{
   TestAes();
    
	return 0;
}
