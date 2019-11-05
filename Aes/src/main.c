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


int AesEncrypt(unsigned char *pt,int PtLength,const unsigned char *AesKey)
{
	unsigned char iv[IV_SIZE] = {0};
	memcpy(iv,AesKey,IV_SIZE);
	
	aes_context aes_enc;
	aes_init(&aes_enc);
	
	unsigned char pt_buf[8000] = {0};
	int i = 0;
	for(i; i < PtLength; i++)
	{
		pt_buf[i] = pt[i];
	}

	int index = PtLength;
	int pading = 16 - (index % 16);
    DEBUG_INFO("%d",pading);
	for(i = 0; i < pading; i++)
	{
		pt_buf[index + i] = pading;
	}

    for(i = 0; i < pading+index; i++)
	{
        printf("0x%02x,",pt_buf[i]);
	}
    printf("\n");
    
	int ret = -1;
	ret = aes_setkey_enc(&aes_enc,AesKey,AES_KEY_SIZE);
	if (ret != 0)
	{
		DEBUG_INFO("set aes key failed,ret=%d",ret);
		return -1;
	}

	ret = aes_crypt_cbc(&aes_enc,AES_ENCRYPT,index+pading,iv,pt_buf,pt);
	if (ret != 0)
	{
		DEBUG_INFO("aes cbc en failed,ret=%d",ret);
		return -1;
	}
    DEBUG_INFO("%d",index+pading);
    #if 1
	printf("aes en after:\n");
    //printf("{");
	for(i = 0; i < index + pading; i++)
	{
		printf("0x%02x,",pt[i]);
	}
    //printf("}");
	printf("\n");
    #endif
    return index+pading;
}

int DecryptAes(const unsigned char *DataIn ,int PtLength,const unsigned char* AesKey , unsigned char* DataOut)
{
    int ret;
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

	ret = aes_crypt_cbc(&aes_dec,AES_DECRYPT,PtLength,iv,DataIn,DataOut);
	if (ret != 0)
	{
		DEBUG_INFO("aes en failed,ret=%d",ret);
		return -1;
	}
	if(DataOut[PtLength-1] > PtLength || DataOut[PtLength-1] < 0)
	{
		DataOut[0]='\0';
		return -1;
	}
	int Num = PtLength-DataOut[PtLength-1];
    DataOut[Num]='\0';
	DEBUG_INFO("aes de %s",DataOut);
	return Num;
}



//测试
void TestAes(void)
{
    char AesKey[17] = {"b23456788765432a"};
    char *InBuf = "1234567887654321";
    char EnOutBuf[1024] = {0};
    char DeOutBuf[1024] = {0};
    memcpy(EnOutBuf,InBuf,strlen(InBuf));
    int PtLength = AesEncrypt(EnOutBuf,strlen(InBuf),AesKey);
    if (PtLength < 0){
        return;
    }
    DecryptAes(EnOutBuf,PtLength,AesKey,DeOutBuf);
    DEBUG_INFO("%s",DeOutBuf);
}

int main(void)
{
    TestAes();
    
	return 0;
}
