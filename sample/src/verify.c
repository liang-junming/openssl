#include <stdio.h>
#include <string.h>
#include <unistd.h>  
#include <fcntl.h>  
#include <sys/types.h>  
#include <sys/stat.h> 
#include <openssl/sha.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>

unsigned char *sha(const char *filePath)
{
    SHA256_CTX sha;
    int fd = -1;
    unsigned char buff[1024];
    int len;
    unsigned char *hash;

    fd = open(filePath, O_RDONLY);
    if (fd == -1)
    {
        printf("E:Can not open file:%s\n", filePath);
        return NULL;
    }

    SHA256_Init(&sha);

    while ((len = read(fd, buff, sizeof(buff))) > 0)
        SHA256_Update(&sha, buff, len);
    
    hash = (unsigned char *)malloc(32);
    if (hash == NULL)
    {
        printf("E:Malloc error!\n");
		close(fd);
        return NULL;
    }

    SHA256_Final(hash, &sha);

	close(fd);
    return hash;
}

int rsaVerify(const char *certPath, const char *pubkeyPath, unsigned char **buff)
{
	RSA *pRSA;
	FILE *file;
	int rsaLen;
	unsigned char *result;

	int fd;
	unsigned char *data;
	int dLen;

    fd = open(certPath, O_RDONLY);
    if (fd == -1)
    {
        printf("E:Can not open file:%s\n", certPath);
        return -1;
    }
	dLen = lseek(fd, 0, SEEK_END);
	lseek(fd, 0, SEEK_SET);
	data = (unsigned char *)malloc(dLen);
	read(fd, data, dLen);
	close(fd);

	if ((file = fopen(pubkeyPath, "r")) == NULL)
	{
		printf("E:can not open file:%s\n", pubkeyPath);
		free(data);
		return -1;
	}

	if ((pRSA = PEM_read_RSA_PUBKEY(file,NULL,NULL,NULL)) == NULL)
	{
		printf("E:can not read public key!\n");
		fclose(file);
		free(data);
		return -1;
	}

	rsaLen = RSA_size(pRSA);
	if ((result = (unsigned char *)malloc(rsaLen + 1)) == NULL)
	{
		printf("E:malloc error!\n");
		fclose(file);
		free(data);
		RSA_free(pRSA);
		return -1;
	}
	memset(result, 0, rsaLen+1);

	int rLen;
	rLen = RSA_public_decrypt(dLen, data, result, pRSA, RSA_PKCS1_PADDING);
	if (rLen < 0)
	{
		printf("E:RSA_public_decrypt error!\n");
		fclose(file);
		free(data);
		RSA_free(pRSA);
		return -1;
	}
	*buff = result;

	RSA_free(pRSA);
	fclose(file);
	free(data);

	return rLen;
}


int main(int argc, char **argv)
{
    char *filePath=NULL,*keyPath=NULL,*certPath=NULL;

    if (argc != 4)
    {
        printf("Usage:\nfile=\nkey=\ncert=\n");
        return -1;
    }

    int i;
    for (i=1; i<4; i++)
    {
        char *argType,*argValure;
        argType = strtok_r(argv[i], "=", &argValure);
        if (!strcmp(argType, "file"))
            filePath = argValure;
        else if (!strcmp(argType, "key"))
            keyPath = argValure;
        else if (!strcmp(argType, "cert"))
            certPath = argValure;
    }

    if (filePath==NULL || keyPath==NULL || certPath==NULL)
    {
        printf("Usage:\nfile=\nkey=\ncert=\n");
        return -1;
    }

    unsigned char *hash = NULL;
    hash = sha(filePath);
    if (hash == NULL)
        return -1;

	int verLen;
	unsigned char *verData;
	verLen = rsaVerify(certPath, keyPath, &verData);
	if (verLen < 0)
		return -1;

	if (verLen != 32)
	{
		printf("error size of verify data!\n");
		return -1;
	}
	
	if (memcmp(verData, hash, 32) != 0)
	{
		printf("memcmp failure!\n");
		return -1;
	}

#ifdef DEBUG
    for (i=0; i<32; i++)
    {
        printf("%.2x", hash[i]);
        if (i%16 == 15)
            printf("\n");
    }

	for (i=0; i<verLen; i++)
	{
		printf("%.2x", verData[i]);
		if (i%16 == 15)
			printf("\n");
	}
#endif

	free(hash);
	free(verData);
    return 0;
}












