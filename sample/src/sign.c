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

int rsaSign(const unsigned char *data, int dLen, const char *prikeyPath, unsigned char **buff)
{
	RSA *pRSA;
	FILE *file;
	int rsaLen;
	unsigned char *result;

	if ((file = fopen(prikeyPath, "r")) == NULL)
	{
		printf("E:can not open file:%s\n", prikeyPath);
		return -1;
	}

	if ((pRSA = PEM_read_RSAPrivateKey(file,NULL,NULL,NULL)) == NULL)
	{
		printf("E:can not read public key!\n");
		fclose(file);
		return -1;
	}

	rsaLen = RSA_size(pRSA);
	if ((result = (unsigned char *)malloc(rsaLen + 1)) == NULL)
	{
		printf("E:malloc error!\n");
		fclose(file);
		RSA_free(pRSA);
		return -1;
	}
	memset(result, 0, rsaLen+1);

	int rLen;
	rLen = RSA_private_encrypt(dLen, data, result, pRSA, RSA_PKCS1_PADDING);
	if (rLen < 0)
	{
		printf("E:RSA_private_encrypt error!\n");
		fclose(file);
		free(result);
		RSA_free(pRSA);
		return -1;
	}
	*buff = result;

	RSA_free(pRSA);
	fclose(file);

	return rLen;
}


int main(int argc, char **argv)
{
    char *filePath=NULL,*keyPath=NULL;

    if (argc != 3)
    {
        printf("Usage:\nfile=\nkey=\n");
        return -1;
    }

    int i;
    for (i=1; i<3; i++)
    {
        char *argType,*argValure;
        argType = strtok_r(argv[i], "=", &argValure);
        if (!strcmp(argType, "file"))
            filePath = argValure;
        else if (!strcmp(argType, "key"))
            keyPath = argValure;
    }

    if (filePath==NULL || keyPath==NULL)
    {
        printf("Usage:\nfile=\nkey=\n");
        return -1;
    }

    unsigned char *hash = NULL;
    hash = sha(filePath);
    if (hash == NULL)
        return -1;

	int signLen;
	unsigned char *signData;
	signLen = rsaSign(hash, 32, keyPath, &signData);
	if (signLen < 0)
		return -1;
	
	int fd;
	umask(0);
    fd = open(strcat(filePath, "_cert.bin"), O_WRONLY | O_CREAT | O_TRUNC, S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP|S_IROTH);
    if (fd == -1)
    {
        printf("E:Can not open file:%s\n", filePath);
        return -1;
    }

	write(fd, signData, signLen);
	close(fd);

#ifdef DEBUG
    for (i=0; i<32; i++)
    {
        printf("%.2x", hash[i]);
        if (i%16 == 15)
            printf("\n");
    }
	printf("--------------------------------\n");
	for (i=0; i<signLen; i++)
	{
		printf("%.2x", signData[i]);
		if (i%16 == 15)
			printf("\n");
	}
#endif

	free(hash);
	free(signData);
    return 0;
}












