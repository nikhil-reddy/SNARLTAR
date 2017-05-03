// CryptoProj2CLI.cpp : Defines the entry point for the console application.//
//CANT RUN WITHOUT THEM
#include "stdafx.h"
#include "Cp2IO.hpp"
#include <string>
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <fstream>
#include <sys/stat.h>
#include <openssl/aes.h>
#include <openssl/hmac.h>
using namespace std;
HMAC_CTX ctx;
//DEFINE COUNTER
struct ctr_state {
	unsigned char ivec[16];
	unsigned int num;
	unsigned char ecount[16];
};

//GLOBAL VARIABLES
char filename[20];
AES_KEY key;//AES KEY
struct ctr_state state;
unsigned char ckey[50];
unsigned char ckey1[50];
unsigned char iv[8] = { 0 };
unsigned char b[2048];
//PSEUDO RANDOM NUMBER GENERATOR
int prng(int number)
{
	srand(number);
	return rand() % 99999999999;
}

//HASHING BLOCK
void hasher(unsigned char indata[256], unsigned char * key, int blcksize, encryptedFile f1, int j)
{
	unsigned char *result;
	unsigned int len = 64;
	result = (unsigned char*)malloc(sizeof(char) *len);
	HMAC_Init_ex(&ctx, key, 4, EVP_sha256(), NULL);
	HMAC_Update(&ctx, indata, blcksize);
	HMAC_Final(&ctx, result, &len);
	HMAC_CTX_cleanup(&ctx);
	f1.setBlockHash(j, result, blcksize);
}

//GENERATES RANDOM STRINGS OF DEFINED LENGTH
unsigned char * genRandom(int blcksize, int random)
{
	random += prng(random);
	srand(random);
	static const char alphanum[] =
		"0123456789"
		"!@#$%^&*"
		"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
		"abcdefghijklmnopqrstuvwxyz";
	int stringLength = sizeof(alphanum) - 1;
	for (int i = 0; i < blcksize; ++i)
	{
		b[i] = (unsigned char)alphanum[rand() % stringLength];
	}
	return b;
}

//INIT COUNTER
void init_ctr(struct ctr_state *state, const unsigned char iv[8])
{
	state->num = 0;
	memset(state->ecount, 0, 16);
	memset(state->ivec + 8, 0, 8);
	memcpy(state->ivec, iv, 8);
}

//ENCRYPT BLOCK
void encrypt(unsigned char indata[256], int blcksize, int i, encryptedFile f1, unsigned char *ckey)
{
	AES_set_encrypt_key(ckey, blcksize, &key);
	unsigned char outdata[256];
	init_ctr(&state, iv);
	AES_ctr128_encrypt(indata, outdata, blcksize, &key, state.ivec, state.ecount, &state.num);
	f1.setBlock(i, outdata, blcksize);
}

//DECRYPT BLOCK
void decrypt(unsigned char indata[256], int blcksize, unsigned char * ckey, int j)
{
	FILE *op;
	fopen_s(&op, "deciphered.txt", "wb");
	fseek(op, 0, SEEK_END);
	AES_set_encrypt_key(ckey, blcksize, &key);
	unsigned char outdata[256];
	init_ctr(&state, iv);
	AES_ctr128_encrypt(indata, outdata, blcksize, &key, state.ivec, state.ecount, &state.num);
	fwrite(outdata, 1, blcksize, op);
	fclose(op);
	j += 1;
}
//DENIABILITY BLOCK
int deniability(unsigned char *ckey, int random, int blcksize, int bytes_written, int j, encryptedFile f1)// file deniability 
{
	int dummy_bytes = 0;
	unsigned char *buffer = NULL;
	while (dummy_bytes != bytes_written)
	{
		buffer = genRandom(blcksize, random);
		unsigned char buffer2[256];
		encrypt(buffer, blcksize, j, f1, ckey);
		f1.getBlock(j, buffer2, blcksize);
		hasher(buffer2, ckey, blcksize, f1, j);
		dummy_bytes += 1;
		j += 1;
	}
	return j;
}
//HASH CHECKER
int hash_checker(unsigned char buffer[256], unsigned char indata[256], unsigned char * key, int blcksize, int j)
{
	int flag = 0;
	unsigned char *result;
	unsigned int len = 64;
	result = (unsigned char*)malloc(sizeof(char) *len);
	HMAC_CTX ctx;
	HMAC_CTX_init(&ctx);
	HMAC_Init_ex(&ctx, key, sizeof(key), EVP_sha256(), NULL);
	HMAC_Update(&ctx, indata, blcksize);
	HMAC_Final(&ctx, result, &len);
	HMAC_CTX_cleanup(&ctx);
	for (int a = 0; a < sizeof(result); a++)
	{
		if (result[a] == buffer[a])
		{
			flag = 1;
		}
		else
			flag = 0;
		break;
	}
	if (flag == 1)
	{
		decrypt(indata, blcksize, (unsigned char *)key, j);
		return j;
	}
	else
	{
		return j;
	}
}
//MAIN BLOCK
int main()
{
	int blcksize = 0, num_blocks = 0, random = 0;
	int cs = 0, b = 0, fin_blocks = 0;
	cout << "\n WELCOME TO SNARLTAR \n";
	cout << "\n ...YOUR FRIENDLY DENIABLE FILE SYSTEM... \n";
	//SWITCH SCHEME FOR BETTER CLI UI
	cout << "\nEnter the function you want to run:\n";
	cout << "1.Encrypt\n";
	cout << "2.Decrypt\n";
	cin >> cs;
	srand((int)time(NULL));
	random = rand() % 10000000;
	if (cs == 1)
	{
		srand(random);
		cout << "Enter the file name that you want to Encrypt using SNARLTAR: ";
		cin >> filename;
		cout << "Enter the block size: ";
		cin >> blcksize;
		cout << "Enter the number of files: ";
		cin >> num_blocks;
		b = rand() % num_blocks;
		int j = 0;
		int bytes_read = 0, bytes_written = 0;
		//find num of blocks of file..
		FILE *ifs;
		fopen_s(&ifs, filename, "rb");
		fseek(ifs, 0L, SEEK_END);
		bytes_read = ftell(ifs);
		bytes_written = ((bytes_read - 1) / blcksize) + 1;
		fin_blocks = num_blocks * bytes_written;
		fopen_s(&ifs, filename, "rb");
		encryptedFile f1 = encryptedFile("encrypted.txt", 1, 1, fin_blocks, blcksize);
		//Deniable File
		for (int i = 0; i < num_blocks; i++)
		{
			//ckey[50] = NULL;
			cout << "Enter the password:\n";
			cin >> (unsigned char *)ckey;
			if (i == b)
			{
				int dummy_blocks = 0;
				while (dummy_blocks < bytes_written)
				{
					unsigned char buffer[256];
					unsigned char buffer2[256];
					fread((char *)buffer, 1, blcksize, ifs);
					encrypt(buffer, blcksize, j, f1, ckey);
					f1.getBlock(j, buffer2, blcksize);
					hasher(buffer2, ckey, blcksize, f1, j);
					j += 1;
					dummy_blocks += 1;
				}
				strcpy_s((char *)ckey1, sizeof(ckey), (char *)ckey);
				fclose(ifs);
			}
			else
			{
				random += rand() % 10000000;
				random += prng(random);
				j = deniability(ckey, random, blcksize, bytes_written, j, f1);
			}
		}
		remove(filename);
		cout << "\n Your file password is :" << ckey1 << "\n";
		cout << "\n...FILE ENCRYPTED SUCCESSFULLY...\n";
		cout << "\n !THANK YOU FOR USING SNARLTAR DENIABLE SYSTEM! \n";
	}
	else if (cs == 2)
	{
		int i, j = 0;
		cout << "Enter the file name that you want to decrypt using SNARLTAR: ";
		cin >> filename;
		encryptedFile f4 = encryptedFile(filename);
		num_blocks = f4.getNumBlocks();
		blcksize = f4.getBlockSize();
		cout << "\n" << blcksize << "\n";
		cout << "Enter the password for the block:\n";
		cin >> (unsigned char *)ckey;
		for (i = 0; i < num_blocks; i++)
		{
			unsigned char buffer[256];
			unsigned char buffer1[256];
			f4.getBlockHash(i, buffer, blcksize);
			f4.getBlock(i, buffer1, blcksize);
			j = hash_checker(buffer, buffer1, ckey, blcksize, j);
		}
		remove(filename);
		cout << "\n...FILE DECRYPTED SUCCESSFULLY...\n";
		cout << "\n !THANK YOU FOR USING SNARLTAR DENIABLE SYSTEM! \n";
	}
	else
	{
		cout << "\n...OH NO!Bad case! PLEASE RE-RUN THE SNARLTAR...\n";
		exit(1);
	}
	return 0;
}
