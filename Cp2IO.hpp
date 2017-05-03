#pragma once

/*
Header file for Crypto-Project 2 Input/Output

*/

#include <stdio.h>
#include <iostream>


class encryptedFile {
private:
	char * fname;
	FILE * file;
	int header_ver;
	int crypt_algo;
	int hash_algo;
	int n_blocks;
	size_t block_size;
public:
	encryptedFile(char*filename); // open a existing encrypted file
	encryptedFile(char*filename, int CryptAlgo, int HashAlgo, int NBlocks, size_t Blocksize); // create a new encrypted file
	int getHeaderVer();
	int getCryptAlgorithm();
	int getHashAlgorithm();
	int getNumBlocks();
	int getBlock(int bnum, void*buffer,size_t max_buffer_size);
	int getBlockHash(int bnum, void*buffer, size_t max_buffer_size);
	int setBlock(int bnum, void*buffer, size_t buffer_size);
	int setBlockHash(int bnum, void*buffer, size_t buffer_size);
	void Fileclose() { fclose(file); }
	size_t getBlockSize();
};

struct headerv1 {
	long magic;
	int header_ver;
	int crypt_algo;
	int hash_algo;
	int n_blocks;
	size_t blocksize;
};
struct Sha256Hash {
	char hash[256];
};