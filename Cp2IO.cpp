#include "Cp2IO.hpp"
#include <exception>
#include <fstream>
#define DEBUG
#ifdef DEBUG
#define DBG(...) std::cout<<__VA_ARGS__<<std::endl
#else
#define DBG(...) 
#endif
encryptedFile::encryptedFile(char * filename) {
	fname = (char*) malloc(strlen(filename)+1);
	memcpy(fname, filename, strlen(filename));
#ifdef _MSC_VER
	fopen_s(&file, filename, "r+b");
#else
	file = fopen(filename, "r+b");
#endif
	if (file == NULL) {
		throw new std::exception("File Not found");
	}
	unsigned long magic = 0;
	int headerver = 0;
	int nrd = fread(&magic, sizeof(long), 1, file);
	if (nrd < 1) {
		throw new std::exception("File is empty");
	}
	if (magic != 0xdeadbeef) {
		throw new std::exception("Wrong Magic Number");
	}
	nrd = fread(&headerver, sizeof(int), 1, file);
	if (nrd < 1) {
		throw new std::exception("File is empty");
	}
	if (headerver != 1) {
		throw new std::exception("Unknown File Version");
	}
	fseek(file, 0, 0);
	struct headerv1 hdr;
	nrd = fread(&hdr, sizeof(struct headerv1), 1, file);
	header_ver = hdr.header_ver;
	crypt_algo = hdr.crypt_algo;
	hash_algo = hdr.hash_algo;
	n_blocks = hdr.n_blocks;
	block_size = hdr.blocksize;
}
bool f_exists(const char *f)
{
	std::ifstream e = std::ifstream(f);
	return e.good();
}


encryptedFile::encryptedFile(char * filename, int CryptAlgo, int HashAlgo, int NBlocks, size_t Blocksize)
{
	bool existed = false;
	if (f_exists(filename)) {
		existed = true;
		DBG("FILE EXISTS!");
	}
	else {

#ifdef _MSC_VER
		fopen_s(&file, filename, "w+b");
		fclose(file);
#else
		file = fopen(filename, "w+b");
		fclose(file);
#endif
	}
	fname = (char*)malloc(strlen(filename) + 1);
	memcpy(fname, filename, strlen(filename));
#ifdef _MSC_VER
	fopen_s(&file, filename, "r+b");
#else
	file = fopen(filename, "r+b");
#endif
	if (file == NULL) {
		throw new std::exception("Could not create file!");
	}
	struct headerv1 hdr;
	if (!existed) {
		hdr.magic = 0xdeadbeef;
		hdr.header_ver = 1;
		hdr.crypt_algo = CryptAlgo;
		hdr.hash_algo = HashAlgo;
		hdr.n_blocks = NBlocks;
		hdr.blocksize = Blocksize;
	}
	

	// if the file already existed
	if (existed) {
		fseek(file, 0, 0);
		int nrd = fread(&hdr,sizeof(char), sizeof(headerv1), file);
		if (nrd != sizeof(hdr)) {
			DBG("NRD = " << nrd);
			throw new std::exception("Filename in use (Not Valid)");
		}
		if (((unsigned)hdr.magic) != (long)0xdeadbeef || hdr.header_ver != 1)
			throw new std::exception("Filename in use (Not Valid)");
	}
	else {
		fwrite(&hdr, sizeof(struct headerv1), 1, file);
	}

	// read back out the file versions!

	header_ver = hdr.header_ver;
	crypt_algo = hdr.crypt_algo;
	hash_algo = hdr.hash_algo;
	n_blocks = hdr.n_blocks;
	block_size = hdr.blocksize;
	if (existed) return;



	// create zero rest of file
	void* zblock = malloc(block_size);
	memset(zblock, 0, block_size);
	size_t hash_size = 0;
	if (hash_algo == 1) {
		hash_size = sizeof(struct Sha256Hash);
	}
	void* zhash = malloc(hash_size);
	memset(zhash, 0, hash_size);
	for (int i = 0; i < NBlocks; i++) {
		fwrite(zhash, hash_size, 1, file);
	}
	for (int i = 0; i < NBlocks; i++) {
		fwrite(zblock, block_size, 1, file);
	}
}

int encryptedFile::getHeaderVer()
{
	return header_ver;
}

int encryptedFile::getCryptAlgorithm()
{
	return crypt_algo;
}

int encryptedFile::getHashAlgorithm()
{
	return hash_algo;
}

int encryptedFile::getNumBlocks()
{
	return n_blocks;
}

int encryptedFile::getBlock(int bnum, void * buffer, size_t max_buffer_size)
{
	if (file == NULL) {
		exit(1);
	}
	size_t seek = 0;
	if (header_ver == 1) {
		seek += sizeof(struct headerv1);
	}
	if (hash_algo == 1) {
		seek += sizeof(struct Sha256Hash) * n_blocks;
	}
	seek += block_size*bnum;
	fseek(file, seek, 0);
	int to_read = max_buffer_size;
	if (to_read > block_size) { // truncate
		to_read = block_size;
	}
	return fread(buffer, sizeof(char),to_read,file);
}

int encryptedFile::getBlockHash(int bnum, void * buffer, size_t max_buffer_size)
{
	if (file == NULL) {
		exit(1);
	}
	size_t seek = 0;
	size_t hash_size =0;
	if (header_ver == 1) {
		seek += sizeof(struct headerv1);
	}
	if (hash_algo == 1) {
		hash_size = sizeof(struct Sha256Hash);
	}
	seek += bnum * hash_size;
	if (hash_size > max_buffer_size) {
		return 0;
	}
	fseek(file, seek, 0);
	int nread = fread(buffer, sizeof(char), hash_size, file);
	return nread;
}

int encryptedFile::setBlock(int bnum, void * buffer, size_t buffer_size)
{
	if (file == NULL) {
		exit(1);
	}
	size_t seek = 0;
	if (header_ver == 1) {
		seek += sizeof(struct headerv1);
	}
	if (hash_algo == 1) {
		seek += sizeof(struct Sha256Hash) * n_blocks;
	}
	seek += block_size*bnum;
	fseek(file, seek, 0);
	if (buffer_size > block_size) { // truncate
		buffer_size = block_size;
	}
	return fwrite(buffer,1,buffer_size,file);
}

int encryptedFile::setBlockHash(int bnum, void * buffer, size_t buffer_size)
{
	if (file == NULL) {
		exit(1);
	}
	size_t seek = 0;
	size_t hash_size = 0;
	if (header_ver == 1) {
		seek += sizeof(struct headerv1);
	}
	if (hash_algo == 1) {
		hash_size = sizeof(struct Sha256Hash);
	}
	seek += bnum * hash_size;
	if (hash_size < buffer_size) {
		return 0;
	}
	fseek(file, seek, 0);
	return fwrite(buffer, hash_size, 1, file);
}

size_t encryptedFile::getBlockSize()
{
	return block_size;
}
