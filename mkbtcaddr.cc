/*
 * mkbtcaddr - Generate encrypted bitcoin keypair
 *
 * Based on code by:
 *
 * Copyright (c) 2009-2010 Satoshi Nakamoto
 * Distributed under the MIT/X11 software license, see
 * http://www.opensource.org/licenses/mit-license.php.
 *
 * Permission is hereby granted, free of charge, to any person 
 * obtaining a copy of this software and associated documentation files 
 * (the "Software"), to deal in the Software without restriction, 
 * including without limitation the rights to use, copy, modify, merge, 
 * publish, distribute, sublicense, and/or sell copies of the Software, 
 * and to permit persons to whom the Software is furnished to do so, 
 * subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be 
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, 
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF 
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND 
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS 
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN 
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN 
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE 
 * SOFTWARE.
 */

/*
 * Donations accepted: 1JQ3c5P1xeR1hfYecHQ6vMp2kDswn4xnVa
 */

#include <algorithm>
#include <set>
#include <stdexcept>
#include <string>
#include <vector>

#include <assert.h>
#include <limits.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <db.h>
#include <gpgme.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/obj_mac.h>
#include <openssl/rand.h>
#include <openssl/ripemd.h>
#include <openssl/sha.h>

static void die(const char *message)
{
	fprintf(stderr, "error: %s\n", message);

	/* Try hard to really die. */
	abort();
	exit(EXIT_FAILURE);
	++*((char *) 0);
	while (1)
		;
}

static std::string base58_encode(const unsigned char *p, unsigned int n)
{
	static const char pszBase58[] =
		"123456789"
		"ABCDEFGHJKLMNPQRSTUVWXYZ"
		"abcdefghijkmnopqrstuvwxyz";

	BN_CTX *pctx = BN_CTX_new();
	if (!pctx)
		die("BN_CTX_new() returned error");

	BIGNUM bn58;
	BN_init(&bn58);
	if (!BN_set_word(&bn58, 58))
		die("BN_set_word() returned error");

	BIGNUM bn0;
	BN_init(&bn0);
	if (!BN_set_word(&bn0, 0))
		die("BN_set_word() returned error");

	/* Convert big endian data to little endian */
	/* Extra zero at the end make sure bignum will interpret as a positive number */
	std::vector<unsigned char> vchTmp(n, 0);
	reverse_copy(p, p + n, vchTmp.begin());

	/* Convert little endian data to bignum */
	BIGNUM bn;
	BN_init(&bn);

	{
		const std::vector<unsigned char> &vch = vchTmp;
	        std::vector<unsigned char> vch2(vch.size() + 4);
	        unsigned int nSize = vch.size();
	        vch2[0] = (nSize >> 24) & 0xff;
	        vch2[1] = (nSize >> 16) & 0xff;
	        vch2[2] = (nSize >> 8) & 0xff;
	        vch2[3] = (nSize >> 0) & 0xff;
	        reverse_copy(vch.begin(), vch.end(), vch2.begin() + 4);

	        if (!BN_mpi2bn(&vch2[0], vch2.size(), &bn))
			die("BN_mpi2bn() returned error");
	}

	/* Convert bignum to std::string */
	std::string str;

	BIGNUM dv;
	BN_init(&dv);

	BIGNUM rem;
	BN_init(&rem);

	while (BN_cmp(&bn, &bn0) > 0) {
		if (!BN_div(&dv, &rem, &bn, &bn58, pctx))
			die("BN_div() returned error");

		if (!BN_copy(&bn, &dv))
			die("BN_copy() returned error");

		unsigned int c = BN_get_word(&rem);
		if (c > sizeof(pszBase58))
			die("base58 remainder was out of range");

		str += pszBase58[c];
	}

	BN_clear_free(&bn58);
	BN_clear_free(&bn0);
	BN_clear_free(&bn);
	BN_clear_free(&dv);
	BN_clear_free(&rem);

	BN_CTX_free(pctx);

	/* Encode leading zeros as base58 zeros */
	for (unsigned int i = 0; i < n && p[i] == 0; ++i)
		str += pszBase58[0];

	/* Convert little endian std::string to big endian */
	reverse(str.begin(), str.end());
	return str;
}

static std::string base58_encode(const std::vector<unsigned char>& vch)
{
	return base58_encode(&vch[0], vch.size());
}

static gpgme_error_t read_passphrase(void *hook, const char *uid_hint,
	const char *passphrase_info, int prev_was_pad, int fd)
{
	if (uid_hint)
		die("UID hint was provided");

	/* Be paranoid. Just in case. */

	char *tmp1 = getpass("Passphrase: ");
	char *passphrase1 = strdup(tmp1);
	memset(tmp1, 0, strlen(tmp1));

	size_t passphrase_len = strlen(passphrase1);
	if (passphrase_len < 8)
		fprintf(stderr, "warning: short passphrase\n");

	char *tmp2 = getpass("Repeat passphrase: ");
	char *passphrase2 = strdup(tmp2);
	memset(tmp2, 0, strlen(tmp2));

	if (strcmp(passphrase1, passphrase2))
		die("passphrase mismatch");

	/* Don't need this one anymore. */
	memset(passphrase2, 0, passphrase_len);
	free(passphrase2);

	FILE *fp = fdopen(fd, "a");
	if (!fp)
		die("fdopen() returned error");

	if (fwrite(passphrase1, 1, passphrase_len, fp) != passphrase_len) {
		memset(passphrase1, 0, passphrase_len);
		die("fwrite() too short");
	}

	if (fwrite("\n", 1, 1, fp) != 1)
		die("fwrite() too short");

	memset(passphrase1, 0, passphrase_len);
	free(passphrase1);

	if (fflush(fp) != 0)
		die("fflush() returned error");

	if (fclose(fp) != 0)
		die("fclose() returned error");

	return GPG_ERR_NO_ERROR;
}

static void gpgme_data_printf(gpgme_data_t dh, const char *format, ...)
{
	va_list ap;
	va_start(ap, format);

	char *str;
	int len = vasprintf(&str, format, ap);
	if (len == -1)
		die("vasprintf() returned error");

	va_end(ap);

	int len2 = gpgme_data_write(dh, str, len);
	if (len2 != len)
		die("gpgme_data_write() too short");

	free(str);
}

static void gpgme_data_print_bytes(gpgme_data_t dh,
	const unsigned char *bytes, unsigned int n)
{
	if (n <= 252) {
		gpgme_data_printf(dh, "%02x", n);
	} else if (n <= 65535) {
		gpgme_data_printf(dh, "%02x%02x%02x",
			253, n & 0xff, (n >> 8) & 0xff);
	} else {
		die("gpgme_print_bytes(): string too long");
	}

	for (unsigned int i = 0; i < n; ++i)
		gpgme_data_printf(dh, "%02x", bytes[i]);
}

static void gpgme_data_print_string(gpgme_data_t dh, const char *str)
{
	gpgme_data_print_bytes(dh, (const unsigned char *) str, strlen(str));
}

int main(int argc, char *argv[])
{
	gpgme_check_version(NULL);

	/* If booted from a live-CD, the kernel's entropy pool could
	 * theoretically be very poor. Let's ask the user for some
	 * randomness. */
	printf("Please enter a random string of letters/numbers/etc. from the keyboard. You\n");
	printf("do _NOT_ have to remember or write down this string. It is used purely as a\n");
	printf("means to improve the quality of the entropy pool (in case you booted from a\n");
	printf("live-CD, for example).\n");
	printf("\n");

	char *input = getpass("Randomness: ");

	unsigned char input_sha512[64];
	SHA512((unsigned char *) input, strlen(input), input_sha512);
	memset(input, 0, strlen(input));

	RAND_add(input_sha512, sizeof(input_sha512), 0);
	memset(input_sha512, 0, sizeof(input_sha512));

	EC_KEY *key;
	key = EC_KEY_new_by_curve_name(NID_secp256k1);
	if (!key)
		die("EC_KEY_new_by_curve_name() returned error");

	if (!EC_KEY_generate_key(key))
		die("EC_KEY_generate_key() returned error");

	int private_size = i2d_ECPrivateKey(key, NULL);
	if (private_size <= 0)
		die("i2d_ECPrivateKey() returned zero or negative");

	unsigned char private_key[private_size];
	unsigned char *private_key_begin = &private_key[0];
	if (i2d_ECPrivateKey(key, &private_key_begin) != private_size)
		die("i2d_ECPrivateKey() returned the wrong size");

	int public_size = i2o_ECPublicKey(key, NULL);
	if (public_size <= 0)
		die("i2o_ECPublicKey() returned zero or negative");

	unsigned char public_key[public_size];
	unsigned char *public_key_begin = &public_key[0];
	if (i2o_ECPublicKey(key, &public_key_begin) != public_size)
		die("i2o_ECPublicKey() returned the wrong size");

	/* Free keypair, since we're not using them anymore */
	EC_KEY_free(key);

	unsigned char hash1[32];
	SHA256(public_key, public_size, hash1);

	unsigned char hash2[20];
	RIPEMD160(hash1, sizeof(hash1), hash2);

	std::vector<unsigned char> vch(1, 0);
	vch.insert(vch.end(), &hash2[0], &hash2[20]);

	/* Add 4-byte hash check to the end */
	unsigned char hash3[32];
	SHA256(&vch[0], vch.size(), hash3);

	unsigned char hash4[32];
	SHA256(&hash3[0], sizeof(hash3), hash4);

	vch.insert(vch.end(), &hash4[0], &hash4[4]);

	std::string addr = base58_encode(vch);

	/* Public key */
	std::string pub;
	for (int i = 0; i < public_size; ++i) {
		char *str;
		if (asprintf(&str, "%02x", public_key[i]) == -1)
			die("asprintf() returned error");
		pub += str;
		free(str);
	}

	/* Set up GPGME context */
	gpgme_ctx_t ctx;
	{
		gpgme_error_t ret = gpgme_new(&ctx);
		if (gpgme_err_code(ret) != GPG_ERR_NO_ERROR)
			die("gpgme_new() returned error");
	}

	{
		gpgme_error_t ret = gpgme_set_protocol(ctx,
			GPGME_PROTOCOL_OpenPGP);
		if (gpgme_err_code(ret) != GPG_ERR_NO_ERROR)
			die("gpgme_set_procotol() returned error");
	}

	gpgme_set_armor(ctx, 1);
	gpgme_set_include_certs(ctx, 0);

	gpgme_set_passphrase_cb(ctx, &read_passphrase, NULL);

	gpgme_data_t plaintext;
	{
		gpgme_error_t ret = gpgme_data_new(&plaintext);
		if (gpgme_err_code(ret) != GPG_ERR_NO_ERROR)
			die("gpgme_data_new_from_mem() returned error");
	}

	gpgme_data_printf(plaintext, "VERSION=3\n");
	gpgme_data_printf(plaintext, "format=bytevalue\n");
	gpgme_data_printf(plaintext, "database=main\n");
	gpgme_data_printf(plaintext, "type=btree\n");
	gpgme_data_printf(plaintext, "db_pagesize=4096\n");
	gpgme_data_printf(plaintext, "HEADER=END\n");
	gpgme_data_printf(plaintext, " ");
	gpgme_data_print_string(plaintext, "key");
	gpgme_data_print_bytes(plaintext, public_key, public_size);
	gpgme_data_printf(plaintext, "\n");
	gpgme_data_printf(plaintext, " ");
	gpgme_data_print_bytes(plaintext, private_key, private_size);
	gpgme_data_printf(plaintext, "\n");
	gpgme_data_printf(plaintext, "DATA=END\n");
	gpgme_data_seek(plaintext, 0, SEEK_SET);

	char *filename;
	if (asprintf(&filename, "%s.txt", addr.c_str()) == -1)
		die("asprintf() returned error");

	FILE *fp = fopen(filename, "w");
	if (!fp)
		die("fopen() returned error");

	free(filename);

	gpgme_data_t ciphertext;
	{
		gpgme_error_t ret = gpgme_data_new_from_stream(&ciphertext, fp);
		if (gpgme_err_code(ret) != GPG_ERR_NO_ERROR)
			die("gpgme_data_new_from_stream() returned error");
	}

	{
		gpgme_error_t ret = gpgme_op_encrypt(ctx, NULL,
			(gpgme_encrypt_flags_t) 0, plaintext, ciphertext);
		if (gpgme_err_code(ret) != GPG_ERR_NO_ERROR)
			die("gpgme_op_encrypt() returned error");
	}

	if (fflush(fp) != 0)
		die("fflush() returned error");

	if (fclose(fp) != 0)
		die("fclose() returned error");

	printf("%s\n", addr.c_str());
	return 0;
}
