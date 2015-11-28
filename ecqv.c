/*
 * ECQV Public/Private Key Pair Generator Command Line Tool (ecqv-keygen)
 * Copyright (c) 2015 Jani Pellikka <jpellikk@users.noreply.github.com>
 */
#include "ecqv.h"

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

#include <openssl/bn.h>
#include <openssl/bio.h>
#include <openssl/ecdh.h>
#include <openssl/objects.h>
#include <openssl/rand.h>
#include <openssl/ec.h>
#include <openssl/pem.h>
#include <openssl/evp.h>

struct ecqv_gen_t {
	BN_CTX *ctx;
	BIGNUM *order;
	EC_GROUP const *group;
	EC_KEY *ca_key;
	EC_KEY *cl_key;
	EC_POINT *Pu;
	BIGNUM *r;
	BIGNUM *a;
	BIGNUM *k;
	BIGNUM *e;
	EVP_MD const *hash;
	FILE *in;
	FILE *out;
	FILE *key;
	FILE *log;
};

#define ECQV_HASH EVP_sha1()

static void ecqv_log_bn(struct ecqv_gen_t *gen, const char *label, const BIGNUM *bn)
{
	char *str;

	if (!gen->log) {
		return;
	}

	str = BN_bn2hex(bn);

	if (!str) {
		fprintf(stderr, "Log: error converting bignum to hex.\n");
		return;
	}

	fprintf(gen->log, "BIGNUM (%s): %s\n", label, str);
	fflush(gen->log);
	OPENSSL_free(str);
}

static void ecqv_log_point(struct ecqv_gen_t *gen, const char *label, const EC_POINT *point)
{
	char *str;

	if (!gen->log) {
		return;
	}

	str = EC_POINT_point2hex(gen->group, point,
	                         POINT_CONVERSION_UNCOMPRESSED, gen->ctx);

	if (!str) {
		fprintf(stderr, "Log: error converting point to hex.\n");
		return;
	}

	fprintf(gen->log, "EC_POINT (%s): %s\n", label, str);
	fflush(gen->log);
	OPENSSL_free(str);
}

static void ecqv_log_key(struct ecqv_gen_t *gen, const char *label, const EC_KEY *key)
{
	if (!gen->log) {
		return;
	}

	fprintf(gen->log, "EC_KEY (%s):\n", label);

	if (EC_KEY_print_fp(gen->log, key, 3) == 0) {
		fprintf(stderr, "Log: error printing EC key.\n");
		return;
	}

	fflush(gen->log);
}

static FILE *ecqv_open_file(const char *name, const char *mode)
{
	FILE *file = fopen(name, mode);

	if (!file) {
		fprintf(stderr, "Error opening file '%s': %s.\n",
		        name, strerror(errno));
		return NULL;
	}

	return file;
}

static EC_KEY *ecqv_read_private_key(FILE *file)
{
	EVP_PKEY *pk = PEM_read_PrivateKey(file, NULL, NULL, NULL);
	EC_KEY *key;

	if (!pk) {
		fprintf(stderr, "Error reading private key file.\n");
		return NULL;
	}

	key = EVP_PKEY_get1_EC_KEY(pk);

	if (!key) {
		fprintf(stderr, "Error loading EC private key.\n");
	}

	EVP_PKEY_free(pk);
	return key;
}

static int ecqv_write_private_key(struct ecqv_gen_t *ecqv_gen)
{
	EVP_PKEY *evp_pkey;
	EC_KEY *ec_key;
	evp_pkey = EVP_PKEY_new();

	if (!evp_pkey) {
		return -1;
	}

	ec_key = EC_KEY_dup(ecqv_gen->cl_key);

	if (!ec_key) {
		return -1;
	}

	if (EVP_PKEY_assign_EC_KEY(evp_pkey, ec_key) == 0) {
		return -1;
	}

	if (PEM_write_PrivateKey(ecqv_gen->out, evp_pkey,
	                         NULL, NULL, 0, 0, NULL) == 0) {
		EVP_PKEY_free(evp_pkey);
		return -1;
	}

	EVP_PKEY_free(evp_pkey);
	return 0;
}

static int ecqv_write_impl_cert(struct ecqv_gen_t *ecqv_gen)
{
	BIO *b64 = NULL, *bio = NULL;
	unsigned char *buf = NULL;
	size_t buf_len;
	buf_len = EC_POINT_point2oct(ecqv_gen->group, ecqv_gen->Pu,
	                             POINT_CONVERSION_UNCOMPRESSED,
	                             NULL, 0, ecqv_gen->ctx);

	if (buf_len == 0) {
		goto ERROR;
	}

	buf = OPENSSL_malloc(buf_len);

	if (!buf) {
		goto ERROR;
	}

	buf_len = EC_POINT_point2oct(ecqv_gen->group, ecqv_gen->Pu,
	                             POINT_CONVERSION_UNCOMPRESSED,
	                             buf, buf_len, ecqv_gen->ctx);

	if (buf_len == 0) {
		goto ERROR;
	}

	b64 = BIO_new(BIO_f_base64());
	BIO_set_flags(b64, 0);
	bio = BIO_new_fp(ecqv_gen->out, BIO_NOCLOSE);
	bio = BIO_push(b64, bio);
	fprintf(ecqv_gen->out, "-----BEGIN IMPLICIT CERTIFICATE-----\n");
	BIO_write(bio, buf, buf_len);
	(void)BIO_flush(bio);
	fprintf(ecqv_gen->out, "-----END IMPLICIT CERTIFICATE-----\n");
	OPENSSL_free(buf);
	BIO_free_all(bio);
	return 0;
ERROR:

	if (buf) {
		OPENSSL_free(buf);
	}

	if (bio) {
		BIO_free_all(bio);
	}

	return -1;
}

static int ecqv_create_bn_from_id(struct ecqv_gen_t *ecqv_gen)
{
	EVP_MD_CTX *md_ctx = NULL;
	unsigned char *buf = NULL;
	unsigned char md_value[EVP_MAX_MD_SIZE];
	unsigned int md_len;
	long int file_len;
	size_t buf_len;

	if (!ecqv_gen->e) {
		ecqv_gen->e = BN_new();
	}

	if (!ecqv_gen->e) {
		return -1;
	}

	md_ctx = EVP_MD_CTX_create();

	if (!md_ctx) {
		return -1;
	}

	if (EVP_DigestInit_ex(md_ctx, ecqv_gen->hash, 0) == 0) {
		goto ERROR;
	}

	buf_len = EC_POINT_point2oct(ecqv_gen->group, ecqv_gen->Pu,
	                             POINT_CONVERSION_UNCOMPRESSED,
	                             NULL, 0, ecqv_gen->ctx);

	if (buf_len == 0) {
		goto ERROR;
	}

	buf = OPENSSL_malloc(buf_len);

	if (!buf) {
		goto ERROR;
	}

	if (EC_POINT_point2oct(ecqv_gen->group, ecqv_gen->Pu,
	                       POINT_CONVERSION_UNCOMPRESSED,
	                       buf, buf_len, ecqv_gen->ctx) == 0) {
		goto ERROR;
	}

	if (EVP_DigestUpdate(md_ctx, buf, buf_len) == 0) {
		goto ERROR;
	}

	if (fseek(ecqv_gen->in, 0L, SEEK_END) == -1) {
		goto ERROR;
	}

	file_len = ftell(ecqv_gen->in);
	rewind(ecqv_gen->in);

	if (file_len > 0) {
		unsigned char *tmp_buf;
		tmp_buf = realloc(buf, file_len);

		if (!tmp_buf) {
			goto ERROR;
		}

		buf = tmp_buf;
		file_len = fread(buf, file_len, 1, ecqv_gen->in);
		EVP_DigestUpdate(md_ctx, buf, file_len);
	} else {
		fprintf(stderr, "No identity data supplied.\n");
		goto ERROR;
	}

	if (EVP_DigestFinal_ex(md_ctx, md_value, &md_len) == 0) {
		goto ERROR;
	}

	if (!BN_bin2bn(md_value, md_len, ecqv_gen->e)) {
		goto ERROR;
	}

	ecqv_log_bn(ecqv_gen, "e", ecqv_gen->e);
	EVP_MD_CTX_destroy(md_ctx);
	OPENSSL_free(buf);
	return 0;
ERROR:

	if (md_ctx) {
		EVP_MD_CTX_destroy(md_ctx);
	}

	if (buf) {
		OPENSSL_free(buf);
	}

	return -1;
}

static int ecqv_public_reconstr_data(struct ecqv_gen_t *ecqv_gen)
{
	EC_POINT *p_alphaG = NULL, *p_kG = NULL;

	if (!ecqv_gen->a) {
		ecqv_gen->a = BN_new();
	}

	if (!ecqv_gen->a) {
		return -1;
	}

	if (BN_rand_range(ecqv_gen->a, ecqv_gen->order) == 0) {
		return -1;
	}

	ecqv_log_bn(ecqv_gen, "alpha", ecqv_gen->a);
	p_alphaG = EC_POINT_new(ecqv_gen->group);

	if (!p_alphaG) {
		goto ERROR;
	}

	if (EC_POINT_mul(ecqv_gen->group, p_alphaG, ecqv_gen->a,
	                 NULL, NULL, NULL) == 0) {
		goto ERROR;
	}

	ecqv_log_point(ecqv_gen, "alphaG", p_alphaG);

	if (!ecqv_gen->k) {
		ecqv_gen->k = BN_new();
	}

	if (!ecqv_gen->k) {
		goto ERROR;
	}

	if (BN_rand_range(ecqv_gen->k, ecqv_gen->order) == 0) {
		goto ERROR;
	}

	ecqv_log_bn(ecqv_gen, "k", ecqv_gen->k);
	p_kG = EC_POINT_new(ecqv_gen->group);

	if (!p_kG) {
		goto ERROR;
	}

	if (EC_POINT_mul(ecqv_gen->group, p_kG, ecqv_gen->k,
	                 NULL, NULL, NULL) == 0) {
		goto ERROR;
	}

	ecqv_log_point(ecqv_gen, "kG", p_kG);

	if (!ecqv_gen->Pu) {
		ecqv_gen->Pu = EC_POINT_new(ecqv_gen->group);
	}

	if (EC_POINT_add(ecqv_gen->group, ecqv_gen->Pu,
	                 p_alphaG, p_kG, NULL) == 0) {
		goto ERROR;
	}

	ecqv_log_point(ecqv_gen, "Pu", ecqv_gen->Pu);
	EC_POINT_free(p_alphaG);
	EC_POINT_free(p_kG);
	return 0;
ERROR:

	if (p_alphaG) {
		EC_POINT_free(p_alphaG);
	}

	if (p_kG) {
		EC_POINT_free(p_kG);
	}

	return -1;
}

static int ecqv_priv_reconstr_data(struct ecqv_gen_t *ecqv_gen)
{
	const BIGNUM *c;
	BIGNUM *ek = BN_new();

	if (!ek) {
		return -1;
	}

	if (BN_mul(ek, ecqv_gen->e, ecqv_gen->k, ecqv_gen->ctx) == 0) {
		goto ERROR;
	}

	ecqv_log_bn(ecqv_gen, "ek", ek);

	if (!ecqv_gen->r) {
		ecqv_gen->r = BN_new();
	}

	if (!ecqv_gen->r) {
		goto ERROR;
	}

	c = EC_KEY_get0_private_key(ecqv_gen->ca_key);

	if (!c) {
		goto ERROR;
	}

	if (BN_mod_add(ecqv_gen->r, ek, c, ecqv_gen->order, ecqv_gen->ctx) == 0) {
		goto ERROR;
	}

	ecqv_log_bn(ecqv_gen, "s", ecqv_gen->r);
	BN_free(ek);
	return 0;
ERROR:

	if (ek) {
		BN_free(ek);
	}

	return -1;
}

static int ecqv_create_keypair(struct ecqv_gen_t *ecqv_gen)
{
	EC_POINT *p_efii = NULL, *p_Qa = NULL;
	BIGNUM *ealpha = NULL, *a = NULL;
	const EC_POINT *p_Qc = NULL;
	ealpha = BN_new();

	if (!ealpha || BN_mul(ealpha, ecqv_gen->e,
	                      ecqv_gen->a, ecqv_gen->ctx) == 0) {
		goto ERROR;
	}

	ecqv_log_bn(ecqv_gen, "ealpha", ealpha);
	a = BN_new();

	if (!a) {
		goto ERROR;
	}

	if (BN_mod_add(a, ealpha, ecqv_gen->r,
	               ecqv_gen->order, ecqv_gen->ctx) == 0) {
		goto ERROR;
	}

	ecqv_log_bn(ecqv_gen, "a", a);
	p_efii = EC_POINT_new(ecqv_gen->group);

	if (!p_efii) {
		goto ERROR;
	}

	if (EC_POINT_mul(ecqv_gen->group, p_efii, NULL,
	                 ecqv_gen->Pu, ecqv_gen->e, NULL) == 0) {
		goto ERROR;
	}

	ecqv_log_point(ecqv_gen, "efii", p_efii);
	p_Qa = EC_POINT_new(ecqv_gen->group);

	if (!p_Qa) {
		goto ERROR;
	}

	p_Qc = EC_KEY_get0_public_key(ecqv_gen->ca_key);

	if (!p_Qc) {
		goto ERROR;
	}

	if (EC_POINT_add(ecqv_gen->group, p_Qa, p_efii, p_Qc, 0) == 0) {
		goto ERROR;
	}

	ecqv_log_point(ecqv_gen, "Qa", p_Qa);
	ecqv_gen->cl_key = EC_KEY_new();

	if (!ecqv_gen->cl_key) {
		goto ERROR;
	}

	if (EC_KEY_set_group(ecqv_gen->cl_key, ecqv_gen->group) == 0) {
		goto ERROR;
	}

	if (EC_KEY_set_private_key(ecqv_gen->cl_key, a) == 0) {
		goto ERROR;
	}

	if (EC_KEY_set_public_key(ecqv_gen->cl_key, p_Qa) == 0) {
		goto ERROR;
	}

	ecqv_log_key(ecqv_gen, "CLIENT", ecqv_gen->cl_key);
	EC_POINT_free(p_efii);
	EC_POINT_free(p_Qa);
	BN_free(ealpha);
	BN_free(a);
	return 0;
ERROR:

	if (p_efii) {
		EC_POINT_free(p_efii);
	}

	if (p_Qa) {
		EC_POINT_free(p_Qa);
	}

	if (ealpha) {
		BN_free(ealpha);
	}

	if (a) {
		BN_free(a);
	}

	return -1;
}

static int ecqv_key_generation(struct ecqv_gen_t *ecqv_gen)
{
	if (ecqv_public_reconstr_data(ecqv_gen) == -1) {
		fprintf(stderr, "Creating public reconstruction data (Pu) failed.\n");
		return -1;
	}

	if (ecqv_create_bn_from_id(ecqv_gen) == -1) {
		fprintf(stderr, "Creating bignum from the identity failed.\n");
		return -1;
	}

	if (ecqv_priv_reconstr_data(ecqv_gen) == -1) {
		fprintf(stderr, "Creating private reconstruction data (r) failed.\n");
		return -1;
	}

	if (ecqv_create_keypair(ecqv_gen) == -1) {
		fprintf(stderr, "Creating public/private key pair failed.\n");
		return -1;
	}

	return 0;
}

void ecqv_initialize(void)
{
	CRYPTO_malloc_init();
	OpenSSL_add_all_digests();
}

void ecqv_cleanup(void)
{
	EVP_cleanup();
	CRYPTO_cleanup_all_ex_data();
}

int ecqv_create(struct ecqv_gen_t **ecqv_gen, const struct ecqv_opt_t *opt)
{
	struct ecqv_gen_t *ecqv;
	const EC_POINT *G;

	if (!opt->key) {
		fprintf(stderr, "No CA private key given.\n");
		return -1;
	}

	ecqv = OPENSSL_malloc(sizeof(*ecqv));

	if (!ecqv) {
		return -1;
	}

	memset(ecqv, 0, sizeof(*ecqv));

	if (opt->hash) {
		ecqv->hash = EVP_get_digestbyname(opt->hash);
	} else {
		ecqv->hash = ECQV_HASH;
	}

	if (!ecqv->hash) {
		fprintf(stderr, "Hash '%s' not found.\n", opt->hash);
		goto ERROR;
	}

	ecqv->key = ecqv_open_file(opt->key, "rb");

	if (!ecqv->key) {
		goto ERROR;
	}

	ecqv->ca_key = ecqv_read_private_key(ecqv->key);

	if (!ecqv->ca_key) {
		goto ERROR;
	}

	ecqv->in = (opt->in) ? ecqv_open_file(opt->in, "rb") : stdin;

	if (!ecqv->in) {
		goto ERROR;
	}

	ecqv->log = (opt->log) ? ecqv_open_file(opt->log, "wb") : NULL;

	if (!ecqv->log && opt->log) {
		goto ERROR;
	}

	ecqv->out = (opt->out) ? ecqv_open_file(opt->out, "wb") : stdout;

	if (opt->out) {
		goto ERROR;
	}

	ecqv_log_key(ecqv, "CA", ecqv->ca_key);
	ecqv->ctx = BN_CTX_new();

	if (!ecqv->ctx) {
		goto ERROR;
	}

	ecqv->group = EC_KEY_get0_group(ecqv->ca_key);

	if (!ecqv->group) {
		fprintf(stderr, "Failed to get the group.\n");
		goto ERROR;
	}

	G = EC_GROUP_get0_generator(ecqv->group);

	if (!G) {
		fprintf(stderr, "Failed to get the generator.\n");
		goto ERROR;
	}

	ecqv_log_point(ecqv, "G", G);
	ecqv->order = BN_new();

	if (!ecqv->order) {
		goto ERROR;
	}

	if (EC_GROUP_get_order(ecqv->group, ecqv->order, 0) == 0) {
		fprintf(stderr, "Failed to get the order.\n");
		goto ERROR;
	}

	ecqv_log_bn(ecqv, "order", ecqv->order);
	*ecqv_gen = ecqv;
	return 0;
ERROR:

	if (ecqv) {
		ecqv_free(ecqv);
	}

	return -1;
}

int ecqv_free(struct ecqv_gen_t *ecqv_gen)
{
	if (ecqv_gen->ctx) {
		BN_CTX_free(ecqv_gen->ctx);
	}

	if (ecqv_gen->order) {
		BN_free(ecqv_gen->order);
	}

	if (ecqv_gen->ca_key) {
		EC_KEY_free(ecqv_gen->ca_key);
	}

	if (ecqv_gen->cl_key) {
		EC_KEY_free(ecqv_gen->cl_key);
	}

	if (ecqv_gen->Pu) {
		EC_POINT_free(ecqv_gen->Pu);
	}

	if (ecqv_gen->r) {
		BN_free(ecqv_gen->r);
	}

	if (ecqv_gen->k) {
		BN_free(ecqv_gen->k);
	}

	if (ecqv_gen->a) {
		BN_free(ecqv_gen->a);
	}

	if (ecqv_gen->e) {
		BN_free(ecqv_gen->e);
	}

	if (ecqv_gen->log) {
		fclose(ecqv_gen->log);
	}

	if (ecqv_gen->key) {
		fclose(ecqv_gen->key);
	}

	if (ecqv_gen->in) {
		fclose(ecqv_gen->in);
	}

	if (ecqv_gen->out) {
		fclose(ecqv_gen->out);
	}

	OPENSSL_free(ecqv_gen);
	return 0;
}

int ecqv_generate_keypair(struct ecqv_gen_t *ecqv_gen)
{
	if (ecqv_key_generation(ecqv_gen) == -1) {
		fprintf(stderr, "Generating key pair failed.\n");
		return -1;
	}

	return 0;
}

int ecqv_verify_keypair(struct ecqv_gen_t *ecqv_gen)
{
	if (EC_KEY_check_key(ecqv_gen->cl_key) == 0) {
		fprintf(stderr, "Public key check failed.\n");
		return -1;
	}

	// TODO: verify key as per the ECQV standard
	return 0;
}

int ecqv_export_keypair(struct ecqv_gen_t *ecqv_gen)
{
	if (ecqv_write_private_key(ecqv_gen) == -1) {
		fprintf(stderr, "Exporting key pair failed.\n");
		return -1;
	}

	if (ecqv_write_impl_cert(ecqv_gen) == -1) {
		fprintf(stderr, "Exporting certificate failed.\n");
		return -1;
	}

	return 0;
}
