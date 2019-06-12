#include <stdio.h>
#include <stdlib.h>
#include <openssl/evp.h>
#include <string.h>
#include <openssl/bn.h>
#include <openssl/aes.h>
#include <openssl/pem.h>
#include <openssl/pkcs7.h>

#pragma comment (lib,"ws2_32.lib")
#pragma comment (lib,"crypt32")



FILE _iob[] = { *stdin, *stdout, *stderr };
extern "C" FILE * __cdecl __iob_func(void) { return _iob; }

static int _read_from_file(char *filename, unsigned char **data, unsigned int *len)
{
	if (data == NULL || len == NULL)
		return 0;

	FILE *fp = fopen(filename, "rb");
	if (fp == NULL)
		return 0;

	fseek(fp, 0, SEEK_END);
	*len = (unsigned int)ftell(fp);
	fseek(fp, 0, SEEK_SET);

	*data = (unsigned char *)malloc(*len);

	fread(*data, 1, *len, fp);
	fclose(fp);

	return 1;
}

static int _write_to_file(char *filename, unsigned char *data, unsigned int len)
{
	if (data == NULL)
		return 0;

	FILE *fp = fopen(filename, "wb");
	if (fp == NULL)
		return 0;

	fwrite(data, 1, len, fp);

	fclose(fp);

	return 1;
}

void generate_RSA_key_pairs(const int npubk) {
	//generate npubk RSA key pairs and store each in a file for further use

	EVP_PKEY_CTX* kctx;
	
	EVP_PKEY** keypair_array = (EVP_PKEY**)malloc(sizeof(EVP_PKEY*) * npubk);

	for (int i = 0; i < npubk; i++) {
		keypair_array[i] = EVP_PKEY_new();
	}


	if (!(kctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL)))
		printf("Eroare init ctx!\n");

	if (!EVP_PKEY_keygen_init(kctx))
		printf("Eroare keygen init!\n");


	if (!EVP_PKEY_CTX_set_rsa_keygen_bits(kctx, 2048))
		printf("eroare la lungime key!\n");

	
	///DE MODIFICAT CONFORM ==npubk==
	if (!EVP_PKEY_keygen(kctx, &(keypair_array[0])))
		printf("eroare generare pereche 0!\n");

	if (!EVP_PKEY_keygen(kctx, &(keypair_array[1])))
		printf("eroare generare pereche 1!\n");

	if (!EVP_PKEY_keygen(kctx, &(keypair_array[2])))
		printf("eroare generare pereche 2!\n");
	
	FILE* fp_pub_usr1 = fopen("1.pub", "wb");
	FILE* fp_pub_usr2 = fopen("2.pub", "wb");
	FILE* fp_pub_usr3 = fopen("3.pub", "wb");

	FILE* fp_prv_usr1 = fopen("1.prv", "wb");
	FILE* fp_prv_usr2 = fopen("2.prv", "wb");
	FILE* fp_prv_usr3 = fopen("3.prv", "wb");



	PEM_write_PUBKEY(fp_pub_usr1, keypair_array[0]);
	PEM_write_PUBKEY(fp_pub_usr2, keypair_array[1]);
	PEM_write_PUBKEY(fp_pub_usr3, keypair_array[2]);

	PEM_write_PKCS8PrivateKey(fp_prv_usr1, keypair_array[0], EVP_aes_128_cbc(), NULL, 0, NULL, (void*)"user1");
	PEM_write_PKCS8PrivateKey(fp_prv_usr2, keypair_array[1], EVP_aes_128_cbc(), NULL, 0, NULL, (void*)"user2");
	PEM_write_PKCS8PrivateKey(fp_prv_usr3, keypair_array[2], EVP_aes_128_cbc(), NULL, 0, NULL, (void*)"user3");

	for (int i = 0; i < 3; i++) {
		free(keypair_array[i]);
	}


	EVP_PKEY_CTX_free(kctx);
	free(keypair_array);
	fclose(fp_pub_usr1);
	fclose(fp_pub_usr2);
	fclose(fp_pub_usr3);
	fclose(fp_prv_usr1);
	fclose(fp_prv_usr2);
	fclose(fp_prv_usr3);
}

void read_RSA_key_pairs(EVP_PKEY**& keypair_array, const int npubk) {


	keypair_array = (EVP_PKEY**)malloc(sizeof(EVP_PKEY*) * npubk);

	for (int i = 0; i < npubk; i++) {
		keypair_array[i] = EVP_PKEY_new();
	}



	///DE MODIFICAT CONFORM ==npubk==
	FILE* fp_pub_usr1 = fopen("1.pub", "rb");
	FILE* fp_pub_usr2 = fopen("2.pub", "rb");
	FILE* fp_pub_usr3 = fopen("3.pub", "rb");

	FILE* fp_prv_usr1 = fopen("1.prv", "rb");
	FILE* fp_prv_usr2 = fopen("2.prv", "rb");
	FILE* fp_prv_usr3 = fopen("3.prv", "rb");

	PEM_read_PUBKEY(fp_pub_usr1, &keypair_array[0], NULL, NULL);
	PEM_read_PUBKEY(fp_pub_usr2, &keypair_array[1], NULL, NULL);
	PEM_read_PUBKEY(fp_pub_usr3, &keypair_array[2], NULL, NULL);

	PEM_read_PrivateKey(fp_prv_usr1, &keypair_array[0], NULL, (void*)"usr1");
	PEM_read_PrivateKey(fp_prv_usr2, &keypair_array[1], NULL, (void*)"usr2");
	PEM_read_PrivateKey(fp_prv_usr3, &keypair_array[2], NULL, (void*)"usr3");


	fclose(fp_pub_usr1);
	fclose(fp_pub_usr2);
	fclose(fp_pub_usr3);
	fclose(fp_prv_usr1);
	fclose(fp_prv_usr2);
	fclose(fp_prv_usr3);
}

int envelope_seal(EVP_PKEY **pub_key, unsigned char *plaintext, int plaintext_len,
	unsigned char **&encrypted_key, int *encrypted_key_len, unsigned char *&iv,
	unsigned char *&ciphertext, const int npubk)
{
	EVP_CIPHER_CTX *ctx;

	int ciphertext_len;

	int len;


	encrypted_key = (unsigned char**)malloc(sizeof(unsigned char*) * npubk);
	for (int i = 0; i < npubk; i++)
		encrypted_key[i] = (unsigned char*)malloc(sizeof(unsigned char) * EVP_PKEY_size(pub_key[i]));

	
	iv = (unsigned char*)malloc(EVP_MAX_IV_LENGTH);
	int ivLength = EVP_MAX_IV_LENGTH;
	ciphertext = (unsigned char*)malloc(plaintext_len + EVP_MAX_IV_LENGTH);

	/* Create and initialise the context */
	ctx = EVP_CIPHER_CTX_new();

	/* Initialise the envelope seal operation. This operation generates
	 * a key for the provided cipher, and then encrypts that key npubk
	 * times (one for each public key provided in the pub_key array). In
	 * this example the array size is just one. This operation also
	 * generates an IV and places it in iv. */
	if (npubk != EVP_SealInit(ctx, EVP_aes_256_cbc(), encrypted_key, encrypted_key_len, iv, pub_key, npubk))
		printf("Eroare SealInit!\n");

	/* Provide the message to be encrypted, and obtain the encrypted output.
	 * EVP_SealUpdate can be called multiple times if necessary
	 */
	if (1 != EVP_SealUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
		printf("Eroare SealUpdate!\n");
	ciphertext_len = len;

	/* Finalise the encryption. Further ciphertext bytes may be written at
	 * this stage.
	 */
	if (1 != EVP_SealFinal(ctx, ciphertext + len, &len)) 
		printf("Eroare SealFinal!\n");
	
	ciphertext_len += len;

	/* Clean up */
	EVP_CIPHER_CTX_free(ctx);
	


	return ciphertext_len;
}



int envelope_open(EVP_PKEY *priv_key, unsigned char *ciphertext, int ciphertext_len,
	unsigned char *encrypted_key, int encrypted_key_len, unsigned char *iv,
	unsigned char *&plaintext)
{
	//decrypt the RecipientInfo of some recipient providing his private key
	//can be called multiple times with different priv_keys and encrypted_keys to open for multiple recipients
	//ciphertext and iv should stay the same, as it's the AES encryption of input file(plaintext)

	EVP_CIPHER_CTX *ctx;

	int len;

	int plaintext_len;



	plaintext = (unsigned char*)malloc(ciphertext_len + EVP_MAX_IV_LENGTH);


	/* Create and initialise the context */
	ctx = EVP_CIPHER_CTX_new();

	/* Initialise the decryption operation. The asymmetric private key is
	 * provided and priv_key, whilst the encrypted session key is held in
	 * encrypted_key */
	if (1 != EVP_OpenInit(ctx, EVP_aes_256_cbc(), encrypted_key, encrypted_key_len, iv, priv_key))
		printf("Eroare la OpenInit!\n");

	/* Provide the message to be decrypted, and obtain the plaintext output.
	 * EVP_OpenUpdate can be called multiple times if necessary
	 */
	if (1 != EVP_OpenUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
		printf("Eroare la OpenUpdate!\n");
	plaintext_len = len;

	/* Finalise the decryption. Further plaintext bytes may be written at
	 * this stage.
	 */
	if (1 != EVP_OpenFinal(ctx, plaintext + len, &len)) printf("Eroare la OpenFinal!\n");
	plaintext_len += len;

	/* Clean up */
	EVP_CIPHER_CTX_free(ctx);

	return plaintext_len;
}

void open_Envelope_knowing_some_user_priv_key(unsigned char* ciphertext, unsigned int len_ciphertext, unsigned char** encrypted_symmetric_key, int* len_enc_symm_key, unsigned char* iv) {

	EVP_PKEY* PRIV_KEY = EVP_PKEY_new();
	FILE* fp_prv_usr1 = fopen("1.prv", "rb");
	PEM_read_PrivateKey(fp_prv_usr1, &PRIV_KEY, NULL, (void*)"user1");

	_write_to_file((char*)"out.envp", ciphertext, len_ciphertext);

	unsigned char* plaintext = (unsigned char*)malloc(len_ciphertext + EVP_MAX_IV_LENGTH);
	int len_plaintext = 0;
	len_plaintext = envelope_open(PRIV_KEY, ciphertext, len_ciphertext, encrypted_symmetric_key[0], len_enc_symm_key[0], iv, plaintext);

	_write_to_file((char*) "out.txt", plaintext, len_plaintext);

	fclose(fp_prv_usr1);
	EVP_PKEY_free(PRIV_KEY);
	free(plaintext);
}


X509* ReadCertificateFromFile(const char* fileName)
{
	FILE* fp = fopen(fileName, "rb");

	if (fp == NULL)
	{
		printf("Error loading certificate file ! \n");
		return NULL;
	}
	X509* certificate = X509_new();
	if (d2i_X509_fp(fp, &certificate) == NULL)
	{
		printf("Certificatul de intrare trebuie sa fie conform codarii BER ! \n");
		return nullptr;
	}
	fclose(fp);

	return certificate;
}


EVP_PKEY*  getPubKey(char* cert_filename) 
{
	//gets the public key from a X.509 cert
	FILE* fp = fopen(cert_filename, "rb");

	if (fp == NULL)
	{
		printf("Error loading certificate file ! \n");
		return NULL;
	}
	X509* cert = X509_new();
	d2i_X509_fp(fp, &cert);
	fclose(fp);

	EVP_PKEY * pubkey = X509_get_pubkey(cert);

	X509_free(cert);
	return pubkey;
}



void main(int argc, char* argv[]) {
	//generate_RSA_key_pairs(npubk); //from first version(using only keys, not certificates)
	//read_RSA_key_pairs(key_pairs,npubk); //from first version(using only keys, not certificates)
	//open_Envelope_knowing_some_user_priv_key(ciphertext, len_ciphertext, encrypted_symmetric_key, len_enc_symm_key, iv); //from first version(using only keys, not certificates)
	
	//****************************************************************************************************************************************************************************\\
																	///Using certificates

	///IMPORTANT:
	//Note: Before passing the certs to the program, one needs to remove the header and footer(e.g.:"-----BEGIN CERTIFICATE----")
	//		and decode them from base64 to hex

	///USAGE:
	/*

	 * Envelope Seal: -seal file.txt N=no_of_recipients file.incert1 file.incert2 ... file.incertN envelope.out
	 * Envelope Open: -open envelope.out key.prv file.incert decrypted.txt

	 */




	if (!strcmp(argv[1], "-seal")) {

		unsigned char* plaintext = NULL;
		unsigned int len_plaintext = 0;
		_read_from_file(argv[2], &plaintext, &len_plaintext); //get the plaintext
		
		int npubk = atoi(argv[3]); //get the number of recipients
		EVP_PKEY** key_pairs = (EVP_PKEY**)malloc(sizeof(EVP_PKEY*) * npubk); //needed for sealing the envelope
		X509** certs = (X509**)malloc(sizeof(X509*) * npubk); //required by PKCS#7 envelope structure


		unsigned char** encrypted_symmetric_keys = NULL;
		int* len_enc_symm_keys = (int*)malloc(sizeof(int) * npubk);


		for (int i = 0; i < npubk; i++) {//alloc and extract the public keys from certs
			certs[i] = ReadCertificateFromFile(argv[i + 4]);
			key_pairs[i] = EVP_PKEY_new();
			key_pairs[i] = getPubKey(argv[i + 4]);
		}

		//basic allocations for envelope_seal
		encrypted_symmetric_keys = (unsigned char**)malloc(EVP_PKEY_size(*key_pairs) * npubk);
		len_enc_symm_keys = (int*)malloc(sizeof(int) * npubk);
		for (int j = 0; j < npubk; j++) {
			encrypted_symmetric_keys[j] = (unsigned char*)malloc(EVP_PKEY_size(key_pairs[j]));
		}
		unsigned char* iv = (unsigned char*)malloc(AES_BLOCK_SIZE); //iv size for AES is always the same as the block size
		unsigned char *ciphertext = (unsigned char*)malloc(AES_BLOCK_SIZE);
		unsigned int len_ciphertext = 0;

		//envelope_seal can be viewed as a black box as long as the right parameters are provided
		len_ciphertext = envelope_seal(key_pairs, plaintext, len_plaintext, encrypted_symmetric_keys, len_enc_symm_keys, iv, ciphertext, npubk);
		/* the ciphertext and len_ciphertext returned is the plaintext encrypted with the BLOCK CIPHER(AES_256_CBC in this case)
		 * the symmetric key encrypted with each RSA public key get stored in encrypted_symmetric_keys
		 * the len_enc_symm_keys specifies the length of the symmetric key encrypted with every asymmetric key(RSA public in this case)*/

		_write_to_file((char*)"file.iv", iv, AES_BLOCK_SIZE);

		PKCS7_ENVELOPE* enveloped_data = PKCS7_ENVELOPE_new();

		//version
		enveloped_data->version->data = 0;

		//recipientinfos 
		PKCS7_RECIP_INFO** recipientInfos = (PKCS7_RECIP_INFO**)malloc(sizeof(PKCS7_RECIP_INFO) * npubk);
		for (int k = 0; k < npubk; k++) {
			recipientInfos[k] = PKCS7_RECIP_INFO_new();
			long ver = npubk;
			ASN1_INTEGER_set(recipientInfos[k]->version, ver);

			recipientInfos[k]->cert = certs[k];

			recipientInfos[k]->issuer_and_serial->issuer = X509_get_issuer_name(certs[k]);
			recipientInfos[k]->issuer_and_serial->serial = X509_get_serialNumber(certs[k]);

			ASN1_BIT_STRING * encryptedkey = ASN1_BIT_STRING_new();
			ASN1_BIT_STRING_set(encryptedkey, encrypted_symmetric_keys[k], len_enc_symm_keys[k]);
			recipientInfos[k]->enc_key = encryptedkey;

			recipientInfos[k]->key_enc_algor->algorithm = OBJ_nid2obj(NID_rsaEncryption);

			sk_PKCS7_RECIP_INFO_push(enveloped_data->recipientinfo, recipientInfos[k]);
		}

		//enc_data
		enveloped_data->enc_data = PKCS7_ENC_CONTENT_new();
		enveloped_data->enc_data->algorithm->algorithm = OBJ_nid2obj(NID_aes_256_cbc);
		enveloped_data->enc_data->cipher = EVP_aes_256_cbc();
		enveloped_data->enc_data->content_type = OBJ_nid2obj(NID_textNotice);
		ASN1_OCTET_STRING* octString = ASN1_OCTET_STRING_new();
		ASN1_OCTET_STRING_set(octString, ciphertext, len_ciphertext);
		enveloped_data->enc_data->enc_data = octString;


		//write envelope to file
		unsigned char* tofile = NULL;
		unsigned int len_env = 0;


		PKCS7* PKCS7 = PKCS7_new();
		PKCS7->type = OBJ_nid2obj(NID_pkcs7_enveloped);

		PKCS7->d.enveloped = enveloped_data;
		len_env = i2d_PKCS7(PKCS7, &tofile);
		_write_to_file(argv[argc - 1], tofile, len_env);


	}
	else {

		
		unsigned char* envelope = NULL;
		unsigned int len_envelope = 0;
		_read_from_file(argv[2], &envelope, &len_envelope);

		PKCS7* PKCS7 = PKCS7_new();
		PKCS7 = d2i_PKCS7(&PKCS7, (const unsigned char**)&envelope, len_envelope);

		PKCS7_ENVELOPE* Envelope = PKCS7_ENVELOPE_new();
		Envelope = PKCS7->d.enveloped;


		unsigned char* ciphertext = NULL;
		unsigned int len_ciphertext = 0;
		len_ciphertext = Envelope->enc_data->enc_data->length;
		ciphertext = (unsigned char*)malloc(len_ciphertext);
		memcpy(ciphertext, Envelope->enc_data->enc_data->data, len_ciphertext);

		unsigned char* iv = NULL;
		unsigned int len_iv = 0;
		_read_from_file((char*)"file.iv", &iv, &len_iv);


		//read prv key
		EVP_PKEY* priv_key = EVP_PKEY_new();
		FILE* fp_prv = fopen(argv[3], "rb");
		priv_key = PEM_read_PrivateKey(fp_prv, &priv_key, NULL, (void*)"pascu");//provide the password for private key


		PKCS7_RECIP_INFO* repinfos = PKCS7_RECIP_INFO_new();

		X509* my_cert;
		my_cert = ReadCertificateFromFile(argv[4]);

		X509_NAME* my_issuer = X509_NAME_new();
		my_issuer = X509_get_issuer_name(my_cert);

		ASN1_INTEGER* my_sn_asn1 = ASN1_INTEGER_new();
		my_sn_asn1 = X509_get_serialNumber(my_cert);

		repinfos = sk_PKCS7_RECIP_INFO_pop(Envelope->recipientinfo);

		int len_stack = atoi(argv[3]);

		for (int i = 0; i < len_stack; i++) {
			if (!X509_NAME_cmp(my_issuer, repinfos->issuer_and_serial->issuer)) {
				if (!ASN1_INTEGER_cmp(my_sn_asn1, repinfos->issuer_and_serial->serial))
					break;
			}
			repinfos = sk_PKCS7_RECIP_INFO_pop(Envelope->recipientinfo);
		}

		unsigned char* encrypted_key = (unsigned char*)malloc(repinfos->enc_key->length);
		int encrypted_key_len = repinfos->enc_key->length;
		memcpy(encrypted_key, repinfos->enc_key->data, encrypted_key_len);

		unsigned char* plaintext = (unsigned char*)malloc(EVP_PKEY_size(priv_key));
		unsigned int len_plaintext = 0;

		len_plaintext = envelope_open(priv_key, ciphertext, len_ciphertext,
			encrypted_key, encrypted_key_len, iv, plaintext);

		_write_to_file(argv[argc - 1], plaintext, len_plaintext);

	}



	
	
	

	printf("\n\nFINAL!\n");
	getchar();
}