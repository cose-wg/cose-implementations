#include "cose.h"
#include "configure.h"
#include "cose_int.h"
#include "crypto.h"

#ifdef USE_OPEN_SSL

#include <openssl\evp.h>
#include <openssl\rand.h>


bool AES_CCM_Decrypt(COSE_Encrypt * pcose, int TSize, int LSize, const byte * pbAuthData, int cbAuthData)
{
	EVP_CIPHER_CTX ctx;
	int cbOut;
	byte * rgbOut = NULL;
	size_t NSize = 15 - LSize;
	int outl = 0;
	byte rgbIV[15] = { 0 };
#ifdef USE_CBOR_CONTEXT
	cn_cbor_context * context = &pcose->m_message.m_allocContext;
#endif

	//  Setup the IV/Nonce and put it into the message

	if (pcose->pbIV == NULL) {
	error:
		if (rgbOut != NULL) COSE_FREE(rgbOut, context);
		return false;
	}

	if (pcose->cbIV > NSize) goto error;
	memcpy(&rgbIV[NSize - pcose->cbIV], pcose->pbIV, pcose->cbIV);

	if (!cn_cbor_mapput_int(pcose->m_message.m_cbor, COSE_Header_IV, cn_cbor_data_create(rgbIV, NSize, CBOR_CONTEXT_PARAM_COMMA NULL), CBOR_CONTEXT_PARAM_COMMA NULL)) {
		goto error;
	}

	//  Setup and run the OpenSSL code

	EVP_CIPHER_CTX_init(&ctx);
	EVP_EncryptInit_ex(&ctx, EVP_aes_128_ccm(), NULL, NULL, NULL);

	EVP_CIPHER_CTX_ctrl(&ctx, EVP_CTRL_CCM_SET_L, LSize, 0);
	EVP_CIPHER_CTX_ctrl(&ctx, EVP_CTRL_CCM_SET_IVLEN, NSize, 0);
	EVP_CIPHER_CTX_ctrl(&ctx, EVP_CTRL_CCM_SET_TAG, TSize, NULL);	// Say we are doing an 8 byte tag

	EVP_EncryptInit(&ctx, 0, pcose->pbKey, rgbIV);

	EVP_EncryptUpdate(&ctx, 0, &cbOut, 0, pcose->cbContent);

	EVP_EncryptUpdate(&ctx, NULL, &outl, pbAuthData, cbAuthData);

	rgbOut = (byte *)COSE_CALLOC(cbOut + TSize, 1, context);
	if (rgbOut == NULL) goto error;

	EVP_EncryptUpdate(&ctx, rgbOut, &cbOut, pcose->pbContent, pcose->cbContent);

	EVP_EncryptFinal_ex(&ctx, &rgbOut[cbOut], &cbOut);

	EVP_CIPHER_CTX_ctrl(&ctx, EVP_CTRL_CCM_GET_TAG, TSize, &rgbOut[pcose->cbContent]);

	cn_cbor_mapput_int(pcose->m_message.m_cbor, COSE_Header_Ciphertext, cn_cbor_data_create(rgbOut, pcose->cbContent + TSize, CBOR_CONTEXT_PARAM_COMMA NULL), CBOR_CONTEXT_PARAM_COMMA NULL);

	return true;
}


bool AES_CCM_Encrypt(COSE_Encrypt * pcose, int TSize, int LSize, const byte * pbAuthData, int cbAuthData)
{
	EVP_CIPHER_CTX ctx;
	int cbOut;
	byte * rgbOut = NULL;
	size_t NSize = 15 - LSize;
	int outl = 0;
	byte rgbIV[15] = { 0 };
#ifdef USE_CBOR_CONTEXT
	cn_cbor_context * context = &pcose->m_message.m_allocContext;
#endif

	//  Setup the IV/Nonce and put it into the message

	if (pcose->pbIV == NULL) {
		error:
		if (rgbOut != NULL) COSE_FREE(rgbOut, context);
		return false;
	}

	if (pcose->cbIV > NSize) goto error;
	memcpy(&rgbIV[NSize-pcose->cbIV], pcose->pbIV, pcose->cbIV);

	if (!cn_cbor_mapput_int(pcose->m_message.m_cbor, COSE_Header_IV, cn_cbor_data_create(rgbIV, NSize, CBOR_CONTEXT_PARAM_COMMA NULL), CBOR_CONTEXT_PARAM_COMMA NULL)) {
		goto error;
	}

	//  Setup and run the OpenSSL code

	EVP_CIPHER_CTX_init(&ctx);
	EVP_EncryptInit_ex(&ctx, EVP_aes_128_ccm(), NULL, NULL, NULL);

	EVP_CIPHER_CTX_ctrl(&ctx, EVP_CTRL_CCM_SET_L, LSize, 0);
	EVP_CIPHER_CTX_ctrl(&ctx, EVP_CTRL_CCM_SET_IVLEN, NSize, 0);
	EVP_CIPHER_CTX_ctrl(&ctx, EVP_CTRL_CCM_SET_TAG, TSize, NULL);	// Say we are doing an 8 byte tag

	EVP_EncryptInit(&ctx, 0, pcose->pbKey, rgbIV);

	EVP_EncryptUpdate(&ctx, 0, &cbOut, 0, pcose->cbContent);

	EVP_EncryptUpdate(&ctx, NULL, &outl, pbAuthData, cbAuthData);

	rgbOut = (byte *)COSE_CALLOC(cbOut + TSize, 1, context);
	if (rgbOut == NULL) goto error;

	EVP_EncryptUpdate(&ctx, rgbOut, &cbOut, pcose->pbContent, pcose->cbContent);

	EVP_EncryptFinal_ex(&ctx, &rgbOut[cbOut], &cbOut);

	EVP_CIPHER_CTX_ctrl(&ctx, EVP_CTRL_CCM_GET_TAG, TSize, &rgbOut[pcose->cbContent]);

	cn_cbor_mapput_int(pcose->m_message.m_cbor, COSE_Header_Ciphertext, cn_cbor_data_create(rgbOut,  pcose->cbContent + TSize, CBOR_CONTEXT_PARAM_COMMA NULL), CBOR_CONTEXT_PARAM_COMMA NULL);

	return true;
}


void rand_bytes(byte * pb, size_t cb)
{
	RAND_bytes(pb, cb);
}

#endif // USE_OPEN_SSL
