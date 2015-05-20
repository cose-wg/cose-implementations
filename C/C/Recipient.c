#include "cose.h"
#include "cose_int.h"
#include "configure.h"
#include "crypto.h"

bool IsValidRecipientHandle(HCOSE_RECIPIENT h)
{
	if (h == NULL) return false;
	return true;
}

HCOSE_RECIPIENT COSE_Encrypt_GetRecipient(HCOSE_ENCRYPT cose, int iRecipient, cose_errback * perr)
{
	int i;
	COSE_RecipientInfo * p;

	if (!IsValidEncryptHandle(cose)) {
		if (perr != NULL) perr->err = COSE_ERR_INVALID_PARAMETER;
		return NULL;
	}

	p = ((COSE_Encrypt *)cose)->m_recipientFirst;
	for (i = 0; i < iRecipient; i++) {
		if (p == NULL) {
			if (perr != NULL) perr->err = COSE_ERR_INVALID_PARAMETER;
			return NULL;
		}
	}
	return (HCOSE_RECIPIENT)p;
}

COSE_RecipientInfo * _COSE_Recipient_Init_From_Object(const cn_cbor * cbor, CBOR_CONTEXT_COMMA cose_errback * errp)
{
	COSE_RecipientInfo * pRecipient = NULL;

	pRecipient = (COSE_RecipientInfo *)COSE_CALLOC(1, sizeof(COSE_RecipientInfo), context);
	if (pRecipient == NULL) {
		if (errp != NULL) errp->err = COSE_ERR_OUT_OF_MEMORY;
		return NULL;
	}

	if (_COSE_Encrypt_Init_From_Object(cbor, &pRecipient->m_encrypt, CBOR_CONTEXT_PARAM_COMMA errp) == NULL) {
		_COSE_Recipient_Free(pRecipient);
		return NULL;
	}

	return pRecipient;
}

void _COSE_Recipient_Free(COSE_RecipientInfo * pRecipient)
{
	COSE_FREE(pRecipient, &pRecipient->m_encrypt.m_message.m_allocContext);

	return;
}

byte * _COSE_RecipientInfo_generateKey(COSE_RecipientInfo * pRecipient, size_t cbitKeySize)
{
	int alg;
	const cn_cbor * cn_Alg = _COSE_Encrypt_map_get_int(&pRecipient->m_encrypt, COSE_Header_Algorithm, COSE_BOTH, NULL);

	if (cn_Alg == NULL) return false;
	if (cn_Alg->type != CN_CBOR_UINT) return false;
	alg = cn_Alg->v.uint;

	switch (alg) {
	case COSE_Algorithm_Direct:
	{
		if (pRecipient->m_encrypt.cbKey != cbitKeySize / 8) return NULL;
		byte * pb = (byte *)malloc(cbitKeySize / 8);
		if (pb == NULL) return NULL;
		memcpy(pb, pRecipient->m_encrypt.pbKey, cbitKeySize / 8);
		return pb;
	}
	break;

	default:
		return NULL;
	}
}

bool COSE_Recipient_SetKey(HCOSE_RECIPIENT h, const byte * pbKey, int cbKey, cose_errback * perror)
{
	COSE_RecipientInfo * p;

	if (!IsValidRecipientHandle(h) || (pbKey == NULL)) {
		if (perror != NULL) perror->err = COSE_ERR_CBOR;
		return false;
	}

	p = (COSE_RecipientInfo *)h;

	p->m_encrypt.pbKey = (byte *)COSE_CALLOC(cbKey, 1, &p->m_encrypt.m_message.m_allocContext);
	if (p->m_encrypt.pbKey == NULL) {
		if (perror != NULL) perror->err = COSE_ERR_OUT_OF_MEMORY;
		return false;
	}

	memcpy(p->m_encrypt.pbKey, pbKey, cbKey);
	p->m_encrypt.cbKey = cbKey;

	return true;
}