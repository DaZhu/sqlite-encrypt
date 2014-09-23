#ifndef __ENCRYPTIMPL__H__
#define __ENCRYPTIMPL__H__

#ifdef __cplusplus
extern "C" {
#endif
#include <Windows.h>
#include <WinCrypt.h>
#include <assert.h>
	typedef struct tagST_CODEC_HANDLE
	{
		HCRYPTPROV	hCryptProv;
		HCRYPTHASH	hHash;
		HCRYPTKEY	hKey;
	} ST_CODEC_HANDLE, *LPST_CODEC_HANDLE;

	HANDLE_CODEC SQLiteCodecInit(IN_PARAM const void* pKey, IN_PARAM int nCbKey, OUT_OPTINAL_PARAM unsigned int* punCbBlockSize)
	{
		void*				pRtnValue		= NULL;
		LPST_CODEC_HANDLE	pstCodecHandle	= NULL;

		pstCodecHandle = (ST_CODEC_HANDLE*)malloc(sizeof(ST_CODEC_HANDLE));
		ZeroMemory(pstCodecHandle, sizeof(ST_CODEC_HANDLE));

		if (FALSE == CryptAcquireContext(&pstCodecHandle->hCryptProv, NULL, MS_ENH_RSA_AES_PROV, PROV_RSA_AES, 0))
		{
			assert(FALSE);
			goto FINAL;
		}

		if (FALSE == CryptCreateHash(pstCodecHandle->hCryptProv, CALG_SHA_256, 0, 0, &pstCodecHandle->hHash))
		{
			assert(FALSE);
			goto FINAL;
		}

		if (FALSE == CryptHashData(pstCodecHandle->hHash, (LPBYTE)pKey, nCbKey, 0))
		{
			assert(FALSE);
			goto FINAL;
		}

		if (FALSE == CryptDeriveKey(pstCodecHandle->hCryptProv, CALG_AES_256, pstCodecHandle->hHash, CRYPT_EXPORTABLE, &pstCodecHandle->hKey))
		{
			assert(FALSE);
			goto FINAL;
		}

		// AES 256 block size
		*punCbBlockSize = 16;

		pRtnValue = pstCodecHandle;

FINAL:
		return pRtnValue;
	}

	void SQLiteCodecDeInit(IN_PARAM HANDLE_CODEC hHandle)
	{
		LPST_CODEC_HANDLE pstHandle = NULL;

		pstHandle = (LPST_CODEC_HANDLE)hHandle;
		if (NULL == pstHandle)
		{
			goto FINAL;
		}

		if (0 != pstHandle->hKey)
		{
			CryptDestroyKey(pstHandle->hKey);
			pstHandle->hKey = 0;
		}

		if (0 != pstHandle->hHash)
		{
			CryptDestroyHash(pstHandle->hHash);
			pstHandle->hHash = 0;
		}

		if (0 != pstHandle->hCryptProv)
		{
			CryptReleaseContext(pstHandle->hCryptProv, 0);
			pstHandle->hCryptProv = 0;
		}

		free(hHandle);
		hHandle = 0;

FINAL:
		return;
	}

	int SQLiteCodecEncode(IN_PARAM HANDLE_CODEC hHandle, IN_PARAM void* pSource, IN_PARAM int nCbSource, OUT_PARAM void* pDest, IN_PARAM int nCbDestBufSize, OUT_PARAM int* pnCbDest)
	{
		int					nRtnValue	= 1;
		LPST_CODEC_HANDLE	pstHandle	= NULL;
		DWORD				dwCbLength	= 0;

		pstHandle = (LPST_CODEC_HANDLE)hHandle;
		if (NULL == pstHandle)
		{
			nRtnValue = 0;
			assert(FALSE);
			goto FINAL;
		}

		dwCbLength = nCbSource;
		CopyMemory(pDest, pSource, nCbDestBufSize);
		if (FALSE == CryptEncrypt(pstHandle->hKey, 0, TRUE, 0, (LPBYTE)pDest, &dwCbLength, nCbDestBufSize))
		{
			nRtnValue = 0;
			assert(FALSE);
			goto FINAL;
		}
		*pnCbDest = dwCbLength;

FINAL:
		return nRtnValue;
	}

	int SQLiteCodecDecode(IN_PARAM HANDLE_CODEC hHandle, IN_PARAM void* pSource, IN_PARAM int nCbSource, OUT_PARAM void* pDest, IN_PARAM int nCbDestBufSize, OUT_PARAM int* pnCbDest)
	{
		int					nRtnValue	= 1;
		LPST_CODEC_HANDLE	pstHandle	= NULL;
		DWORD				dwCbLength	= 0;

		pstHandle = (LPST_CODEC_HANDLE)hHandle;
		if (NULL == pstHandle)
		{
			nRtnValue = 0;
			assert(FALSE);
			goto FINAL;
		}

		dwCbLength = nCbDestBufSize;
		CopyMemory(pDest, pSource, nCbDestBufSize);
		if (FALSE == CryptDecrypt(pstHandle->hKey, 0, TRUE, 0, (LPBYTE)pDest, &dwCbLength))
		{
			nRtnValue = 0;
			assert(FALSE);
			goto FINAL;
		}
		*pnCbDest = dwCbLength;

FINAL:
		return nRtnValue;
	}

#ifdef __cplusplus
}
#endif

#endif //__ENCRYPTIMPL__H__