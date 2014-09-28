
// build when SQLITE_HAS_CODEC was defined
#ifdef SQLITE_HAS_CODEC

#include "codec.h"
#include <assert.h>
//////////////////////////////////////////////////////////////////////////
// reference function in caller (외부에서 정의하시오)
extern HANDLE_CODEC SQLiteCodecInit(IN_PARAM const void* pKey, IN_PARAM int nCbKey, OUT_OPTINAL_PARAM unsigned int* punCbBlockSize);
extern void  SQLiteCodecDeInit(IN_PARAM HANDLE_CODEC hHandle);
extern int SQLiteCodecEncode(IN_PARAM HANDLE_CODEC hHandle, IN_PARAM void* pSource, IN_PARAM int nCbSource, OUT_PARAM void* pDest, IN_PARAM int nCbDestBufSize, OUT_PARAM int* pnCbDest);
extern int SQLiteCodecDecode(IN_PARAM HANDLE_CODEC hHandle, IN_PARAM void* pSource, IN_PARAM int nCbSource, OUT_PARAM void* pDest, IN_PARAM int nCbDestBufSize, OUT_PARAM int* pnCbDest);

/*
Description

1)
	To build successfully, you define following four functions in your project.
	They are referenced from the sqlite3 codes as c function,
	so if you are planed to define them in c++, they must be in __cplusplus.
		----------------------
		| #ifdef __cplusplus |
		| extern "C" {		 |
		| #endif			 |
		| ...				 |
		| #ifdef __cplusplus |
		| }					 |
		| #endif			 |
		----------------------

2) do not use amalgamation version of sqlite.
   preprocessed version of legacy source code is recommended.

HANDLE_CODEC SQLiteCodecInit(IN_PARAM const void* pKey, IN_PARAM int nCbKey, OUT_OPTINAL_PARAM unsigned int* punCbBlockSize);
	pKey			: Key

	nCbKey			: Key length (in bytes)

	punCbBlockSize	: block size for encrypt.

					  if you'll use some symmetric cryptosystem(ex, AES 256),
					  some of them has a fixed increasing size when encrypt.
					  you must assign that fixed increasing size.
					  you can easily get it simply as encrypt ""(empty data).
					  the size of encrypt data can be considered.

					  if you using simply XOR encoding, and that encoding
					  does not have increasing size. so you can ignore this parameter.

    [return] Success : Context pointer / Fail : NULL

	it is called when "PRAGMA KEY='...'" was executed or sqlite3_key(...) was called.
	you must return HANDLE(or void*).
	that value can be used as a context of processing codec.

	if NULL was returned, the call of 'PRAGMA KEY=' or sqlite3_key(...) was FAILED as SQLITE_NOMEM.
	so the initialization of codec module was failed, you can pass NULL.

void SQLiteCodecDeInit(IN_PARAM HANDLE_CODEC hHandle);
	hHandle : HANDLE of SQLiteCodecInit(...)

	it is called when db was about closed.
	you can clean up all context from SQLiteCodecInit(...)

int SQLiteCodecEncode(IN_PARAM HANDLE_CODEC hHandle, IN_PARAM void* pSource, IN_PARAM int nCbSource, OUT_PARAM void* pDest, IN_PARAM int nCbDestBufSize, OUT_PARAM int* pnCbDest);
int SQLiteCodecDecode(IN_PARAM HANDLE_CODEC hHandle, IN_PARAM void* pSource, IN_PARAM int nCbSource, OUT_PARAM void* pDest, IN_PARAM int nCbDestBufSize, OUT_PARAM int* pnCbDest);
	hHandle        : HANDLE of SQLiteCodecInit(...)

	pSource        : En(De)crypt Source

	nCbSource      : pSource size (in bytes)

	pDest          : De(En)crypt Destination which must be filled in.

	nCbDestBufSize : pDest allocation size (in bytes)

	pnCbDest       : De(En)crypted size (in bytes)

	[return] Success : 1 / Fail : 0
	
	it is called when the database action was executed.

	if en(de)cryption was failed, you can pass return as 0.
	when it was returned as 0, the database action was failed.
	you can pass return as 1, it is that en(de)cryption was successful.

	[remark]
	pDest was guaranteed to be zero memory.
*/

// Internal Callback Prototype
static void* CodecInternal(void* ctx, void* data, Pgno pgNo, int mode);
static void CodecFreeInternal(void* ctx);

// reference function in pager.c
extern void sqlite3PagerSetCodec(Pager *pPager,void *(*xCodec)(void*,void*,Pgno,int),void (*xCodecSizeChng)(void*,int,int),void (*xCodecFree)(void*),void *pCodec);

//////////////////////////////////////////////////////////////////////////
// Function for SQLITE_HAS_CODEC

// called from
// "vaccum;" (nDB = 0)
// "attach database 'xxx.db' as db2"; (nDB > 0)
void sqlite3CodecGetKey(sqlite3* db, int nDb, void** zKey, int* nKey)
{
	// magic value as 1313
	*zKey = NULL;
	*nKey = 1313;
}

// called from
// ATTACH DATABASE db AS dba KEY k
// or
// PRAGMA KEY=k (sqlite_attach)
// zKey can be NULL.
// nKey,
//		minus - zKey as encrypt key. using abs(nKey) to get length.
//		0     - not encrypted
//		plus  - zKey as passphrase. using nKey to get length
int sqlite3CodecAttach(sqlite3* db, int nDb, const void* zKey, int nKey)
{
	int							rc			= SQLITE_OK;	// return code
	unsigned int				nBlockSize	= 0;
	struct Db*					pDb			= NULL;
	LPST_CODEC_INTERNAL_CONTEXT	pstContext	= NULL;

	if (NULL == db)
	{
		assert(FALSE);
		return SQLITE_INTERNAL;
	}

	if ((NULL == zKey) && (1313 == nKey))
	{
		// magic value.
		// already called sqlite3PagerSetCodec(...), so exit.
		rc = SQLITE_OK;
		goto FINAL;
	}

	if ((NULL == zKey) || (0 == nKey))
	{
		rc = SQLITE_OK;
		assert(FALSE);
		goto FINAL;
	}

	if (NULL == db->aDb)
	{
		rc = SQLITE_INTERNAL;
		assert(FALSE);
		goto FINAL;
	}

	// where is database?
	pDb	= &db->aDb[nDb];

	if ((NULL == pDb->pBt) || (NULL == sqlite3BtreePager(pDb->pBt)))
	{
		rc = SQLITE_INTERNAL;
		assert(FALSE);
		goto FINAL;
	}

	// allocation of internal context
	pstContext	= sqlite3MallocZero(sizeof(ST_CODEC_INTERNAL_CONTEXT));
	if (NULL == pstContext)
	{
		rc = SQLITE_NOMEM;
		assert(FALSE);
		goto FINAL;
	}

	// Assign codec information.
	// compiled with over Sqlite3 version 3006016.
	sqlite3PagerSetCodec(sqlite3BtreePager(pDb->pBt), CodecInternal, NULL, CodecFreeInternal, (void*)pstContext);

	// call external define function
	pstContext->hHandle = SQLiteCodecInit(zKey, abs(nKey), &nBlockSize);
	if (NULL == pstContext->hHandle)
	{
		rc = SQLITE_NOMEM;
		assert(FALSE);
		goto FINAL;
	}

	if (sqlite3BtreeGetPageSize(pDb->pBt) + 1<= (int)nBlockSize)
	{
		// user defined block size check failed
		// block size must be smaller than page size
		rc = SQLITE_INTERNAL;
		assert(FALSE);
		goto FINAL;
	}

	// configuration internal context
	pstContext->unBlockSize = nBlockSize;
	pstContext->pBt			= pDb->pBt;
	pstContext->nPageSize	= sqlite3BtreeGetPageSize(pDb->pBt);
	pstContext->nReserveSize= nBlockSize;
	pstContext->nBufferSize	= pstContext->nPageSize;
	pstContext->pBuffer		= sqlite3MallocZero(pstContext->nBufferSize);
	if (NULL == pstContext->pBuffer)
	{
		rc = SQLITE_NOMEM;
		assert(FALSE);
		goto FINAL;
	}

	// set page size.
	// pageSize : x^2. size of page to be save to file		==> normally SQLITE_DEFAULT_PAGE_SIZE(1024 byte)
	// reserved : the user define area in the end of a page.==> block size byte
	//
	// actual page size to be saved is (pageSize-reserve).
	// we can reserve the block size of the codec algorithm,
	// encrypt a page can not be overflowed by increasing small block size.
	if (0 != pstContext->nReserveSize)
	{
		//////////////////////////////////////////////////////////////////////////
		// db lock
		sqlite3_mutex_enter(db->mutex);
		{
			sqlite3BtreeSetPageSize(pDb->pBt, pstContext->nPageSize, pstContext->nReserveSize, 0);
		}
		sqlite3_mutex_leave(db->mutex);
		// db unlock
		//////////////////////////////////////////////////////////////////////////
	}

FINAL:
	return rc;
}

void sqlite3_activate_see(const char *zPassPhrase)
{
	return;
}

// change key. not implemented.
// you can change key to call sqlite3_backup_init.
int sqlite3_rekey(sqlite3 *db, const void *pKey, int nKey)
{
	assert(FALSE);
	return SQLITE_ERROR;
}

// PRAGMA KEY='xxxx';
int sqlite3_key(sqlite3 *db, const void *pKey, int nKey)
{
	if ((0 == nKey) || (NULL == pKey))
	{
		return SQLITE_OK;
	}

	return sqlite3CodecAttach(db, 0, pKey, nKey);
}

int sqlite3_key_v2( sqlite3 *db, const char *zDbName, const void *pKey, int nKey )
{
	return sqlite3_key(db, pKey, nKey);
}

int sqlite3_rekey_v2( sqlite3 *db, const char *zDbName, const void *pKey, int nKey )
{
	return sqlite3_rekey(db, pKey, nKey);
}

//////////////////////////////////////////////////////////////////////////
// Internal used

// Codec callback
static void* CodecInternal(void* ctx, void* data, Pgno pgNo, int mode)
{
	LPST_CODEC_INTERNAL_CONTEXT	pstContext		= NULL;
	unsigned char*				pRtnValue		= NULL;
	int							i				= 0;
	int							nCbCodec		= 0;
	int							nPageSize		= 0;
	int							nReserveSize	= 0;
	int							nDataSize		= 0;
	int							nCbBuffer		= 0;
	int							rc				= SQLITE_OK;

	pstContext = (LPST_CODEC_INTERNAL_CONTEXT)ctx;
	if (NULL == pstContext)
	{
		goto FINAL;
	}

	if (NULL == pstContext->hHandle)
	{
		goto FINAL;
	}

	// get page and reserve size
	nPageSize		= sqlite3BtreeGetPageSize(pstContext->pBt);
	nReserveSize	= sqlite3BtreeGetReserve(pstContext->pBt);

	// actual size to be saved
	nDataSize		= nPageSize - nReserveSize;
	if (nDataSize < 0)
	{
		assert(FALSE);
		goto FINAL;
	}

	switch (mode)
	{
		//////////////////////////////////////////////////////////////////////////
		// decrypt
		case 0:	// journal file decrypt
		case 2:	// page reload
		case 3:	// page load
		{
			// decode here
			if (0 == SQLiteCodecDecode(pstContext->hHandle, 
									   data, 
									   nPageSize, 
									   pstContext->pBuffer, 
									   pstContext->nBufferSize, 
									   &nCbBuffer))
			{
				// return as NULL.
				// execute of database will be failed.
				assert(FALSE);
				goto FINAL;
			}

			if (nCbBuffer != nDataSize)
			{
				// must be same
				assert(FALSE);
			}
			else
			{
				pRtnValue = pstContext->pBuffer;

				// save to data
				memcpy(data, pstContext->pBuffer, nDataSize);
			}
		}
		break;

		//////////////////////////////////////////////////////////////////////////
		// encrypt
		case 6:	// page encrypt
		case 7:	// journal file encrypt
		{
			// encrypt here
			if (0 == SQLiteCodecEncode(pstContext->hHandle, 
									   data, 
									   nDataSize, 
									   pstContext->pBuffer, 
									   pstContext->nBufferSize, 
									   &nCbBuffer))
			{
				// 이곳에서 NULL이 전달되면, sql statement 실행은 실패된다.
				assert(FALSE);
				goto FINAL;
			}

			pRtnValue = pstContext->pBuffer;
		}
		break;
	}
	
FINAL:
	return pRtnValue;
}

// Codec callback
static void CodecFreeInternal(void* ctx)
{
	LPST_CODEC_INTERNAL_CONTEXT pstContext = NULL;

	pstContext = (LPST_CODEC_INTERNAL_CONTEXT)ctx;
	if (NULL == pstContext)
	{
		return;
	}

	if (NULL != pstContext->pBuffer)
	{
		sqlite3_free(pstContext->pBuffer);
		pstContext->pBuffer = NULL;
	}

	if (NULL == pstContext->hHandle)
	{
		return;
	}

	SQLiteCodecDeInit(pstContext->hHandle);
	pstContext->hHandle = NULL;

	sqlite3_free(pstContext);
	pstContext = NULL;
}

#else // SQLITE_HAS_CODEC
	#pragma message("[codec.c] SQLITE_HAS_CODEC is not defined.")
#endif // SQLITE_HAS_CODEC
