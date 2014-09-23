#ifndef HEADER_CODEC_H
#define HEADER_CODEC_H
//////////////////////////////////////////////////////////////////////////
// License
//
// SQLiteCodecWrapper.
// jun jin pyo.
//
// http://greenfishblog.tistory.com/134
//
// This source code is under CC license.(http://creativecommons.org/licenses/)
// And any change of this source code is NOT permitted.
// BY-NC-ND was applied.
//
// 1. Redistributions of source code must retain the above copywrite notice with
//    no modification.
//
// 2. The use of this is non-commercial.
//
//////////////////////////////////////////////////////////////////////////

// parameter from sqlite tp user function
#define IN_PARAM

// parameter from user function to sqlite
#define OUT_PARAM

// parameter from user function to sqlite. you can ignore it.
#define OUT_OPTINAL_PARAM

// context for codec
typedef void* HANDLE_CODEC;

typedef struct tagST_CODEC_INTERNAL_CONTEXT
{
	unsigned int		unBlockSize;
	int					nPageSize;
	int					nReserveSize;
	void*				hHandle;
	Btree*				pBt;
	void*				pBuffer;
	int					nBufferSize;
} ST_CODEC_INTERNAL_CONTEXT, *LPST_CODEC_INTERNAL_CONTEXT;

#endif // HEADER_CODEC_H