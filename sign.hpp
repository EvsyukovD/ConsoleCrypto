# pragma once
#include "apibase.hpp"
#define STATUS_BAD_SIGNATURE 0xC000A000
typedef struct SignObject {
	BCRYPT_KEY_HANDLE hKey = NULL;
	BCRYPT_ALG_HANDLE hSignAlg = NULL;
	DWORD cbSignature = 0;
	PBYTE pbSignature = NULL;
} SignObject, * PSignObject;

/**
  Initialize Sign object struct
  
  @param pSObject - destiny sign structure
  @param lpAlgorithmID - algorithm identificator
  @param lpAlgorithmProvider - algorithm implementation
*/
NTSTATUS InitSign(PSignObject pSObject,LPCWSTR lpAlgorithmID, LPCWSTR lpAlgorithmProvider);
/**
 Create signature key for given algorithm

 @param pSObject - destiny sign object
 @param dwKeyLen - key length in bits
*/
NTSTATUS CreateSignKey(PSignObject pSObject, DWORD dwKeyLen);
/**
  Sign given hash

  @param pSobject - destiny sign object
  @param pHash - source hash array
  @param cbHash - hash size in bytes
  @param lpPaddingInfo - padding info struct
  @param dwPaddingFlags - padding flags
*/
NTSTATUS SignHash(PSignObject pSobject, PBYTE pHash, DWORD cbHash, PVOID lpPaddingInfo, DWORD dwPaddingFlags);
/**
  Export key from sign object key to byte array
  This function calculates byte size for destiny buffer,
  allocates this bytes and then copy key to destiny buffer

  @param pSObject - source sign object
  @param pszBlobType - type of source key
  @param pcbBlob - destiny byte size
  @param ppbBlob - byte array pointer
*/
NTSTATUS ExportSignKey(PSignObject pSObject, LPCWSTR pszBlobType, PDWORD pcbBlob, PBYTE* ppbBlob);

/**
  Import key from byte array to sign key object struct

  @param pSObject - destiny sign object
  @param pszBlobType - type of key
  @param cbBlob - source byte size
  @param pbBlob - byte array pointer
*/
NTSTATUS ImportSignKey(PSignObject pSObject, LPCWSTR pszBlobType, DWORD cbBlob, PBYTE pbBlob);
/**
  Verify hash signature

  @param pSObject - signature object structure
  @param pbHash - source hash array
  @param cbHash - hash size in bytes
*/
NTSTATUS VerifyHashSign(PSignObject pSObject, PBYTE pbHash, DWORD cbHash, PVOID lpPaddingInfo, DWORD dwPaddingFlags);


VOID ClearSign(PSignObject pSObject);