#pragma once
#include "hash.hpp"
#include "sign.hpp"
#include "cipher.hpp"

/**
 Hash file content
 Params:
 @param pHashObject - hash object structure pointer
 @param filename - name of target file
*/
NTSTATUS HashFileA(PHashObject pHashObject, LPCSTR szFileName);
/**
 Sign content of file.
 Function calculates hash of file's content and then
 sign this hash.
 @param pSObject - sign object struct pointer
 @param pHashObject - hash object struct pointer
 @param szFileName - name of target file
*/
NTSTATUS SignFileA(PSignObject pSObject, PHashObject pHashObject, LPCSTR szFileName, PVOID lpPaddingInfo, DWORD dwPaddingFlags);

/**
  Main function for hashing content of file

  @param hFile - file handle
  @param pHashObject - hash object struct
*/
NTSTATUS HashFileContent(HANDLE hFile, PHashObject pHashObject);

/**
 Hash directory content. If bool flag boolRecursive is TRUE hashing
 will be done in a recursive way, hashing files content.

 Hash of the dir is equal to Hash( Hash(Object_1) ^ Hash(Object_2) ^ ... Hash(Object_n)) where Object_i is
 file or directory. If boolRecursive == FALSE Object_i is file only, ignore directories

 @param lpRoot - path to the root directory
 @param pHashObject - hash object structure
 @param boolRecursive - do recursive hashing or not
*/
NTSTATUS HashDirectoryA(LPCSTR lpRoot, PHashObject pHashObject, BOOL boolRecursive);

/**
 Sign content of directory.
 Function calculates hash of directory's content and then
 sign this hash.
 @param pSObject - sign object struct pointer
 @param pHashObject - hash object struct pointer
 @param szPath - path to target dir
 @param boolRecursive - hash dir recursively or not
*/
NTSTATUS SignDirectoryA(PSignObject pSObject, PHashObject pHashObject, LPCSTR szPath, BOOL boolRecursive, PVOID lpPaddingInfo, DWORD dwPaddingFlags);

/**
  Export signature key to file with optional encoding.
  If you don't want to use encoding, specify dwEncodingFlags = DO_NOT_USE_ENCODING
  @param pSObject - signature object pointer
  @param lpBlobType - blob type
  @param szPath - destiny file path
  @param dwEncodingFlags - encoding flags [optional]
*/
NTSTATUS ExportSignKeyToFileA(PSignObject pSObject, LPCWSTR lpBlobType, LPCSTR szPath, DWORD dwEncodingFlags);

/**
  Import signature key to file with optional decoding.
  If you don't want to use decoding, specify dwDecodingFlags = DO_NOT_USE_DECODING
  @param pSObject - destiny signature object pointer
  @param lpBlobType - blob type
  @param szPath - source file path
  @param dwDecodingFlags - decoding flags [optional]
*/
NTSTATUS ImportSignKeyFromFileA(PSignObject pSObject, LPCWSTR lpBlobType, LPCSTR szPath, DWORD dwDecodingFlags);

/**
  Export symmetric key to file with optional encoding.
  If you don't want to use encoding, specify dwEncodingFlags = DO_NOT_USE_ENCODING
  @param pCO - cipher object pointer
  @param lpBlobType - blob type
  @param szPath - destiny file path
  @param dwEncodingFlags - encoding flags [optional]
*/
NTSTATUS ExportSymKeyToFileA(PCipherObject pCO, LPCWSTR lpBlobType, LPCSTR szPath, DWORD dwEncodingFlags);

/**
  Import symmetric key to file with optional decoding.
  If you don't want to use decoding, specify dwDecodingFlags = DO_NOT_USE_DECODING
  @param pCO - destiny cipher object pointer
  @param lpBlobType - blob type
  @param szPath - source file path
  @param dwDecodingFlags - decoding flags [optional]
*/
NTSTATUS ImportSymKeyFromFileA(PCipherObject pCO, LPCWSTR lpBlobType, LPCSTR szPath, DWORD dwDecodingFlags);
/*
 Encrypt small file

 @param pCO - cipher object pointer with key
 @param szDataPath - target file path
 @param pbIV - iv [optional]
 @param ppbOut - output byte array pointer
 @param pcbOut - output byte array size in bytes pointer
 @param dwEncodingFlags - encoding flags
**/
NTSTATUS EncryptFileA(PCipherObject pCO, LPCSTR szDataPath, PBYTE pbIV, PBYTE* ppbOut, PDWORD pcbOut, DWORD dwEncodingFlags);
/*
 Decrypt small file

 @param pCO - cipher object pointer with key
 @param szDataPath - target file path
 @param pbIV - iv [optional]
 @param ppbOut - output byte array pointer
 @param pcbOut - output byte array size in bytes pointer
 @param dwDecodingFlags - decoding flags
**/
NTSTATUS DecryptFileA(PCipherObject pCO, LPCSTR szDataPath, PBYTE pbIV, PBYTE* ppbOut, PDWORD pcbOut, DWORD dwDecodingFlags);
/*
 Encrypt file by chunks and write them to output file

 @param pCO - cipher object struct with key
 @param szDataPath - input data file path
 @param szOutputPath - output file path
 @param pbIV - iv if need for block cipher mode [optional]
**/
NTSTATUS EncryptFileByChunksA(PCipherObject pCO, LPCSTR szDataPath, LPCSTR szOutputPath, PBYTE pbIV);

NTSTATUS EncryptFileByChunksACore(PCipherObject pCO, HANDLE hInput, HANDLE hOutput, PBYTE pbIV);

/*
 Decrypt file by chunks and write them to output file

 @param pCO - cipher object struct with key
 @param szDataPath - input data file path
 @param szOutputPath - output file path
 @param pbIV - iv if need for block cipher mode [optional]
**/
NTSTATUS DecryptFileByChunksA(PCipherObject pCO, LPCSTR szDataPath, LPCSTR szOutputPath, PBYTE pbIV);

NTSTATUS DecryptFileByChunksACore(PCipherObject pCO, HANDLE hInput, HANDLE hOutput, PBYTE pbIV);