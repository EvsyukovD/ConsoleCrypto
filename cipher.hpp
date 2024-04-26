#pragma once
#include "apibase.hpp"

typedef struct CipherObject{
	BCRYPT_ALG_HANDLE hAlg = NULL;
	BCRYPT_KEY_HANDLE hKey = NULL;
	PBYTE             pbKeyObject = NULL; 
	DWORD             cbKeyObject = 0;
	DWORD             cbBlockLen = 0; 
}CipherObject, *PCipherObject;
/*
 Initialize cipher object struct

 @param pCO - target cipher structure
 @param lpBlockCipherMode - block cipher mode
 @param lpAlgorithmId - algorithm id
 @param lpAlgorithmProvider - algorithm implementation
**/
NTSTATUS InitCipherObject(PCipherObject pCO, LPCWSTR lpBlockCipherMode, LPCWSTR lpAlgorithmId, LPCWSTR lpAlgorithmProvider);
/*
 Generate symmetric key

 @param pCO - target cipher structure
 @param dwKeyLen - key length in bytes
**/
NTSTATUS GenerateSymKey(PCipherObject pCO, DWORD dwKeyLen);
/*
 Encrypt input data.
 
 @param pCO - cipher structure with algorithm and key
 @param pbData - input data array
 @param cbData - input data size in bytes
 @param ppbOut - output ciphertext array pointer
 @param pcbOut - output ciphertext array size in bytes pointer
 @param pbIV - IV array (optional), if use respective block cipher mode
**/
NTSTATUS Encrypt(PCipherObject pCO, PBYTE pbData, DWORD cbData, PBYTE* ppbOut, PDWORD pcbOut, PBYTE pbIV);

/*
 Decrypt input data.

 @param pCO - cipher structure with algorithm and key
 @param pbData - input ciphertext array
 @param cbData - input ciphertext size in bytes
 @param ppbOut - output data array pointer
 @param pcbOut - output data array size in bytes pointer
 @param pbIV - IV array (optional), if use respective block cipher mode
**/
NTSTATUS Decrypt(PCipherObject pCO, PBYTE pbData, DWORD cbData, PBYTE* ppbOut, PDWORD pcbOut, PBYTE pbIV);

/*
 Encrypt 1 chunk of data. Note that this function will modify pbIV, 
 so for next call of this function you can use this new pbIV
 
 @param pCO - cipher structure with algorithm and key
 @param pbData - input data chunk array
 @param ppbOut - output ciphertext array pointer
 @param pcbOut - output ciphertext array size in bytes pointer
 @param pbIV - IV array (optional), if use respective block cipher mode
**/
NTSTATUS EncryptChunk(PCipherObject pCO, PBYTE pbData, PBYTE* ppbOut, PDWORD pcbOut, PBYTE pbIV);
/*
 Decrypt 1 chunk of data. Note that this function will modify pbIV,
 so for next call of this function you can use this new pbIV

 @param pCO - cipher structure with algorithm and key
 @param pbData - input data chunk array
 @param ppbOut - output ciphertext array pointer
 @param pcbOut - output ciphertext array size in bytes pointer
 @param pbIV - IV array (optional), if use respective block cipher mode
**/
NTSTATUS DecryptChunk(PCipherObject pCO, PBYTE pbData, PBYTE* ppbOut, PDWORD pcbOut, PBYTE pbIV);
/*
 Make PKCS7 padding

 @param pbData - buffer with plaintext with size of 1 block
 @param cbData - plaintext size in bytes in buffer
 @param dwBlockLen - length of 1 block in bytes
**/
NTSTATUS PadPKCS7(PBYTE pbData, DWORD cbData, DWORD dwBlockLen);
/*
 Remove PKCS7 padding

 @param pbData - buffer with plaintext with size of 1 block
 @param pcbData - plaintext size in bytes in buffer pointer. It must be a multiple of 1 block size
 @param dwBlockLen - length of 1 block in bytes
**/
NTSTATUS UnPadPKCS7(PBYTE pbData, PDWORD pcbData, DWORD dwBlockLen);

NTSTATUS ExportSymKey(PCipherObject pCO, LPCWSTR lpBlobType, PBYTE* ppbBlob, PDWORD pcbBlob);

NTSTATUS ImportSymKey(PCipherObject pCO, LPCWSTR lpBlobType, PBYTE pbBlob, DWORD cbBlob);

VOID ClearCipherObject(PCipherObject pCO);