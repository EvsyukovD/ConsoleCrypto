#pragma once
#include <Windows.h>
#include <iostream>

#define DO_NOT_USE_ENCODING 0xffffffff

#define DO_NOT_USE_DECODING 0xffffffff

#define NT_SUCCESS(Status)          (((NTSTATUS)(Status)) >= 0)

#define STATUS_UNSUCCESSFUL         ((NTSTATUS)0xC0000001L)

/**
 Encode bytes and write them to string.
 If output string is too small, function reallocates memory for it

 @param pbBinary - source bytes for encoding
 @param cbBinary - source size in bytes
 @param dwFlags - flags for encoding [coding without headers]
 @param pszString - output string pointer
 @param pcbString - output string size pointer
*/
BOOL EncodeBytes(const PBYTE pbBinary, DWORD cbBinary, DWORD dwFlags, LPSTR *pszString, PDWORD pcbString);

/**
 Decode string and write chars to bytes.
 If output bytes array is too small, function reallocates memory for it

 @param ppbBinary - output bytes array pointer
 @param pcbBinary - output size in bytes pointer
 @param dwFlags - flags for decoding [coding without headers]
 @param szString - source encoded string
*/
BOOL DecodeBytes(PBYTE* ppbBinary, PDWORD pcbBinary, DWORD dwFlags, LPCSTR szString);
/*
Write blob to file

@param szPath - target file path
@param pbBlob - blob byte array
@param cbBlob - blob byte array size in bytes
**/
DWORD WriteBlobToFileA(LPCSTR szPath, const PBYTE pbBlob, DWORD cbBlob);
/*
Read blob from file. In fact, it returns zero terminated string. 

@param szPath - target file path
@param ppbBlob - blob byte array pointer
@param pcbBlob - blob byte array size in bytes without zero on the end
**/
DWORD ReadBlobFromFileA(LPCSTR szPath, PBYTE* ppbBlob, PDWORD pcbBlob);

/**
  Get key length in bits for cipher/signature algorithm.
  If algorithm is not defined, it returns 0

  @param lpAlgorithmID - algorithm identificator
*/
DWORD GetKeyLenForAlgId(LPCWSTR lpAlgorithmID);