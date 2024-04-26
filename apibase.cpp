#include "apibase.hpp"
#include "wincrypt.h"

#define BUFSIZE 256

BOOL EncodeBytes(const PBYTE pbBinary, DWORD cbBinary, DWORD dwFlags, LPSTR* pszString, PDWORD pcbString) {

	DWORD dwSize = 0;

	CryptBinaryToStringA(pbBinary, cbBinary, dwFlags, NULL, &dwSize);
	if (dwSize > *pcbString) {
		LPSTR lpResult = (LPSTR)realloc((LPSTR)*pszString, dwSize);
		if (!lpResult) {
			wprintf(L"**** memory allocation failed\n");
			return FALSE;
		}
		*pcbString = dwSize;
		*pszString = lpResult;
		memset(*pszString, 0, *pcbString);
	}
	return CryptBinaryToStringA(pbBinary, cbBinary, dwFlags, *pszString, &dwSize);
}

BOOL DecodeBytes(PBYTE* ppbBinary, PDWORD pcbBinary, DWORD dwFlags, LPCSTR szString) {

	DWORD dwSize = 0, dwSkip = 0, dwCryptFlags = 0;

	CryptStringToBinaryA(szString, 0, dwFlags, NULL, &dwSize, &dwSkip, &dwCryptFlags);
	if (dwSize > *pcbBinary) {
		PBYTE lpResult = (PBYTE)realloc((PBYTE)*ppbBinary, dwSize);
		if (!lpResult) {
			wprintf(L"**** memory allocation failed\n");
			return FALSE;
		}
		*pcbBinary = dwSize;
		*ppbBinary = lpResult;
		memset(*ppbBinary, 0, *pcbBinary);
	}
	return CryptStringToBinaryA(szString, 0, dwFlags, *ppbBinary, &dwSize, &dwSkip, &dwCryptFlags);
}

DWORD WriteBlobToFileA(LPCSTR szPath, const PBYTE pbBlob, DWORD cbBlob) {
	HANDLE hFile = NULL;
	DWORD dwStatus = 0, dwWrittenBytes = 0;
	BOOL boolResult = FALSE;

	// Open file for writing
	hFile = CreateFileA(szPath,
		FILE_GENERIC_READ | FILE_GENERIC_WRITE,
		FILE_SHARE_WRITE | FILE_SHARE_READ,
		NULL, OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
		dwStatus = GetLastError();
		wprintf(L"**** Error 0x%x returned by CreateFileA\n", dwStatus);
		return dwStatus;
	}

	// Write blob to file
	boolResult = WriteFile(hFile, pbBlob, cbBlob, &dwWrittenBytes, NULL);
	if (!boolResult || dwWrittenBytes != cbBlob) {
		dwStatus = GetLastError();
		wprintf(L"**** Error 0x%x returned by WriteFile\n", dwStatus);
		CloseHandle(hFile);
		return dwStatus;
	}
	CloseHandle(hFile);
	return 0;
}

DWORD ReadBlobFromFileA(LPCSTR szPath, PBYTE* ppbBlob, PDWORD pcbBlob) {

	HANDLE hFile = NULL;
	DWORD dwStatus = 0, cbRead = 0, cchString = 0;
	BOOL boolResult = FALSE;
	BYTE buffer[BUFSIZE] = {0};
	PBYTE lpString = NULL;
	LPVOID lpTmp = NULL;

	// Open file for reading
	hFile = CreateFileA(szPath,
		FILE_GENERIC_READ | FILE_GENERIC_WRITE,
		FILE_SHARE_WRITE | FILE_SHARE_READ,
		NULL, OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL, NULL);

	if (hFile == INVALID_HANDLE_VALUE) {
		dwStatus = GetLastError();
		wprintf(L"**** Error 0x%x returned by CreateFileA\n", dwStatus);
		return dwStatus;
	}

	// Start reading file via buffer with fixed size
	while (boolResult = ReadFile(hFile, buffer, BUFSIZE - 1,
		&cbRead, NULL))
	{
		if (0 == cbRead)
		{
			break;
		}

		if (cchString == 0) {
			lpTmp = calloc(1 + cbRead, 1);
		}
		else {
			lpTmp = realloc(lpString, cchString + cbRead);
		}
		if (!lpTmp) {
			dwStatus = GetLastError();
			wprintf(L"**** memory allocation failed\n");
			free(lpString);
			CloseHandle(hFile);
			return dwStatus;
		}
		lpString = (PBYTE)lpTmp;
		memcpy_s(&lpString[cchString], cbRead, buffer, cbRead);
		cchString += cbRead;
		memset(buffer, 0, BUFSIZE);
	}

	CloseHandle(hFile);

	if (!boolResult)
	{
		dwStatus = GetLastError();
		wprintf(L"**** Error 0x%x returned by ReadFile\n", dwStatus);
		free(lpString);
		return dwStatus;
	}

	*ppbBlob = lpString;
	*pcbBlob = cchString;
	return 0;
}

DWORD GetKeyLenForAlgId(LPCWSTR lpAlgorithmID) {
	if (!wcscmp(lpAlgorithmID, BCRYPT_ECDH_P256_ALGORITHM) || !wcscmp(lpAlgorithmID, BCRYPT_ECDSA_P256_ALGORITHM))
		return 256;
	if (!wcscmp(lpAlgorithmID, BCRYPT_ECDH_P384_ALGORITHM) || !wcscmp(lpAlgorithmID, BCRYPT_ECDSA_P384_ALGORITHM))
		return 384;
	if (!wcscmp(lpAlgorithmID, BCRYPT_ECDH_P521_ALGORITHM) || !wcscmp(lpAlgorithmID, BCRYPT_ECDSA_P521_ALGORITHM))
		return 521;
	if (!wcscmp(lpAlgorithmID, BCRYPT_RSA_ALGORITHM))
		return 2048;
	if (!wcscmp(lpAlgorithmID, BCRYPT_DSA_ALGORITHM))
		return 2048;
	if (!wcscmp(lpAlgorithmID, BCRYPT_DH_ALGORITHM))
		return 2048;
	if (!wcscmp(lpAlgorithmID, BCRYPT_AES_ALGORITHM))
		return 128;

	return 0;
}