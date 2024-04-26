#include "crypto.hpp"
#include "hash.hpp"
#include <Shlwapi.h>

#define BUFSIZE 256

NTSTATUS HashFileA(PHashObject pHashObject, LPCSTR filename)

{
	DWORD dwStatus = 0;
	NTSTATUS ntStatus;
	HANDLE hFile = NULL;

	if (!pHashObject || !filename)
		return STATUS_INVALID_PARAMETER;

	// Open file.
	hFile = CreateFileA(filename,
		GENERIC_READ | GENERIC_WRITE,
		FILE_SHARE_READ | FILE_SHARE_WRITE,
		NULL,
		OPEN_EXISTING,
		FILE_FLAG_SEQUENTIAL_SCAN | FILE_FLAG_BACKUP_SEMANTICS,
		NULL);

	if (INVALID_HANDLE_VALUE == hFile) {
		dwStatus = GetLastError();
		wprintf(L"**** Error 0x%x returned by CreateFileA\n", dwStatus);
		return STATUS_UNSUCCESSFUL;
	}

	ntStatus = HashFileContent(hFile, pHashObject);
	CloseHandle(hFile);

	if (!NT_SUCCESS(ntStatus)) {
		wprintf(L"**** Error 0x%x returned by HashFileContent\n", ntStatus);
	}

	return ntStatus;
}

NTSTATUS SignFileA(PSignObject pSObject, PHashObject pHashObject, LPCSTR szFileName, PVOID lpPaddingInfo, DWORD dwPaddingFlags)
{
	if (!pSObject || !pHashObject || !szFileName)
		return STATUS_INVALID_PARAMETER;

	NTSTATUS ntStatus = 0;

	if (!NT_SUCCESS(ntStatus = HashFileA(pHashObject, szFileName))) {
		wprintf(L"**** Error 0x%x returned by HashFileA\n", ntStatus);
		return ntStatus;
	}

	if (!NT_SUCCESS(ntStatus = SignHash(pSObject, pHashObject->pbHash, pHashObject->cbHash, lpPaddingInfo, dwPaddingFlags))) {
		wprintf(L"**** Error 0x%x returned by SignHash\n", ntStatus);
		return ntStatus;
	}
	return 0;
}

NTSTATUS HashFileContent(HANDLE hFile, PHashObject pHashObject) {
	NTSTATUS ntStatus = 0;
	BOOL boolResult = FALSE;
	DWORD dwStatus = 0, cbRead = 0;

	BYTE buffer[BUFSIZE] = { 0 };


	if (INVALID_HANDLE_VALUE == hFile || !pHashObject)
	{
		return STATUS_INVALID_PARAMETER;
	}


	// hash content of file via buffer & cycle
	while (boolResult = ReadFile(hFile, buffer, BUFSIZE - 1,
		&cbRead, NULL))
	{
		if (0 == cbRead)
		{
			break;
		}

		if (!NT_SUCCESS(ntStatus = UpdateHashObject(pHashObject, (PBYTE)buffer, cbRead))) {
			wprintf(L"**** Error 0x%x returned by UpdateHashObject\n", ntStatus);
			return ntStatus;
		}

	}

	if (!boolResult)
	{
		dwStatus = GetLastError();
		wprintf(L"**** Error 0x%x returned by ReadFile\n", dwStatus);
		return STATUS_UNSUCCESSFUL;
	}
	FinalizeHashObject(pHashObject);
	return 0;
}

NTSTATUS HashDirectoryA(LPCSTR lpRoot, PHashObject pHashObject, BOOL boolRecursive) {

	if (!lpRoot || !pHashObject)
		return STATUS_INVALID_PARAMETER;

	NTSTATUS ntStatus = 0;
	DWORD dwLen = 0, dwDgstLen = 0;
	CHAR buffer[MAX_PATH] = { 0 };
	HANDLE hFind = INVALID_HANDLE_VALUE;
	WIN32_FIND_DATAA FindDataA;
	BOOL boolFilesExist = FALSE;
	PBYTE pbDgst = (BYTE*)calloc(pHashObject->cbHash, 1);
	if (!pbDgst) {
		wprintf(L"**** memory allocation failed\n");
		return STATUS_NO_MEMORY;
	}
	dwDgstLen = pHashObject->cbHash;

	LPCSTR lpPattern = "*";
	// Write to buffer pattern symbols 
	// for the FindFirstFile function
	snprintf(buffer, MAX_PATH - 1, "%s\\%s", lpRoot, lpPattern);

	hFind = FindFirstFileA(buffer, &FindDataA);
	if (hFind != INVALID_HANDLE_VALUE) {

		do
		{
			// Check if it is symbol link
			if ((FindDataA.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != FILE_ATTRIBUTE_REPARSE_POINT) {

				// Check if it is directory 
				if ((FindDataA.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) == FILE_ATTRIBUTE_DIRECTORY) {

					// Check if it is not current directory or
					// directory, that located upper than current directory and
					// check if we need to calculate hash recursively
					if (strcmp(FindDataA.cFileName, ".") && strcmp(FindDataA.cFileName, "..") &&
						boolRecursive) {

						dwLen = strlen(buffer);
						strncat_s(buffer, MAX_PATH, "\\", MAX_PATH - dwLen);
						strncat_s(buffer, MAX_PATH, FindDataA.cFileName, MAX_PATH - dwLen - 1);

						// Now calculate hash of directrory
						ntStatus = HashDirectoryA(buffer, pHashObject, TRUE);
						if (!NT_SUCCESS(ntStatus)) {
							wprintf(L"**** Error 0x%x returned by HashDirectoryA\n", ntStatus);
							FindClose(hFind);
							free(pbDgst);
							return ntStatus;
						}

						for (DWORD i = 0; i < dwDgstLen; i++)
						{
							pbDgst[i] ^= pHashObject->pbHash[i];
						}


					}
				}
				else {

					// We find a file, so calculate file hash
					boolFilesExist = TRUE;

					// Firstly, build path to file
					memset(buffer, 0, MAX_PATH);
					snprintf(buffer, MAX_PATH - 1, "%s\\%s", lpRoot, FindDataA.cFileName);

					// Now calculate hash of file
					ntStatus = HashFileA(pHashObject, buffer);
					if (!NT_SUCCESS(ntStatus)) {
						wprintf(L"**** Error 0x%x returned by HashFileA\n", ntStatus);
						FindClose(hFind);
						free(pbDgst);
						return ntStatus;
					}

					for (DWORD i = 0; i < dwDgstLen; i++)
					{
						pbDgst[i] ^= pHashObject->pbHash[i];
					}

				}
			}

		} while (FindNextFileA(hFind, &FindDataA));
		FindClose(hFind);
	}
	// If we don't have any files -> do FinalizeHashObject.
	// There, in fact, we calculate Hash(e) where e - empty string
	if (!boolFilesExist) {
		ntStatus = FinalizeHashObject(pHashObject);
		if (!NT_SUCCESS(ntStatus)) {
			wprintf(L"**** Error 0x%x returned by FinalizeHashObject\n", ntStatus);
			free(pbDgst);
			return ntStatus;
		}
	}
	else {
		// After last hash calculating we do FinalizeHashObject operation,
		// therefore input data buffer for hashing is empty. 
		// Call UpdateHashObject to put into it pbDgst data.
		ntStatus = UpdateHashObject(pHashObject, pbDgst, dwDgstLen);
		if (!NT_SUCCESS(ntStatus)) {
			wprintf(L"**** Error 0x%x returned by FinalizeHashObject\n", ntStatus);
			free(pbDgst);
			return ntStatus;
		}

		ntStatus = FinalizeHashObject(pHashObject);
		if (!NT_SUCCESS(ntStatus)) {
			wprintf(L"**** Error 0x%x returned by FinalizeHashObject\n", ntStatus);
			free(pbDgst);
			return ntStatus;
		}
	}
	free(pbDgst);
	return 0;
}

NTSTATUS ExportSignKeyToFileA(PSignObject pSObject,LPCWSTR lpBlobType,LPCSTR szPath, DWORD dwEncodingFlags) {

	PBYTE pbBlob = NULL;
	DWORD cbBlob = 0, dwStatus = 0, cchString = 0, cbResult = 0;
	LPSTR lpString = NULL;
	LPVOID lpResult = NULL;
	NTSTATUS ntStatus = 0;
	BOOL boolResult = FALSE;

	// First of all copy key
	// to blob array
	ntStatus = ExportSignKey(pSObject, lpBlobType, &cbBlob, &pbBlob);
	if (!NT_SUCCESS(ntStatus)) {
		wprintf(L"**** Error 0x%x returned by ExportSignKey\n", ntStatus);
		free(pbBlob);
		return ntStatus;
	}

	// If we want to encode key use respective flags
	if (dwEncodingFlags != DO_NOT_USE_ENCODING) {
		boolResult = EncodeBytes(pbBlob, cbBlob, dwEncodingFlags, &lpString, &cchString);
		if (!boolResult) {
			dwStatus = GetLastError();
			wprintf(L"**** Error 0x%x returned by EncodeBytes\n", dwStatus);
			free(pbBlob);
			free(lpString);
			return STATUS_UNSUCCESSFUL;
		}
		free(pbBlob);
		lpResult = (LPVOID)lpString;
		cbResult = cchString;
	}
	else {
		lpResult = (LPVOID)pbBlob;
		cbResult = cbBlob;
	}


	// Check file existence
	if (!PathFileExistsA(szPath)) {
		printf("**** Error: file with path %s doesn't exist\n", szPath);
		free(lpResult);
		return STATUS_INVALID_PARAMETER;
	}

	// Write Blob to file
	dwStatus = WriteBlobToFileA(szPath, (PBYTE)lpResult, cbResult);

	free(lpResult);
	
	if (dwStatus) {
		wprintf(L"**** Error 0x%x returned by WriteBlobToFileA\n", dwStatus);
		return STATUS_UNSUCCESSFUL;
	}
	return 0;
}

NTSTATUS ImportSignKeyFromFileA(PSignObject pSObject, LPCWSTR lpBlobType, LPCSTR szPath, DWORD dwDecodingFlags) {
	PBYTE pbBlob = NULL;
	DWORD cbBlob = 0, dwStatus = 0, cchString = 0, cbResult = 0;
	LPSTR lpString = NULL;
	PBYTE lpResult = NULL;
	NTSTATUS ntStatus = 0;
	BOOL boolResult = FALSE;

	// Check params
	if (!pSObject || !szPath)
		return STATUS_INVALID_PARAMETER;

	// Check file existence
	if (!PathFileExistsA(szPath)) {
		printf("**** Error: file with path %s doesn't exist\n", szPath);
		return STATUS_INVALID_PARAMETER;
	}

	dwStatus = ReadBlobFromFileA(szPath, (PBYTE*)&lpString, &cchString);
	if (dwStatus) {
		wprintf(L"**** Error 0x%x returned by ReadBlobFromFileA\n", dwStatus);
		return STATUS_UNSUCCESSFUL;
	}

	// We read whole string -> lets check
	// if we need to decode it
	if (dwDecodingFlags != DO_NOT_USE_DECODING) {
		boolResult = DecodeBytes(&pbBlob, &cbBlob, dwDecodingFlags, lpString);
		if (!boolResult) {
			dwStatus = GetLastError();
			wprintf(L"**** Error 0x%x returned by DecodeBytes\n", dwStatus);
			free(pbBlob);
			free(lpString);
			return STATUS_UNSUCCESSFUL;
		}
		free(lpString);
		lpResult = pbBlob;
		cbResult = cbBlob;
	}
	else {
		lpResult = (PBYTE)lpString;
		cbResult = cchString;
	}

	// Import result to sign structure
	ntStatus = ImportSignKey(pSObject, lpBlobType, cbResult, lpResult);
	if (!NT_SUCCESS(ntStatus)) {
		wprintf(L"**** Error 0x%x returned by ImportSignKey\n", ntStatus);
		free(lpResult);
		return ntStatus;
	}

	free(lpResult);
	return 0;
}

NTSTATUS SignDirectoryA(PSignObject pSObject, PHashObject pHashObject, LPCSTR szPath, BOOL boolRecursive, PVOID lpPaddingInfo, DWORD dwPaddingFlags) {
	if (!pSObject || !pHashObject || !szPath)
		return STATUS_INVALID_PARAMETER;

	NTSTATUS ntStatus = 0;

	if (!NT_SUCCESS(ntStatus = HashDirectoryA(szPath, pHashObject, boolRecursive))) {
		wprintf(L"**** Error 0x%x returned by HashDirectoryA\n", ntStatus);
		return ntStatus;
	}

	if (!NT_SUCCESS(ntStatus = SignHash(pSObject, pHashObject->pbHash, pHashObject->cbHash, lpPaddingInfo, dwPaddingFlags))) {
		wprintf(L"**** Error 0x%x returned by SignHash\n", ntStatus);
		return ntStatus;
	}
	return 0;
}

NTSTATUS ExportSymKeyToFileA(PCipherObject pCO, LPCWSTR lpBlobType, LPCSTR szPath, DWORD dwEncodingFlags) {
	PBYTE pbBlob = NULL;
	DWORD cbBlob = 0, dwStatus = 0, cchString = 0, cbResult = 0;
	LPSTR lpString = NULL;
	LPVOID lpResult = NULL;
	NTSTATUS ntStatus = 0;
	BOOL boolResult = FALSE;

	// First of all copy key
	// to blob array
	ntStatus = ExportSymKey(pCO, lpBlobType, &pbBlob, &cbBlob);
	if (!NT_SUCCESS(ntStatus)) {
		wprintf(L"**** Error 0x%x returned by ExportSignKey\n", ntStatus);
		free(pbBlob);
		return ntStatus;
	}

	// If we want to encode key use respective flags
	if (dwEncodingFlags != DO_NOT_USE_ENCODING) {
		boolResult = EncodeBytes(pbBlob, cbBlob, dwEncodingFlags, &lpString, &cchString);
		if (!boolResult) {
			dwStatus = GetLastError();
			wprintf(L"**** Error 0x%x returned by EncodeBytes\n", dwStatus);
			free(pbBlob);
			free(lpString);
			return STATUS_UNSUCCESSFUL;
		}
		free(pbBlob);
		lpResult = (LPVOID)lpString;
		cbResult = cchString;
	}
	else {
		lpResult = (LPVOID)pbBlob;
		cbResult = cbBlob;
	}


	// Check file existence
	if (!PathFileExistsA(szPath)) {
		printf("**** Error: file with path %s doesn't exist\n", szPath);
		free(lpResult);
		return STATUS_INVALID_PARAMETER;
	}

	// Write Blob to file
	dwStatus = WriteBlobToFileA(szPath, (PBYTE)lpResult, cbResult);

	free(lpResult);

	if (dwStatus) {
		wprintf(L"**** Error 0x%x returned by WriteBlobToFileA\n", dwStatus);
		return STATUS_UNSUCCESSFUL;
	}
	return 0;
}
NTSTATUS ImportSymKeyFromFileA(PCipherObject pCO, LPCWSTR lpBlobType, LPCSTR szPath, DWORD dwDecodingFlags) {
	PBYTE pbBlob = NULL;
	DWORD cbBlob = 0, dwStatus = 0, cchString = 0, cbResult = 0;
	LPSTR lpString = NULL;
	PBYTE lpResult = NULL;
	NTSTATUS ntStatus = 0;
	BOOL boolResult = FALSE;

	// Check params
	if (!pCO || !szPath)
		return STATUS_INVALID_PARAMETER;

	// Check file existence
	if (!PathFileExistsA(szPath)) {
		printf("**** Error: file with path %s doesn't exist\n", szPath);
		return STATUS_INVALID_PARAMETER;
	}

	dwStatus = ReadBlobFromFileA(szPath, (PBYTE*)&lpString, &cchString);
	if (dwStatus) {
		wprintf(L"**** Error 0x%x returned by ReadBlobFromFileA\n", dwStatus);
		return STATUS_UNSUCCESSFUL;
	}
	
	// We read whole string -> lets check
	// if we need to decode it
	if (dwDecodingFlags != DO_NOT_USE_DECODING) {
		boolResult = DecodeBytes(&pbBlob, &cbBlob, dwDecodingFlags, lpString);
		if (!boolResult) {
			dwStatus = GetLastError();
			wprintf(L"**** Error 0x%x in DecodeBytes\n", dwStatus);
			free(pbBlob);
			free(lpString);
			return STATUS_UNSUCCESSFUL;
		}
		free(lpString);
		lpResult = pbBlob;
		cbResult = cbBlob;
	}
	else {
		lpResult = (PBYTE)lpString;
		cbResult = cchString;
	}

	// Import result to cipher structure
	ntStatus = ImportSymKey(pCO, lpBlobType, lpResult, cbResult);
	if (!NT_SUCCESS(ntStatus)) {
		wprintf(L"**** Error 0x%x returned by ImportSymKey\n", ntStatus);
		free(lpResult);
		return ntStatus;
	}

	free(lpResult);
	return 0;
}

NTSTATUS EncryptFileA(PCipherObject pCO, LPCSTR szDataPath, PBYTE pbIV, PBYTE* ppbOut, PDWORD pcbOut, DWORD dwEncodingFlags) {
	DWORD cbOut = 0, cbOutStr = 0, cbResult = 0;
	NTSTATUS ntStatus = 0;
	BOOL boolResult = FALSE;
	DWORD dwStatus = 0, cbBlob = 0;
	PBYTE pbBlob = NULL,
		  pbOut = NULL,
	      pbResult = NULL;
	LPSTR lpOutStr = NULL;

	// Check params
	if (!pCO || !szDataPath || !ppbOut || !pcbOut)
		return STATUS_INVALID_PARAMETER;

	// Check file existence
	if (!PathFileExistsA(szDataPath)) {
		wprintf(L"**** Error: Input file path doesn't exist\n");
		return STATUS_INVALID_PARAMETER;
	}

	dwStatus = ReadBlobFromFileA(szDataPath, &pbBlob, &cbBlob);
	if (dwStatus) {
		wprintf(L"**** Error 0x%x returned by ReadBlobFromFileA\n", dwStatus);
		free(pbBlob);
		return STATUS_UNSUCCESSFUL;
	}
	ntStatus = Encrypt(pCO, pbBlob, cbBlob, &pbOut, &cbOut, pbIV);
	
	free(pbBlob);
	
	if (!NT_SUCCESS(ntStatus)) {
		wprintf(L"**** Error 0x%x returned by Encrypt\n", ntStatus);
		free(pbOut);
		return ntStatus;
	}

	// We read whole blob -> lets check
	// if we need to encode it
	if (dwEncodingFlags != DO_NOT_USE_ENCODING) {
		boolResult = EncodeBytes(pbOut, cbOut, dwEncodingFlags, &lpOutStr, &cbOutStr);
		if (!boolResult) {
			dwStatus = GetLastError();
			wprintf(L"**** Error 0x%x in EncodeBytes\n", dwStatus);
			free(pbOut);
			free(lpOutStr);
			return STATUS_UNSUCCESSFUL;
		}
		pbResult = (PBYTE)lpOutStr;
		cbResult = cbOutStr;
		free(pbOut);
	}
	else {
		pbResult = pbOut;
		cbResult = cbOut;
	}

	*ppbOut = pbResult;
	*pcbOut = cbResult;
	return ntStatus;
}

NTSTATUS DecryptFileA(PCipherObject pCO, LPCSTR szDataPath, PBYTE pbIV, PBYTE* ppbOut, PDWORD pcbOut, DWORD dwDecodingFlags) {
	DWORD cbOut = 0, cbDecoded = 0, cbResult = 0;
	NTSTATUS ntStatus = 0;
	BOOL boolResult = FALSE;
	DWORD dwStatus = 0, cbBlob = 0;
	PBYTE pbBlob = NULL,
		pbOut = NULL,
		pbDecoded = NULL;
	PBYTE pbResult = NULL;

	// Check params
	if (!pCO || !szDataPath || !ppbOut || !pcbOut)
		return STATUS_INVALID_PARAMETER;

	// Check file existence
	if (!PathFileExistsA(szDataPath)) {
		wprintf(L"**** Error: Input file path doesn't exist\n");
		return STATUS_INVALID_PARAMETER;
	}

	dwStatus = ReadBlobFromFileA(szDataPath, &pbBlob, &cbBlob);
	if (dwStatus) {
		wprintf(L"**** Error 0x%x returned by ReadBlobFromFileA\n", dwStatus);
		free(pbBlob);
		return STATUS_UNSUCCESSFUL;
	}

	// We read whole blob -> lets check
	// if we need to decode it
	if (dwDecodingFlags != DO_NOT_USE_DECODING) {
		boolResult = DecodeBytes(&pbDecoded, &cbDecoded, dwDecodingFlags, (LPCSTR)pbBlob);
		if (!boolResult) {
			dwStatus = GetLastError();
			wprintf(L"**** Error 0x%x in DecodeBytes\n", dwStatus);
			free(pbBlob);
			free(pbDecoded);
			return STATUS_UNSUCCESSFUL;
		}
		pbResult = (PBYTE)pbDecoded;
		cbResult = cbDecoded;
		free(pbBlob);
	}
	else {
		pbResult = pbBlob;
		cbResult = cbBlob;
	}

	ntStatus = Decrypt(pCO, pbResult, cbResult, &pbOut, &cbOut, pbIV);

	free(pbResult);

	if (!NT_SUCCESS(ntStatus)) {
		wprintf(L"**** Error 0x%x returned by Decrypt\n", ntStatus);
		free(pbOut);
		return ntStatus;
	}

	*ppbOut = pbOut;
	*pcbOut = cbOut;
	return ntStatus;
}

NTSTATUS EncryptFileByChunksA(PCipherObject pCO, LPCSTR szDataPath, LPCSTR szOutputPath, PBYTE pbIV) {
	HANDLE hInput = INVALID_HANDLE_VALUE, hOutput = INVALID_HANDLE_VALUE;
	DWORD dwStatus = 0;
	NTSTATUS ntStatus = 0;
	if (!pCO) {
		return STATUS_INVALID_PARAMETER;
	}
	if (!PathFileExistsA(szDataPath) || !PathFileExistsA(szOutputPath)) {
		printf("Given paths '%s' and '%s' doesn't exists\n", szDataPath, szOutputPath);
		return STATUS_INVALID_PARAMETER;
	}
	// Open file for reading
	hInput = CreateFileA(szDataPath,
		FILE_GENERIC_READ | FILE_GENERIC_WRITE,
		FILE_SHARE_WRITE | FILE_SHARE_READ,
		NULL, OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL, NULL);

	if (hInput == INVALID_HANDLE_VALUE) {
		dwStatus = GetLastError();
		wprintf(L"**** Error 0x%x in CreateFileA\n", dwStatus);
		return STATUS_UNSUCCESSFUL;
	}
	// Open file for writing
	hOutput = CreateFileA(szOutputPath,
		FILE_GENERIC_READ | FILE_GENERIC_WRITE,
		FILE_SHARE_WRITE | FILE_SHARE_READ,
		NULL, OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL, NULL);
	if (hOutput == INVALID_HANDLE_VALUE) {
		dwStatus = GetLastError();
		wprintf(L"**** Error 0x%x in CreateFileA\n", dwStatus);
		CloseHandle(hInput);
		return STATUS_UNSUCCESSFUL;
	}
	ntStatus = EncryptFileByChunksACore(pCO, hInput, hOutput, pbIV);
	CloseHandle(hInput);
	CloseHandle(hOutput);
	if (!NT_SUCCESS(ntStatus)) {
		wprintf(L"**** Error 0x%x returned by EncryptFileByChunksACore\n", ntStatus);
		return ntStatus;
	}
	return 0;
}

NTSTATUS EncryptFileByChunksACore(PCipherObject pCO, HANDLE hInput, HANDLE hOutput, PBYTE pbIV) {
	PBYTE pbBuffer = NULL, pbEncrypted = NULL;
	DWORD cbRead = 0, dwStatus = 0, cbEncrypted = 0, dwWrittenBytes = 0, cbPreviousRead = 0;
	PBYTE pbIVCopy = NULL;
	BOOL boolResult = FALSE, isFinish = FALSE;
	NTSTATUS ntStatus = 0;

	if (!pCO || hInput == INVALID_HANDLE_VALUE || hOutput == INVALID_HANDLE_VALUE)
		return STATUS_INVALID_PARAMETER;
	
	// Agreement
	cbPreviousRead = pCO->cbBlockLen;

	// When we use EncryptChunk it changes pbIV
	// therefore we should make copy of pbIV
	if (pbIV) {
		pbIVCopy = (PBYTE)calloc(pCO->cbBlockLen, 1);
		if (!pbIVCopy) {
			wprintf(L"**** memory allocation failed\n");
			return STATUS_NO_MEMORY;
		}
		memcpy_s(pbIVCopy, pCO->cbBlockLen, pbIV, pCO->cbBlockLen);
	}

	pbBuffer = (PBYTE)calloc(pCO->cbBlockLen + 1, 1); // 1 for terminating zero
	if (!pbBuffer) {
		wprintf(L"**** memory allocation failed\n");
		free(pbIVCopy);
		return STATUS_NO_MEMORY;
	}

	// Start reading file via buffer with fixed size
	while (boolResult = ReadFile(hInput, pbBuffer, pCO->cbBlockLen,
		&cbRead, NULL))
	{   
		// If earlier we read last portion and it wasn't block, therefore,
		// we have already made padding and written it to file,
		// therefore, make break 
		if (0 == cbRead && cbPreviousRead != pCO->cbBlockLen)
		{  
			break;
		}
		// If earlier we read last portion and it was block
		// we need to make padding for empty block and write it
		// to file. In this case  cbRead = 0 and cbPreviousRead = cbBlockLen
		
		cbPreviousRead = cbRead;
		if (cbRead < pCO->cbBlockLen) {
			ntStatus = PadPKCS7(pbBuffer, cbRead, pCO->cbBlockLen);
			if (!NT_SUCCESS(ntStatus)) {
				wprintf(L"**** Error 0x%x returned by PadPKCS7\n", ntStatus);
				free(pbIVCopy);
				free(pbBuffer);
				return ntStatus;
			}
			isFinish = TRUE;
		}
		ntStatus = EncryptChunk(pCO, pbBuffer, &pbEncrypted, &cbEncrypted, pbIVCopy);
		if (!NT_SUCCESS(ntStatus)) {
			wprintf(L"**** Error 0x%x returned by EncryptChunk\n", ntStatus);
			free(pbIVCopy);
			free(pbBuffer);
			free(pbEncrypted);
			return ntStatus;
		}
		
		// Write encrypted chunk to file
		boolResult = WriteFile(hOutput, pbEncrypted, cbEncrypted, &dwWrittenBytes, NULL);
		if (!boolResult || dwWrittenBytes != cbEncrypted) {
			dwStatus = GetLastError();
			wprintf(L"**** Error 0x%x in WriteFile\n", dwStatus);
			free(pbIVCopy);
			free(pbBuffer);
			free(pbEncrypted);
			return STATUS_UNSUCCESSFUL;
		}

		free(pbEncrypted);
		pbEncrypted = NULL;
		cbEncrypted = 0;

		if (isFinish) {
			break;
		}
		
	}
	free(pbIVCopy);
	free(pbBuffer);

	if (!boolResult)
	{
		dwStatus = GetLastError();
		wprintf(L"**** Error 0x%x returned by ReadFile\n", dwStatus);
		return STATUS_UNSUCCESSFUL;
	}

	return 0;
}

NTSTATUS DecryptFileByChunksA(PCipherObject pCO, LPCSTR szDataPath, LPCSTR szOutputPath, PBYTE pbIV) {
	HANDLE hInput = INVALID_HANDLE_VALUE, hOutput = INVALID_HANDLE_VALUE;
	DWORD dwStatus = 0;
	NTSTATUS ntStatus = 0;
	if (!pCO) {
		return STATUS_INVALID_PARAMETER;
	}
	if (!PathFileExistsA(szDataPath) || !PathFileExistsA(szOutputPath)) {
		return STATUS_INVALID_PARAMETER;
	}
	// Open file for reading
	hInput = CreateFileA(szDataPath,
		FILE_GENERIC_READ | FILE_GENERIC_WRITE,
		FILE_SHARE_WRITE | FILE_SHARE_READ,
		NULL, OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL, NULL);

	if (hInput == INVALID_HANDLE_VALUE) {
		dwStatus = GetLastError();
		wprintf(L"**** Error 0x%x in CreateFileA\n", dwStatus);
		return STATUS_UNSUCCESSFUL;
	}
	// Open file for writing
	hOutput = CreateFileA(szOutputPath,
		FILE_GENERIC_READ | FILE_GENERIC_WRITE,
		FILE_SHARE_WRITE | FILE_SHARE_READ,
		NULL, OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL, NULL);
	if (hOutput == INVALID_HANDLE_VALUE) {
		dwStatus = GetLastError();
		wprintf(L"**** Error 0x%x in CreateFileA\n", dwStatus);
		CloseHandle(hInput);
		return STATUS_UNSUCCESSFUL;
	}
	ntStatus = DecryptFileByChunksACore(pCO, hInput, hOutput, pbIV);
	CloseHandle(hInput);
	CloseHandle(hOutput);
	if (!NT_SUCCESS(ntStatus)) {
		wprintf(L"**** Error 0x%x returned by DecryptFileByChunksACore\n", ntStatus);
		return ntStatus;
	}
	return 0;
}

NTSTATUS DecryptFileByChunksACore(PCipherObject pCO, HANDLE hInput, HANDLE hOutput, PBYTE pbIV) {
	PBYTE pbBuffer = NULL, pbDecrypted = NULL;
	DWORD cbRead = 0, dwStatus = 0, cbDecrypted = 0, dwWrittenBytes = 0, cbPreviousRead = 0, cbFileSize = 0;
	PBYTE pbIVCopy = NULL;
	BOOL boolResult = FALSE, isFinish = FALSE;
	NTSTATUS ntStatus = 0;

	if (!pCO || hInput == INVALID_HANDLE_VALUE || hOutput == INVALID_HANDLE_VALUE)
		return STATUS_INVALID_PARAMETER;

	// Agreement
	cbPreviousRead = pCO->cbBlockLen;

	// Get file size for detecting last block
	cbFileSize = GetFileSize(hInput, 0);
	
	if (cbFileSize % pCO->cbBlockLen != 0) {
		wprintf(L"*** Error: wrong file size. It must be a multiple of 1 chunk size\n");
		return STATUS_INVALID_PARAMETER;
	}

	// When we use EncryptChunk it changes pbIV
	// therefore we should make copy of pbIV
	if (pbIV) {
		pbIVCopy = (PBYTE)calloc(pCO->cbBlockLen, 1);
		if (!pbIVCopy) {
			wprintf(L"**** memory allocation failed\n");
			return STATUS_NO_MEMORY;
		}
		memcpy_s(pbIVCopy, pCO->cbBlockLen, pbIV, pCO->cbBlockLen);
	}

	pbBuffer = (PBYTE)calloc(pCO->cbBlockLen + 1, 1); // 1 for terminating zero
	if (!pbBuffer) {
		wprintf(L"**** memory allocation failed\n");
		free(pbIVCopy);
		return STATUS_NO_MEMORY;
	}

	// Start reading file via buffer with fixed size
	while (boolResult = ReadFile(hInput, pbBuffer, pCO->cbBlockLen,
		&cbRead, NULL))
	{
		if (0 == cbRead)
		{
			break;
		}
		if (cbRead != pCO->cbBlockLen) {
			wprintf(L"*** Error: bad reading\n");
			free(pbIVCopy);
			free(pbBuffer);
			return STATUS_UNSUCCESSFUL;
		}
		// We read 1 block -> calculate rest bytes
		cbFileSize -= pCO->cbBlockLen;

		// Decrypt chunk
		ntStatus = DecryptChunk(pCO, pbBuffer, &pbDecrypted, &cbDecrypted, pbIVCopy);
		if (!NT_SUCCESS(ntStatus)) {
			wprintf(L"**** Error 0x%x returned by DecryptChunk\n", ntStatus);
			free(pbIVCopy);
			free(pbBuffer);
			free(pbDecrypted);
			return ntStatus;
		}
		
		// if it was last block -> remove padding
		if (cbFileSize == 0) {
			ntStatus = UnPadPKCS7(pbDecrypted, &cbDecrypted, pCO->cbBlockLen);
			if (!NT_SUCCESS(ntStatus)) {
				wprintf(L"**** Error 0x%x returned by UnPadPKCS7\n", ntStatus);
				free(pbIVCopy);
				free(pbBuffer);
				return ntStatus;
			}
			isFinish = TRUE;
		}

		// Write decrypted chunk to file
		boolResult = WriteFile(hOutput, pbDecrypted, cbDecrypted, &dwWrittenBytes, NULL);
		if (!boolResult || dwWrittenBytes != cbDecrypted) {
			dwStatus = GetLastError();
			wprintf(L"**** Error 0x%x in WriteFile\n", dwStatus);
			free(pbIVCopy);
			free(pbBuffer);
			free(pbDecrypted);
			return STATUS_UNSUCCESSFUL;
		}

		free(pbDecrypted);
		pbDecrypted = NULL;
		cbDecrypted = 0;

		if (isFinish) {
			break;
		}

	}
	free(pbIVCopy);
	free(pbBuffer);

	if (!boolResult)
	{
		dwStatus = GetLastError();
		wprintf(L"**** Error 0x%x returned by ReadFile\n", dwStatus);
		return STATUS_UNSUCCESSFUL;
	}
	return 0;
}