#include "cipher.hpp"

VOID ClearCipherObject(PCipherObject pCO) {
    if (pCO->hAlg)
    {
        BCryptCloseAlgorithmProvider(pCO->hAlg, 0);
    }

    if (pCO->hKey)
    {
        BCryptDestroyKey(pCO->hKey);
    }

    if (pCO->pbKeyObject)
    {
        HeapFree(GetProcessHeap(), 0, pCO->pbKeyObject);
    }

    pCO->hAlg = NULL;
    pCO->hKey = NULL;
    pCO->pbKeyObject = NULL;
    pCO->cbBlockLen = 0;
    pCO->cbKeyObject = 0;
}

NTSTATUS InitCipherObject(PCipherObject pCO, LPCWSTR lpBlockCipherMode, LPCWSTR lpAlgorithmId, LPCWSTR lpAlgorithmProvider) {
    NTSTATUS ntStatus = 0;
    DWORD cbData = 0;

    if (!pCO || !lpBlockCipherMode || !lpAlgorithmId)
        return STATUS_INVALID_PARAMETER;

    // Open an algorithm handle.
    if (!NT_SUCCESS(ntStatus = BCryptOpenAlgorithmProvider(
        &pCO->hAlg,
        lpAlgorithmId,
        lpAlgorithmProvider,
        0)))
    {
        wprintf(L"**** Error 0x%x returned by BCryptOpenAlgorithmProvider\n", ntStatus);
        ClearCipherObject(pCO);
        return ntStatus;
    }

    // Calculate the size of the buffer to hold the KeyObject.
    if (!NT_SUCCESS(ntStatus = BCryptGetProperty(
        pCO->hAlg,
        BCRYPT_OBJECT_LENGTH,
        (PBYTE)&pCO->cbKeyObject,
        sizeof(DWORD),
        &cbData,
        0)))
    {
        wprintf(L"**** Error 0x%x returned by BCryptGetProperty\n", ntStatus);
        ClearCipherObject(pCO);
        return ntStatus;
    }

    // Allocate the key object on the heap.
    pCO->pbKeyObject = (PBYTE)HeapAlloc(GetProcessHeap(), 0, pCO->cbKeyObject);
    if (NULL == pCO->pbKeyObject)
    {
        wprintf(L"**** memory allocation failed\n");
        ClearCipherObject(pCO);
        return STATUS_NO_MEMORY;
    }

    // Calculate the block length for the IV.
    if (!NT_SUCCESS(ntStatus = BCryptGetProperty(
        pCO->hAlg,
        BCRYPT_BLOCK_LENGTH,
        (PBYTE)&pCO->cbBlockLen,
        sizeof(DWORD),
        &cbData,
        0)))
    {
        wprintf(L"**** Error 0x%x returned by BCryptGetProperty\n", ntStatus);
        ClearCipherObject(pCO);
        return ntStatus;
    }

    // Set block cipher mode
    if (!NT_SUCCESS(ntStatus = BCryptSetProperty(
        pCO->hAlg,
        BCRYPT_CHAINING_MODE,
        (PBYTE)lpBlockCipherMode,
        sizeof(lpBlockCipherMode),
        0)))
    {
        wprintf(L"**** Error 0x%x returned by BCryptSetProperty\n", ntStatus);
        ClearCipherObject(pCO);
        return ntStatus;
    }

    return 0;
}

NTSTATUS GenerateSymKey(PCipherObject pCO, DWORD dwKeyLen) {
    PBYTE pbBuffer = NULL;
    NTSTATUS ntStatus = 0;

    if (!pCO || !dwKeyLen)
        return STATUS_INVALID_PARAMETER;

    pbBuffer = (PBYTE)calloc(dwKeyLen, 1);
    if (!pbBuffer) {
        wprintf(L"**** memory allocation failed\n");
        return STATUS_NO_MEMORY;
    }

    // Generate secret value
    ntStatus = BCryptGenRandom(BCRYPT_RNG_ALG_HANDLE, pbBuffer, dwKeyLen, 0);

    if (!NT_SUCCESS(ntStatus)) {
        free(pbBuffer);
        wprintf(L"**** Error 0x%x returned by BCryptGenRandom\n", ntStatus);
        return ntStatus;
    }
    // Create symmetric key for given secret
    ntStatus = BCryptGenerateSymmetricKey(pCO->hAlg, 
        &pCO->hKey,
        pCO->pbKeyObject,
        pCO->cbKeyObject, 
        pbBuffer,
        dwKeyLen,
        0);

    free(pbBuffer);
    
    if (!NT_SUCCESS(ntStatus)) {
        wprintf(L"**** Error 0x%x returned by BCryptGenRandom\n", ntStatus);
        return ntStatus;
    }
    return 0;
}

NTSTATUS Encrypt(PCipherObject pCO, PBYTE pbData, DWORD cbData, PBYTE* ppbOut, PDWORD pcbOut, PBYTE pbIV) {
    NTSTATUS ntStatus = 0;
    DWORD cbTmp = 0;
    PBYTE pbIVCopy = NULL, pbResult = NULL;

    if (!pCO || !pbData || !cbData || !ppbOut || !pcbOut)
        return STATUS_INVALID_PARAMETER;


    // When we use BCryptEncrypt it changes pbIV
    // therefore we should make copy of pbIV
    if (pbIV) {
        pbIVCopy = (PBYTE)calloc(pCO->cbBlockLen, 1);
        if (!pbIVCopy) {
            wprintf(L"**** memory allocation failed\n");
            return STATUS_NO_MEMORY;
        }
        memcpy_s(pbIVCopy, pCO->cbBlockLen, pbIV, pCO->cbBlockLen);
    }

    //
    // Get the output buffer size.
    //
    if (!NT_SUCCESS(ntStatus = BCryptEncrypt(
        pCO->hKey,
        pbData,
        cbData,
        NULL,
        pbIVCopy,
        pCO->cbBlockLen,
        NULL,
        0,
        &cbTmp,
        BCRYPT_BLOCK_PADDING)))
    {
        wprintf(L"**** Error 0x%x returned by BCryptEncrypt\n", ntStatus);
        free(pbIVCopy);
        return ntStatus;
    }

    if (cbTmp > *pcbOut) {
        pbResult = (PBYTE)realloc(*ppbOut, cbTmp);
        if (!pbResult) {
            wprintf(L"**** memory allocation failed\n");
            free(pbIVCopy);
            return STATUS_NO_MEMORY;
        }
        *ppbOut = pbResult;
        *pcbOut = cbTmp;
    }

    // Use the key to encrypt the plaintext buffer.
    // For block sized messages, block padding will add an extra block.
    if (!NT_SUCCESS(ntStatus = BCryptEncrypt(
        pCO->hKey,
        pbData,
        cbData,
        NULL,
        pbIVCopy,
        pCO->cbBlockLen,
        *ppbOut,
        *pcbOut,
        &cbTmp,
        BCRYPT_BLOCK_PADDING)))
    {
        wprintf(L"**** Error 0x%x returned by BCryptEncrypt\n", ntStatus);
        free(pbIVCopy);
        free(*ppbOut);
        return ntStatus;
    }
    *pcbOut = cbTmp;
    free(pbIVCopy);
    return 0;
}

NTSTATUS Decrypt(PCipherObject pCO, PBYTE pbData, DWORD cbData, PBYTE* ppbOut, PDWORD pcbOut, PBYTE pbIV) {
    NTSTATUS ntStatus = 0;
    DWORD cbTmp = 0;
    PBYTE pbIVCopy = NULL, pbResult = NULL;

    if (!pCO || !pbData || !cbData || !ppbOut || !pcbOut)
        return STATUS_INVALID_PARAMETER;


    // When we use BCryptDecrypt it changes pbIV
    // therefore we should make copy of pbIV
    if (pbIV) {
        pbIVCopy = (PBYTE)calloc(pCO->cbBlockLen, 1);
        if (!pbIVCopy) {
            wprintf(L"**** memory allocation failed\n");
            return STATUS_NO_MEMORY;
        }
        memcpy_s(pbIVCopy, pCO->cbBlockLen, pbIV, pCO->cbBlockLen);
    }

    //
    // Get the output buffer size.
    //
    if (!NT_SUCCESS(ntStatus = BCryptDecrypt(
        pCO->hKey,
        pbData,
        cbData,
        NULL,
        pbIVCopy,
        pCO->cbBlockLen,
        NULL,
        0,
        &cbTmp,
        BCRYPT_BLOCK_PADDING)))
    {
        wprintf(L"**** Error 0x%x returned by BCryptDecrypt\n", ntStatus);
        free(pbIVCopy);
        return ntStatus;
    }

    if (cbTmp > *pcbOut) {
        pbResult = (PBYTE)realloc(*ppbOut, cbTmp);
        if (!pbResult) {
            wprintf(L"**** memory allocation failed\n");
            free(pbIVCopy);
            return STATUS_NO_MEMORY;
        }
        *ppbOut = pbResult;
        *pcbOut = cbTmp;
    }

    // Use the key to decrypt the ciphertext buffer.
    // For block sized messages, block padding will add an extra block.
    if (!NT_SUCCESS(ntStatus = BCryptDecrypt(
        pCO->hKey,
        pbData,
        cbData,
        NULL,
        pbIVCopy,
        pCO->cbBlockLen,
        *ppbOut,
        *pcbOut,
        &cbTmp,
        BCRYPT_BLOCK_PADDING)))
    {
        wprintf(L"**** Error 0x%x returned by BCryptDecrypt\n", ntStatus);
        free(pbIVCopy);
        free(*ppbOut);
        return ntStatus;
    }
    *pcbOut = cbTmp;
    free(pbIVCopy);
    return 0;
}

NTSTATUS EncryptChunk(PCipherObject pCO, PBYTE pbData, PBYTE* ppbOut, PDWORD pcbOut, PBYTE pbIV) {
    NTSTATUS ntStatus = 0;
    DWORD cbTmp = 0;
    PBYTE pbResult = NULL;

    if (!pCO || !pbData || !ppbOut || !pcbOut)
        return STATUS_INVALID_PARAMETER;

    //
    // Get the output buffer size.
    // There we assume that input data has len = 1 block size
    if (!NT_SUCCESS(ntStatus = BCryptEncrypt(
        pCO->hKey,
        pbData,
        pCO->cbBlockLen,
        NULL,
        pbIV,
        pCO->cbBlockLen,
        NULL,
        0,
        &cbTmp,
        0)))
    {
        wprintf(L"**** Error 0x%x returned by BCryptEncrypt\n", ntStatus);
        return ntStatus;
    }

    if (cbTmp > *pcbOut) {
        pbResult = (PBYTE)realloc(*ppbOut, cbTmp);
        if (!pbResult) {
            wprintf(L"**** memory allocation failed\n");
            return STATUS_NO_MEMORY;
        }
        *ppbOut = pbResult;
        *pcbOut = cbTmp;
    }

    // Use the key to encrypt the plaintext buffer.
    // For block sized messages, block padding will add an extra block.
    if (!NT_SUCCESS(ntStatus = BCryptEncrypt(
        pCO->hKey,
        pbData,
        pCO->cbBlockLen,
        NULL,
        pbIV,
        pCO->cbBlockLen,
        *ppbOut,
        *pcbOut,
        &cbTmp,
        0)))
    {
        wprintf(L"**** Error 0x%x returned by BCryptEncrypt\n", ntStatus);
        free(*ppbOut);
        return ntStatus;
    }
    return 0;
}

NTSTATUS DecryptChunk(PCipherObject pCO, PBYTE pbData, PBYTE* ppbOut, PDWORD pcbOut, PBYTE pbIV) {

    NTSTATUS ntStatus = 0;
    DWORD cbTmp = 0;
    PBYTE pbResult = NULL;

    if (!pCO || !pbData || !ppbOut || !pcbOut)
        return STATUS_INVALID_PARAMETER;

    //
    // Get the output buffer size.
    // There we assume that input data has len = 1 block size
    if (!NT_SUCCESS(ntStatus = BCryptDecrypt(
        pCO->hKey,
        pbData,
        pCO->cbBlockLen,
        NULL,
        pbIV,
        pCO->cbBlockLen,
        NULL,
        0,
        &cbTmp,
        0)))
    {
        wprintf(L"**** Error 0x%x returned by BCryptEncrypt\n", ntStatus);
        return ntStatus;
    }

    if (cbTmp > *pcbOut) {
        pbResult = (PBYTE)realloc(*ppbOut, cbTmp);
        if (!pbResult) {
            wprintf(L"**** memory allocation failed\n");
            return STATUS_NO_MEMORY;
        }
        *ppbOut = pbResult;
        *pcbOut = cbTmp;
    }

    // Use the key to decrypt the ciphertext chunk.
    if (!NT_SUCCESS(ntStatus = BCryptDecrypt(
        pCO->hKey,
        pbData,
        pCO->cbBlockLen,
        NULL,
        pbIV,
        pCO->cbBlockLen,
        *ppbOut,
        *pcbOut,
        &cbTmp,
        0)))
    {
        wprintf(L"**** Error 0x%x returned by BCryptEncrypt\n", ntStatus);
        free(*ppbOut);
        return ntStatus;
    }
    return 0;
}


NTSTATUS ExportSymKey(PCipherObject pCO, LPCWSTR pszBlobType, PBYTE *ppbBlob, PDWORD pcbBlob) {
    SECURITY_STATUS secStatus = ERROR_SUCCESS;
    ULONG ulBlobLen = 0;
    if (!pCO)
        return STATUS_INVALID_PARAMETER;

    if (FAILED(secStatus = BCryptExportKey(
        pCO->hKey,
        NULL,
        pszBlobType,
        NULL,
        NULL,
        &ulBlobLen,
        0)))
    {
        wprintf(L"**** Error 0x%x returned by BCryptExportKey\n", secStatus);
        return STATUS_UNSUCCESSFUL;
    }

    if (ulBlobLen > *pcbBlob) {
        PBYTE pbResult = (PBYTE)realloc(*ppbBlob, ulBlobLen);
        if (!pbResult) {
            wprintf(L"**** memory allocation failed\n");
            return STATUS_NO_MEMORY;
        }
        *ppbBlob = pbResult;
        *pcbBlob = ulBlobLen;
    }

    if (FAILED(secStatus = BCryptExportKey(
        pCO->hKey,
        NULL,
        pszBlobType,
        *ppbBlob,
        *pcbBlob,
        pcbBlob,
        0)))
    {
        wprintf(L"**** Error 0x%x returned by BCryptExportKey\n", secStatus);
        return STATUS_UNSUCCESSFUL;
    }
    return 0;
}

NTSTATUS ImportSymKey(PCipherObject pCO, LPCWSTR pszBlobType, PBYTE pbBlob, DWORD cbBlob) {
    if (!pCO)
        return STATUS_INVALID_PARAMETER;

    SECURITY_STATUS secStatus = ERROR_SUCCESS;

    if (FAILED(secStatus = BCryptImportKey(pCO->hAlg,
        NULL,
        pszBlobType,
        &pCO->hKey,
        pCO->pbKeyObject,
        pCO->cbKeyObject,
        pbBlob,
        cbBlob,
        0))) {
        wprintf(L"**** Error 0x%x returned by BCryptImportKey\n", secStatus);
        return STATUS_UNSUCCESSFUL;
    }

    return 0;
}

NTSTATUS PadPKCS7(PBYTE pbData, DWORD cbData, DWORD dwBlockLen) {
    USHORT usPadValue = 0;
    if (!pbData || !dwBlockLen)
        return STATUS_INVALID_PARAMETER;

    // Calculate padding value
    usPadValue = dwBlockLen - (cbData % dwBlockLen);

    memset(&pbData[cbData], usPadValue, usPadValue);
    return 0;
}
NTSTATUS UnPadPKCS7(PBYTE pbData, PDWORD pcbData, DWORD dwBlockLen) {
    USHORT usPadValue = 0;
    if (!pbData || !dwBlockLen || !pcbData)
        return STATUS_INVALID_PARAMETER;

    if ((*pcbData) % dwBlockLen != 0 || !*pcbData) {
        return STATUS_INVALID_PARAMETER;
    }

    // Assume that padding is correct
    // and last byte equals padding value
    usPadValue = pbData[*pcbData - 1];
    
    if (*pcbData - usPadValue < 0) {
        wprintf(L"*** Error: wrong padding\n");
        return STATUS_INVALID_PARAMETER;
    }
    // Check our assumption
    for (DWORD i = *pcbData - 2; i >= *pcbData - usPadValue; i--)
    {
        if (pbData[i] != usPadValue) {
            wprintf(L"*** Error: wrong padding\n");
            return STATUS_INVALID_PARAMETER;
        }
    }

    // Remove padding
    memset(&pbData[*pcbData - usPadValue], 0, usPadValue);
    *pcbData -= usPadValue;
    return 0;
}