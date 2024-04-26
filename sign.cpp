#include "sign.hpp"

VOID ClearSign(PSignObject pSObject) {
    if (!pSObject)
        return;

    if (pSObject->hSignAlg)
    {
        BCryptCloseAlgorithmProvider(pSObject->hSignAlg, 0);
    }

    if (pSObject->pbSignature)
    {
        free(pSObject->pbSignature);
    }

    if (pSObject->hKey)
    {
        BCryptDestroyKey(pSObject->hKey);
    }
    

    pSObject->cbSignature = 0;
    pSObject->hKey = NULL;
    pSObject->hSignAlg = NULL;
    pSObject->pbSignature = NULL;
}


NTSTATUS InitSign(PSignObject pSObject, LPCWSTR lpAlgorithmID, LPCWSTR lpAlgorithmProvider) {
    NTSTATUS status;

    if (!pSObject)
        return STATUS_INVALID_PARAMETER;

    if (!NT_SUCCESS(status = BCryptOpenAlgorithmProvider(
        &pSObject->hSignAlg,
        lpAlgorithmID,
        lpAlgorithmProvider,
        0)))
    {
        wprintf(L"**** Error 0x%x returned by BCryptOpenAlgorithmProvider\n", status);
        ClearSign(pSObject);
        return status;
    }
    return 0;
}

NTSTATUS CreateSignKey(PSignObject pSObject, DWORD dwKeyLen) {
    SECURITY_STATUS secStatus = ERROR_SUCCESS;

    if (!pSObject)
        return STATUS_INVALID_PARAMETER;

    //Generate key pair
    secStatus = BCryptGenerateKeyPair(pSObject->hSignAlg, &pSObject->hKey, dwKeyLen, 0);
    if (FAILED(secStatus)) {
        wprintf(L"**** Error 0x%x returned by BCryptGenerateKeyPair\n", secStatus);
        ClearSign(pSObject);
        return STATUS_UNSUCCESSFUL;
    }

    //create key on disk
    if (FAILED(secStatus = BCryptFinalizeKeyPair(pSObject->hKey, 0)))
    {
        wprintf(L"**** Error 0x%x returned by BCryptFinalizeKeyPair\n", secStatus);
        return STATUS_UNSUCCESSFUL;
    }
    return 0;
}

NTSTATUS SignHash(PSignObject pSObject, PBYTE pbHash, DWORD cbHash, PVOID lpPaddingInfo, DWORD dwPaddingFlags) {
    SECURITY_STATUS secStatus = ERROR_SUCCESS;
    DWORD cbSign = 0;

    if (!pSObject)
        return STATUS_INVALID_PARAMETER;

    //get signature size
    if (FAILED(secStatus = BCryptSignHash(
        pSObject->hKey,
        lpPaddingInfo,
        pbHash,
        cbHash,
        NULL,
        0,
        &cbSign,
        dwPaddingFlags)))
    {
        wprintf(L"**** Error 0x%x returned by NCryptSignHash\n", secStatus);
        return STATUS_UNSUCCESSFUL;
    }
    
    if (pSObject->pbSignature)
        free(pSObject->pbSignature);

    //allocate the signature buffer
    pSObject->pbSignature = (PBYTE)calloc(cbSign, 1);
    if (NULL == pSObject->pbSignature)
    {
        wprintf(L"**** memory allocation failed\n");
        return STATUS_NO_MEMORY;
    }
    
    pSObject->cbSignature = cbSign;

    // sign hash
    if (FAILED(secStatus = BCryptSignHash(
        pSObject->hKey,
        lpPaddingInfo,
        pbHash,
        cbHash,
        pSObject->pbSignature,
        pSObject->cbSignature,
        &pSObject->cbSignature,
        dwPaddingFlags)))
    {
        wprintf(L"**** Error 0x%x returned by BCryptSignHash\n", secStatus);
        return STATUS_UNSUCCESSFUL;
    }
    return 0;
}

NTSTATUS ExportSignKey(PSignObject pSObject, LPCWSTR pszBlobType, PDWORD pcbBlob, PBYTE* ppbBlob) {
    SECURITY_STATUS secStatus = ERROR_SUCCESS;
    ULONG ulBlobLen = 0;
    if (!pSObject)
        return STATUS_INVALID_PARAMETER;

    if (FAILED(secStatus = BCryptExportKey(
        pSObject->hKey,
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
        pSObject->hKey,
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

NTSTATUS ImportSignKey(PSignObject pSObject, LPCWSTR pszBlobType, DWORD cbBlob, PBYTE pbBlob) {
    if (!pSObject)
        return STATUS_INVALID_PARAMETER;

    SECURITY_STATUS secStatus = ERROR_SUCCESS;

    if (FAILED(secStatus = BCryptImportKeyPair(pSObject->hSignAlg, 
        NULL,
        pszBlobType,
        &pSObject->hKey, 
        pbBlob, 
        cbBlob, 
        0))) {
        wprintf(L"**** Error 0x%x returned by BCryptImportKeyPair\n", secStatus);
        return STATUS_UNSUCCESSFUL;
    }

    return 0;
}

NTSTATUS VerifyHashSign(PSignObject pSObject, PBYTE pbHash, DWORD cbHash, PVOID lpPaddingInfo, DWORD dwPaddingFlags) {
    if (!pSObject)
        return STATUS_INVALID_PARAMETER;

    SECURITY_STATUS secStatus = ERROR_SUCCESS;

    if (FAILED(secStatus = BCryptVerifySignature(pSObject->hKey,
        lpPaddingInfo,
        pbHash,
        cbHash,
        pSObject->pbSignature,
        pSObject->cbSignature,
        dwPaddingFlags))) {
        wprintf(L"**** Error 0x%x returned by BCryptVerifySignature\n", secStatus);
        return secStatus;
    }
    return 0;
}
