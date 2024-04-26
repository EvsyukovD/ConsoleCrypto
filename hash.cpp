#include "hash.hpp"


VOID ClearHashObject(PHashObject pHashObject) 
{   
    if (!pHashObject)
        return;

    if (pHashObject->hAlg != NULL)
        BCryptCloseAlgorithmProvider(pHashObject->hAlg, 0);
    if (pHashObject->hHash != NULL)
        BCryptDestroyHash(pHashObject->hHash);
    if (pHashObject->pbHashObject)
        HeapFree(GetProcessHeap(), 0, pHashObject->pbHashObject);
    if (pHashObject->pbHash)
        free(pHashObject->pbHash);

    pHashObject->cbHash = 0;
    pHashObject->cbHashObject = 0;
    pHashObject->hAlg = NULL;
    pHashObject->pbHash = NULL;
    pHashObject->pbHashObject = NULL;
}


NTSTATUS InitHashObject(PHashObject pHashObject, LPCWSTR lpAlgorithmId, LPCWSTR lpAlgorithmProvider)
{
	DWORD cbData = 0;

    NTSTATUS status;
    
    if (!pHashObject) {
        status = STATUS_INVALID_PARAMETER;
        wprintf(L"**** Error 0x%x returned by InitHashObject\n", status);
        return status;
    }

    //open an algorithm handle and load the algorithm provider
    if (!NT_SUCCESS(status = BCryptOpenAlgorithmProvider(
        &pHashObject->hAlg, lpAlgorithmId, lpAlgorithmProvider, 0))) {
        wprintf(L"**** Error 0x%x returned by BCryptOpenAlgorithmProvider\n", status);
        return status;
    }

    //calculate the size of the buffer to hold the hash object
    if (!NT_SUCCESS(status = BCryptGetProperty(
        pHashObject->hAlg,
        BCRYPT_OBJECT_LENGTH,
        (PBYTE)&pHashObject->cbHashObject,
        sizeof(DWORD),
        &cbData,
        0)))
    {
        ClearHashObject(pHashObject);
        wprintf(L"**** Error 0x%x returned by BCryptGetProperty\n", status);
        return status;
    }

    //allocate the hash object on the heap
    pHashObject->pbHashObject = (PBYTE)HeapAlloc(GetProcessHeap(), 0, pHashObject->cbHashObject);
    if (NULL == pHashObject->pbHashObject)
    {
        wprintf(L"**** memory allocation failed\n");
        ClearHashObject(pHashObject);
        status = STATUS_NO_MEMORY;
        return status;
    }

    //calculate the length of the hash
    if (!NT_SUCCESS(status = BCryptGetProperty(
        pHashObject->hAlg,
        BCRYPT_HASH_LENGTH,
        (PBYTE)&pHashObject->cbHash,
        sizeof(DWORD),
        &cbData,
        0)))
    {
        wprintf(L"**** Error 0x%x returned by BCryptGetProperty\n", status);
        ClearHashObject(pHashObject);
        return status;
    }

    //allocate the hash buffer on the heap
    pHashObject->pbHash = (PBYTE)calloc(pHashObject->cbHash, 1);
    if (NULL == pHashObject->pbHash)
    {
        wprintf(L"**** memory allocation failed\n");
        ClearHashObject(pHashObject);
        status = STATUS_NO_MEMORY;
        return status;
    }

    //create a hash
    if (!NT_SUCCESS(status = BCryptCreateHash(
        pHashObject->hAlg,
        &pHashObject->hHash,
        pHashObject->pbHashObject,
        pHashObject->cbHashObject,
        NULL,
        0,
        BCRYPT_HASH_REUSABLE_FLAG)))
    {
        wprintf(L"**** Error 0x%x returned by BCryptCreateHash\n", status);
        ClearHashObject(pHashObject);
        return status;
    }

    return 0;
}

NTSTATUS UpdateHashObject(PHashObject pHashObject, PBYTE pbData, ULONG cbData) 
{
    NTSTATUS status;
    if (!pHashObject) {
        status = STATUS_INVALID_PARAMETER;
        wprintf(L"**** Error 0x%x returned by UpdateHashObject\n", status);
        return status;
    }

    if (cbData < 0)
        return STATUS_INVALID_PARAMETER;
    
    // If size of input data is 0 - do nothing
    //if (!cbData)
        //return 0;

    status = BCryptHashData(pHashObject->hHash, pbData, cbData, 0);
    return status;
}

NTSTATUS FinalizeHashObject(PHashObject pHashObject) 
{
    NTSTATUS status;
    if (!pHashObject) {
        status = STATUS_INVALID_PARAMETER;
        wprintf(L"**** Error 0x%x returned by FinalizeHashObject\n", status);
        return status;
    }

    status = BCryptFinishHash(
        pHashObject->hHash, pHashObject->pbHash, pHashObject->cbHash, 0);

    return status;
}