# pragma once
#include "apibase.hpp"
#include <bcrypt.h>


typedef struct HashObject {
    BCRYPT_ALG_HANDLE       hAlg = NULL;                      //handle to the algorithm object
    BCRYPT_HASH_HANDLE      hHash = NULL;                     //handle to the hash object            
    DWORD                   cbHashObject = 0;             //Size of the hash object
    DWORD                   cbHash = 0;                   //size of the hash itself
    PBYTE                   pbHashObject = NULL;              //buffer for the internal hash object
    PBYTE                   pbHash = NULL;                    //buffer for the hash itself
} HashObject, *PHashObject;

/**
  Funtion for initialize hash object via AlgorithmID and  AlgorithmProvider

  @param pHashObject - pointer to the target HashObject struct
*/
NTSTATUS InitHashObject(PHashObject pHashObject, LPCWSTR lpAlgorithmId, LPCWSTR lpAlgorithmProvider);
/**
 Function for hash update
 
 @param pHashObject - pointer to the HashObject struct
 @param pbData - input data
 @param cbData - input data size
*/
NTSTATUS UpdateHashObject(PHashObject pHashObject, PBYTE pbData, ULONG cbData);
/**
  Finish hash process and move hash value to pbHash buffer 
  @param pHashObject - pointer to the HashObject struct
*/
NTSTATUS FinalizeHashObject(PHashObject pHashObject);
/**
  Clear all fields in HashObject structure and zeroed them
  @param pHashObject - pointer to the target HashObject struct
*/
VOID ClearHashObject(PHashObject pHashObject);
