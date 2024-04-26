#pragma once
#include "crypto.hpp"
#include <iostream>
#include <map>

NTSTATUS ArgParse(int argc,const char* argv[], std::map<std::string, std::string>& params);

NTSTATUS HashArgs(std::map<std::string, std::string>& params);

NTSTATUS SignArgs(std::map<std::string, std::string>& params);

NTSTATUS VerifyArgs(std::map<std::string, std::string>& params);

NTSTATUS EncryptChunksArgs(std::map<std::string, std::string>& params);

NTSTATUS DecryptChunksArgs(std::map<std::string, std::string>& params);

BOOL isSingleOption(const char* option);

BOOL isOption(const char* s);

LPCWSTR ConvertStrToMode(const std::string& mode);

LPCWSTR ConvertAlgorithmToId(const std::string& algoName);

VOID PrintHelpMessage();

DWORD GetCodingFlags(const std::string& codingName);