#include "apiservs.hpp"

// Feature's params
#define ENC std::string("encrypt")
#define DEC std::string("decrypt")
#define HASH std::string("hash")
#define SIG std::string("sign")
#define VER std::string("verify")
#define HELP std::string("-h, --help")
// Almost common options
#define INPUT_DATA std::string("-i") // positional for all. Input data path [file or directory]
#define OUTPUT_DATA std::string("-o") // positional for ciphering and optional for others. Output data path
#define CODING std::string("-c") // optional for all. Encoding or decoding param

// Specific
#define KEY_CODING std::string("-kc") // optional for  encryption & decryption & verify & sign. Key coding param
#define ALGO std::string("-alg") // positional for encryption & decryption & hash. Algorithm name
#define PUBKEY std::string("-pubk") // positional for sign & verifying. Export or import pub key to or from file
#define OBJECT_TYPE std::string("-t") // positional for hash & sign & verify. Type of object
#define HASH_ALGO std::string("-halg") // positional for verifying & sign. Hash algorithm name
#define SIGN_ALGO std::string("-salg") // positional for verifying & sign. Sign algorithm name
#define SYMKEY std::string("-k") // optional for encryption and positional for decryption. Import key for encryption or decryption
#define GENKEY std::string("-g") // optional for encryption. Generate key and write it to specific file
#define MODE std::string("-m") // positional for encryption & decryption
#define IV std::string("-iv")// optional for encryption & decryption.
#define IV_CODING std::string("-ivc") // optional for encryption & decryption. IV coding
#define SIGN std::string("-s") // positional for verify. Path to signature
// Single options
#define RECURSIVE std::string("-r") // optional for sign & hash & verify. Recursive hashing or not
std::string singleOptions[] = {RECURSIVE};

// Misc
std::string allOptions[] = { INPUT_DATA,
                             OUTPUT_DATA,
	                         CODING,
	                         PUBKEY, 
	                         ALGO,
                             OBJECT_TYPE,
                             HASH_ALGO,
                             SIGN_ALGO,
	                         MODE,
	                         IV,
	                         SIGN,
	                         IV_CODING,
	                         SYMKEY,
	                         GENKEY,
							 KEY_CODING,
                             RECURSIVE};

VOID PrintHelpMessage() {
	std::string start("\t ");
	std::string helpMsgStrs[] = {
	"Console Crypto v1.0",
	"Supported features: encryption, decryption, hashing, signing, signature verifying.",
	"Parameters:",
	"./ConCrypto.exe [feature] [args]",
	"Feature specifying:",
	start + HASH + " - optional. Hash feature [support files and dirs].",
	start + SIG + " - optional. Sign feature [support files and dirs].",
	start + VER + " - optional. Verify sign feature.",
	start + ENC + " - optional. File encryption feature.",
	start + DEC + " - optional. File decryption feature.",
	start + HELP + " - optional. Print this help message.",
	"Almost common arguments:",
	start + INPUT_DATA + " - positional argument. Input data path (file or directory).",
	start + OUTPUT_DATA + " - positional argument for encryption/decryption and optional for others. Output file path. \n\t      Print to stdout if not specified [you must specify coding option before that].",
	start + CODING + " - optional argument. Output [hash, sign features] or input [verify feature] data coding type. Can be 'hex','base64'. \n\t      Ignored by encryption/decryption",
	"Hashing arguments:",
	start + ALGO + " - positional argument. Hash algorithm name. Can be 'sha256', 'md4'.",
	start + OBJECT_TYPE + " - positional argument. Object type - file or directory. Can be 'f' for file and 'd' for directories.",
	start + RECURSIVE + " - optional single argument. Specifying hashing directories in a recursive way or not [default - not]",
	"Signing arguments:",
	start + HASH_ALGO + " - positional argument. Hash algorithm name. Can be 'sha256', 'md4'.",
	start + SIGN_ALGO + " - positional argument. Signature algorithm name. Can be 'rsa', 'ecdsa_p256'",
	start + OBJECT_TYPE + " - positional argument. Object type - file or directory. Can be 'f' for file and 'd' for directories.",
	start + RECURSIVE + " - optional single argument. Specifying hashing directories in a recursive way or not [default - not]",
	start + PUBKEY + " - positional argument. Specifying file for exporting public key",
	start + KEY_CODING + " - optional argument. Use it for encode public key. Can be 'hex', 'base64'",
	"Verifying arguments:",
	start + INPUT_DATA + " - positional argument. Input data path (file or directory) for hashing.",
	start + HASH_ALGO + " - positional argument. Hash algorithm name. Can be 'sha256', 'md4'.",
	start + SIGN_ALGO + " - positional argument. Signature algorithm name. Can be 'rsa', 'ecdsa_p256'",
	start + OBJECT_TYPE + " - positional argument. Object type - file or directory. Can be 'f' for file and 'd' for directories.",
	start + RECURSIVE + " - optional single argument. Specifying hashing directories in a recursive way or not [default - not]",
	start + PUBKEY + " - positional argument. Specifying file for importing public key",
	start + SIGN + " - positional argument. Specifying file for importing signature",
	start + KEY_CODING + " - optional argument. Use it for decode imported public key. Can be 'hex', 'base64'",
	"File encryption arguments:",
	start + ALGO + " - positional argument. Encryption algorithm name. Can be 'aes' (currently only one algorithm supported).",
	start + GENKEY + " - optional argument. Generate key and save it to file.",
	start + SYMKEY + " - optional argument. Import symmetric key from file.",
	start + KEY_CODING + " - optional argument. Use it for decode imported public key or encode generated key. Can be 'hex', 'base64'",
	start + MODE + " - positional argument. Specify block cipher mode. Can be 'ecb', 'cbc', 'cfb'",
	start + IV + " - optional argument. Import iv from file.",
	start + IV_CODING + " - optional argument. Specify iv coding type. Can be 'hex','base64'.",
	"File decryption arguments:",
	start + ALGO + " - positional argument. Encryption algorithm name. Can be 'aes' (currently only one algorithm supported).",
	start + SYMKEY + " - positional argument. Import symmetric key from file.",
	start + KEY_CODING + " - optional argument. Use it for decode imported public key or encode generated key. Can be 'hex', 'base64'",
	start + MODE + " - positional argument. Specify block cipher mode. Can be 'ecb', 'cbc', 'cfb'",
	start + IV + " - optional argument. Import iv from file.",
	start + IV_CODING + " - optional argument. Specify iv coding type. Can be 'hex','base64'."
	};
	USHORT usSize = sizeof(helpMsgStrs) / sizeof(helpMsgStrs[0]);
	for (USHORT i = 0; i < usSize; i++)
	{
		printf("%s\n", helpMsgStrs[i].data());
	}
}

BOOL isSingleOption(const char* option) {
	USHORT usCount = sizeof(singleOptions) / sizeof(singleOptions[0]);
	std::string tmp(option);
	for (USHORT i = 0; i < usCount; i++) {
		if (tmp == singleOptions[i]) {
			return TRUE;
		}
	}
	return FALSE;
}
BOOL isOption(const char* s) {
	USHORT usCount = sizeof(allOptions) / sizeof(allOptions[0]);
	std::string tmp(s);
	for (USHORT i = 0; i < usCount; i++) {

		if (tmp == allOptions[i]) {
			return TRUE;
		}
	}
	return FALSE;
}
LPCWSTR ConvertAlgorithmToId(const std::string& algoName) {
	if(algoName == "sha256")
		return BCRYPT_SHA256_ALGORITHM;
	if (algoName == "md4")
		return BCRYPT_MD4_ALGORITHM;
	if (algoName == "aes")
		return BCRYPT_AES_ALGORITHM;
	if (algoName == "ecdsa_p256")
		return BCRYPT_ECDSA_P256_ALGORITHM;
	if (algoName == "rsa")
		return BCRYPT_RSA_ALGORITHM;
	return NULL;
}
DWORD GetCodingFlags(const std::string& codingName) {
	if (codingName == "hex")
		return CRYPT_STRING_HEXRAW;
	if (codingName == "base64")
		return CRYPT_STRING_BASE64;
	return 0;
}
LPCWSTR ConvertStrToMode(const std::string& mode) {
	if (mode == "ecb")
		return BCRYPT_CHAIN_MODE_ECB;
	if (mode == "cbc")
		return BCRYPT_CHAIN_MODE_CBC;
	if (mode == "cfb")
		return BCRYPT_CHAIN_MODE_CFB;
	return NULL;
}

NTSTATUS ArgParse(int argc, const char* argv[], std::map<std::string, std::string>& params) {
	if (argc < 2) {
		wprintf(L"**** Invalid params\n");
		return STATUS_INVALID_PARAMETER;
	}
	NTSTATUS(*TargetFunc)(std::map<std::string, std::string>&) = NULL;
	NTSTATUS ntStatus = 0;

	LPCSTR param1 = argv[1];

	if (!strcmp(param1, HASH.data())) {
		TargetFunc = HashArgs;
	}
	else if (!strcmp(param1, SIG.data())) {
		TargetFunc = SignArgs;
	}
	else if (!strcmp(param1, ENC.data())) {
		TargetFunc = EncryptChunksArgs;
	}
	else if (!strcmp(param1, DEC.data())) {
		TargetFunc = DecryptChunksArgs;
	}
	else if (!strcmp(param1, VER.data())) {
		TargetFunc = VerifyArgs;
	}
	else if (!strcmp(param1, "-h") || !strcmp(param1, "--help")) {
		PrintHelpMessage();
		return 0;
	}
	else {
		wprintf(L"**** Invalid params\n");
		return STATUS_INVALID_PARAMETER;
	}
	std::string first;
	for (int i = 2; i < argc;) {
		
		if (!isOption(argv[i])) {
			printf("**** Unsupported parameter - '%s'\n", argv[i]);
			return STATUS_INVALID_PARAMETER;
		}
		
		first = std::string(argv[i]);
		if (isSingleOption(argv[i])) {
			params.insert(
				std::make_pair(first, "")
			);
			i++;
		}
		else {
			params.insert(
				std::make_pair(first, std::string(argv[i + 1]))
			);
			i += 2;
		}
	}

	ntStatus = TargetFunc(params);
	if (!NT_SUCCESS(ntStatus)) {
		wprintf(L"**** Error 0x%x returned by TargetFunc\n", ntStatus);
	}
	return ntStatus;
}
NTSTATUS HashArgs(std::map<std::string, std::string>& params) {
	BOOL isFile = TRUE,
		 isRecursive = FALSE, isPrint = FALSE;
	std::string inputPath, type, outputPath;
	std::string coding;
	LPSTR lpString = NULL;
	LPCWSTR lpAlgId;
	DWORD dwCoding = DO_NOT_USE_ENCODING, cchString = 0, dwStatus = 0;
	PBYTE pbResult = NULL;
	DWORD cbResult = 0;
	BOOL boolResult = FALSE;
	HashObject hObject;
	NTSTATUS ntStatus = 0;

	// Check algorithm param
	auto it = params.find(ALGO);
	if (it == params.cend()) {
		printf("Please specify algorithm\n");
		return STATUS_INVALID_PARAMETER;
	}
	lpAlgId = ConvertAlgorithmToId((*it).second);
	if (!lpAlgId) {
		printf("Undefined algorithm - '%s'\n", (*it).first.data());
		return STATUS_INVALID_PARAMETER;
	}

	// Check object type
	it = params.find(OBJECT_TYPE);
	if (it == params.cend()) {
		printf("Please specify type: file or dir ('f' or 'd')\n");
		return STATUS_INVALID_PARAMETER;
	}
	type = (*it).second.data();
	if (type != "f" && type != "d") {
		printf("Undefined type\n");
		return STATUS_INVALID_PARAMETER;
	}
	if (type == "d") {
		isFile = FALSE;
	}

	// Check input param
	it = params.find(INPUT_DATA);
	if (it == params.cend()) {
		printf("Please specify input path\n");
		return STATUS_INVALID_PARAMETER;
	}

	inputPath = (*it).second;

	// Check output param
	it = params.find(OUTPUT_DATA);
	if (it == params.cend()) {
		printf( "Output file path not specified. Print to stdout\n");
		isPrint = TRUE;
	}
	else {
		outputPath = (*it).second;
	}
	// Check coding param
	it = params.find(CODING);
	if (it == params.cend()) {
		dwCoding = DO_NOT_USE_ENCODING;
	}
	else {

		coding = (*it).second;
		dwCoding = GetCodingFlags(coding);
		if (!dwCoding) {
			printf("Undefined coding type\n");
			return STATUS_INVALID_PARAMETER;
		}
	}
    
	// Check recursive param for dir
	it = params.find(RECURSIVE);
	if (it != params.cend()) {
		isRecursive = TRUE;
	}

	ntStatus = InitHashObject(&hObject, lpAlgId, NULL);
	if (!NT_SUCCESS(ntStatus)) {
		wprintf(L"**** Error 0x%x returned by InitHashObject\n", ntStatus);
		return ntStatus;
	}

	// Hash object
	if (isFile) {
		printf("Hash file - '%s'\n", inputPath.data());
		ntStatus = HashFileA(&hObject, inputPath.data());
	}
	else {
		printf("Hash dir - '%s'\n", inputPath.data());
		ntStatus = HashDirectoryA(inputPath.data(), &hObject, isRecursive);
	}

	// Check status
	if (!NT_SUCCESS(ntStatus)) {
		wprintf(L"**** Error 0x%x\n", ntStatus);
		ClearHashObject(&hObject);
		return ntStatus;
	}

	// Encode hash, if need
	if (dwCoding != DO_NOT_USE_ENCODING) {
		boolResult = EncodeBytes(hObject.pbHash, hObject.cbHash, dwCoding, &lpString, &cchString);
		if (!boolResult) {
			dwStatus = GetLastError();
			wprintf(L"**** Error 0x%x in EncodeBytes\n", dwStatus);
			ClearHashObject(&hObject);
			return STATUS_UNSUCCESSFUL;
		}
		pbResult = (PBYTE)lpString;
		cbResult = cchString;
	}
	else {
		pbResult = hObject.pbHash;
		cbResult = hObject.cbHash;

		// We will free pbResult later
		// so we don't need to free pbHash in
		// the ClearHashObject
		hObject.pbHash = NULL;
	}
	
	if (!isPrint) {
		dwStatus = WriteBlobToFileA(outputPath.data(), pbResult, cbResult);
	}
	else {
		printf_s("%s\n", pbResult);
	}

	free(pbResult);

	ClearHashObject(&hObject);

	if (dwStatus) {
		dwStatus = GetLastError();
		wprintf(L"**** Error 0x%x in WriteBlobToFileA\n", dwStatus);
		return STATUS_UNSUCCESSFUL;
	}
	return 0;
}

NTSTATUS SignArgs(std::map<std::string, std::string>& params){
	BOOL isFile = TRUE,
		isRecursive = FALSE, isPrint = FALSE;
	std::string inputPath, type, outputPath, pubKeyPath;
	std::string signCoding, pubKeyCoding;
	LPSTR lpString = NULL;
	LPCWSTR lpHashAlgId, lpSignAlgId;
	DWORD dwSignatureCoding = DO_NOT_USE_ENCODING, dwKeyLen = 0,cchString = 0, dwStatus = 0, dwKeyCoding = DO_NOT_USE_ENCODING;
	PBYTE pbHash = NULL, pbResult = NULL;
	DWORD cbHash = 0, cbResult = 0;
	BOOL boolResult = FALSE;
	HashObject hObject;
	SignObject sObject;
	NTSTATUS ntStatus = 0;
	_BCRYPT_PKCS1_PADDING_INFO padInfo;
	// Check algorithm param
	auto it = params.find(HASH_ALGO);
	if (it == params.cend()) {
		wprintf(L"Please specify hash algorithm\n");
		return STATUS_INVALID_PARAMETER;
	}
	lpHashAlgId = ConvertAlgorithmToId((*it).second);
	if (!lpHashAlgId) {
		wprintf(L"Undefined hash algorithm\n");
		return STATUS_INVALID_PARAMETER;
	}

	// Check signature algorithm param
	it = params.find(SIGN_ALGO);
	if (it == params.cend()) {
		wprintf(L"Please specify sign algorithm\n");
		return STATUS_INVALID_PARAMETER;
	}
	lpSignAlgId = ConvertAlgorithmToId((*it).second);
	if (!lpSignAlgId) {
		wprintf(L"Undefined sign algorithm\n");
		return STATUS_INVALID_PARAMETER;
	}

	// Check object type
	it = params.find(OBJECT_TYPE);
	if (it == params.cend()) {
		wprintf(L"Please specify type: file or dir ('f' or 'd')\n");
		return STATUS_INVALID_PARAMETER;
	}
	type = (*it).second.data();
	if (type != "f" && type != "d") {
		wprintf(L"Undefined type\n");
		return STATUS_INVALID_PARAMETER;
	}
	if (type == "d") {
		isFile = FALSE;
	}

	// Check input param
	it = params.find(INPUT_DATA);
	if (it == params.cend()) {
		wprintf(L"Please specify input path\n");
		return STATUS_INVALID_PARAMETER;
	}

	inputPath = (*it).second;

	// Check output param
	it = params.find(OUTPUT_DATA);
	if (it == params.cend()) {
		wprintf(L"Output file path not specified. Print to stdout\n");
		isPrint = TRUE;
	}
	else {
		outputPath = (*it).second;
	}
	
	// Check coding param
	it = params.find(CODING);
	if (it != params.cend()) {
		signCoding = (*it).second;
		dwSignatureCoding = GetCodingFlags(signCoding);
		if (!dwSignatureCoding) {
			wprintf(L"Undefined coding type\n");
			return STATUS_INVALID_PARAMETER;
		}
	}

	// Check param for key encoding
	it = params.find(KEY_CODING);
	if (it != params.cend()) {
		pubKeyCoding = (*it).second;
		dwKeyCoding = GetCodingFlags(pubKeyCoding);
		if (!dwKeyCoding) {
			wprintf(L"Undefined key coding type\n");
			return STATUS_INVALID_PARAMETER;
		}
	}

	// Check recursive param for dir
	it = params.find(RECURSIVE);
	if (it != params.cend()) {
		isRecursive = TRUE;
	}

	// Check public key export file
	it = params.find(PUBKEY);
	if (it == params.cend()) {
		wprintf(L"Please specify public key path for exporting\n");
		return STATUS_INVALID_PARAMETER;
	}
	pubKeyPath = (*it).second;

	ntStatus = InitHashObject(&hObject, lpHashAlgId, NULL);
	if (!NT_SUCCESS(ntStatus)) {
		wprintf(L"**** Error 0x%x returned by InitHashObject\n", ntStatus);
		return ntStatus;
	}

	ntStatus = InitSign(&sObject, lpSignAlgId, NULL);
	if (!NT_SUCCESS(ntStatus)) {
		wprintf(L"**** Error 0x%x returned by InitSign\n", ntStatus);
		return ntStatus;
	}

	// Hash object
	if (isFile) {
		printf("Hash file - '%s'\n", inputPath.data());
		ntStatus = HashFileA(&hObject, inputPath.data());
	}
	else {
		printf("Hash dir - '%s'\n", inputPath.data());
		ntStatus = HashDirectoryA(inputPath.data(), &hObject, isRecursive);
	}

	// Check status
	if (!NT_SUCCESS(ntStatus)) {
		wprintf(L"**** Error 0x%x\n", ntStatus);
		ClearHashObject(&hObject);
		ClearSign(&sObject);
		return ntStatus;
	}

	pbHash = hObject.pbHash;
	cbHash = hObject.cbHash;
	hObject.pbHash = NULL;

	ClearHashObject(&hObject);

	// Lets create key for signature
	dwKeyLen = GetKeyLenForAlgId(lpSignAlgId);
	if (!dwKeyLen) {
		wprintf(L"*** Error - undefined sign algorithm\n");
		ClearSign(&sObject);
		return STATUS_INVALID_PARAMETER;
	}

	ntStatus = CreateSignKey(&sObject, dwKeyLen);
	if (!NT_SUCCESS(ntStatus)) {
		wprintf(L"**** Error 0x%x returned by CreateSignKey\n", ntStatus);
		ClearSign(&sObject);
		return ntStatus;
	}

	padInfo.pszAlgId = lpHashAlgId;

	ntStatus = SignHash(&sObject, pbHash, cbHash, &padInfo, BCRYPT_PAD_PKCS1);
	if (!NT_SUCCESS(ntStatus)) {
		wprintf(L"**** Error 0x%x returned by SignHash\n", ntStatus);
		ClearSign(&sObject);
		return ntStatus;
	}

	free(pbHash);

	// Encode hash, if need
	if (dwSignatureCoding != DO_NOT_USE_ENCODING) {
		boolResult = EncodeBytes(sObject.pbSignature, sObject.cbSignature, dwSignatureCoding, &lpString, &cchString);
		if (!boolResult) {
			dwStatus = GetLastError();
			wprintf(L"**** Error 0x%x in EncodeBytes\n", dwStatus);
			ClearHashObject(&hObject);
			return STATUS_UNSUCCESSFUL;
		}
		pbResult = (PBYTE)lpString;
		cbResult = cchString;
	}
	else {
		pbResult = sObject.pbSignature;
		cbResult = sObject.cbSignature;
        
		sObject.pbSignature = NULL; // for ClearSign
	}

	ntStatus = ExportSignKeyToFileA(&sObject, BCRYPT_PUBLIC_KEY_BLOB, pubKeyPath.data(), dwKeyCoding);
	ClearSign(&sObject);

	if (!NT_SUCCESS(ntStatus)) {
		wprintf(L"**** Error 0x%x returned by ExportSignKeyToFileA\n", ntStatus);
		free(pbResult);
		return ntStatus;
	}

	// Write signature to file or print it
	if (!isPrint) {
		dwStatus = WriteBlobToFileA(outputPath.data(), pbResult, cbResult);
	}
	else if(dwSignatureCoding != DO_NOT_USE_ENCODING){
		printf("%s\n", pbResult);
	}
	else {
		wprintf(L"Specify coding algorithm to print or choose file for writing signature\n");
	}

	free(pbResult);

	if (dwStatus) {
		dwStatus = GetLastError();
		wprintf(L"**** Error 0x%x in WriteBlobToFileA\n", dwStatus);
		return STATUS_UNSUCCESSFUL;
	}

	return 0;
}

NTSTATUS VerifyArgs(std::map<std::string, std::string>& params) {
	BOOL isFile = TRUE,
		isRecursive = FALSE;
	std::string inputPath, type, outputPath, pubKeyPath, signPath;
	std::string signCoding, pubKeyCoding;
	LPSTR lpString = NULL;
	LPCWSTR lpHashAlgId, lpSignAlgId;
	DWORD dwSignatureCoding = DO_NOT_USE_ENCODING, cchString = 0, dwStatus = 0, dwKeyCoding = DO_NOT_USE_ENCODING;
	PBYTE pbHash = NULL, pbResult = NULL, pbTmp = NULL;
	DWORD cbHash = 0, cbResult = 0, cbTmp = 0;
	BOOL boolResult = FALSE;
	HashObject hObject;
	SignObject sObject;
	NTSTATUS ntStatus = 0;
	_BCRYPT_PKCS1_PADDING_INFO padInfo;

	// Check algorithm param
	auto it = params.find(HASH_ALGO);
	if (it == params.cend()) {
		wprintf(L"Please specify hash algorithm\n");
		return STATUS_INVALID_PARAMETER;
	}
	lpHashAlgId = ConvertAlgorithmToId((*it).second);
	if (!lpHashAlgId) {
		wprintf(L"Undefined hash algorithm\n");
		return STATUS_INVALID_PARAMETER;
	}

	// Check signature algorithm param
	it = params.find(SIGN_ALGO);
	if (it == params.cend()) {
		wprintf(L"Please specify sign algorithm\n");
		return STATUS_INVALID_PARAMETER;
	}
	lpSignAlgId = ConvertAlgorithmToId((*it).second);
	if (!lpSignAlgId) {
		wprintf(L"Undefined sign algorithm\n");
		return STATUS_INVALID_PARAMETER;
	}

	// Check object type
	it = params.find(OBJECT_TYPE);
	if (it == params.cend()) {
		wprintf(L"Please specify type: file or dir ('f' or 'd')\n");
		return STATUS_INVALID_PARAMETER;
	}
	type = (*it).second.data();
	if (type != "f" && type != "d") {
		wprintf(L"Undefined type\n");
		return STATUS_INVALID_PARAMETER;
	}
	if (type == "d") {
		isFile = FALSE;
	}

	// Check input param (path to file or dir for hashing)
	it = params.find(INPUT_DATA);
	if (it == params.cend()) {
		wprintf(L"Please specify input path\n");
		return STATUS_INVALID_PARAMETER;
	}

	inputPath = (*it).second;

	// Check signature path param
	it = params.find(SIGN);
	if (it == params.cend()) {
		wprintf(L"Please specify input path\n");
		return STATUS_INVALID_PARAMETER;
	}

	signPath = (*it).second;

	// Check coding param
	it = params.find(CODING);
	if (it != params.cend()) {
		signCoding = (*it).second;
		dwSignatureCoding = GetCodingFlags(signCoding);
		if (!dwSignatureCoding) {
			wprintf(L"Undefined coding type\n");
			return STATUS_INVALID_PARAMETER;
		}
	}

	// Check param for key decoding
	it = params.find(KEY_CODING);
	if (it != params.cend()) {
		pubKeyCoding = (*it).second;
		dwKeyCoding = GetCodingFlags(pubKeyCoding);
		if (!dwKeyCoding) {
			wprintf(L"Undefined key coding type\n");
			return STATUS_INVALID_PARAMETER;
		}
	}

	// Check recursive param for dir
	it = params.find(RECURSIVE);
	if (it != params.cend()) {
		isRecursive = TRUE;
	}

	// Check public key import file param
	it = params.find(PUBKEY);
	if (it == params.cend()) {
		wprintf(L"Please specify public key path for importing\n");
		return STATUS_INVALID_PARAMETER;
	}
	pubKeyPath = (*it).second;

	ntStatus = InitHashObject(&hObject, lpHashAlgId, NULL);
	if (!NT_SUCCESS(ntStatus)) {
		wprintf(L"**** Error 0x%x returned by InitHashObject\n", ntStatus);
		return ntStatus;
	}

	ntStatus = InitSign(&sObject, lpSignAlgId, NULL);
	if (!NT_SUCCESS(ntStatus)) {
		wprintf(L"**** Error 0x%x returned by InitSign\n", ntStatus);
		return ntStatus;
	}

	// Hash object
	if (isFile) {
		printf("Hash file - '%s'\n", inputPath.data());
		ntStatus = HashFileA(&hObject, inputPath.data());
	}
	else {
		printf("Hash dir - '%s'\n", inputPath.data());
		ntStatus = HashDirectoryA(inputPath.data(), &hObject, isRecursive);
	}

	// Check status
	if (!NT_SUCCESS(ntStatus)) {
		wprintf(L"**** Error 0x%x\n", ntStatus);
		ClearHashObject(&hObject);
		ClearSign(&sObject);
		return ntStatus;
	}

	pbHash = hObject.pbHash;
	cbHash = hObject.cbHash;
	hObject.pbHash = NULL;

	ClearHashObject(&hObject);

	ntStatus = ImportSignKeyFromFileA(&sObject, BCRYPT_PUBLIC_KEY_BLOB, pubKeyPath.data(), dwKeyCoding);
	if (!NT_SUCCESS(ntStatus)) {
		wprintf(L"**** Error 0x%x returned by ImportSignKeyFromFileA\n", ntStatus);
		ClearSign(&sObject);
		free(pbHash);
		return ntStatus;
	}
    // Read signature
	dwStatus = ReadBlobFromFileA(signPath.data(), (PBYTE*) &lpString, &cchString);
	if (dwStatus) {
		wprintf(L"**** Error 0x%x in ImportSignKeyFromFileA\n", dwStatus);
		ClearSign(&sObject);
		free(pbHash);
		return STATUS_UNSUCCESSFUL;
	}

	if (dwSignatureCoding != DO_NOT_USE_DECODING) {
		boolResult = DecodeBytes(&pbTmp, &cbTmp, dwSignatureCoding, lpString);
		if (!boolResult) {
			dwStatus = GetLastError();
			wprintf(L"**** Error 0x%x in DecodeBytes\n", dwStatus);
			ClearSign(&sObject);
			free(pbHash);
			free(lpString);
			return STATUS_UNSUCCESSFUL;
		}
		pbResult = pbTmp;
		cbResult = cbTmp;
		free(lpString);
	}
	else {
		pbResult = (PBYTE)lpString;
		cbResult = cchString;
	}

	sObject.pbSignature = pbResult;
	sObject.cbSignature = cbResult;

	padInfo.pszAlgId = lpHashAlgId;

	ntStatus = VerifyHashSign(&sObject, pbHash, cbHash, &padInfo, BCRYPT_PAD_PKCS1);
	ClearSign(&sObject);
	free(pbHash);

	if (!NT_SUCCESS(ntStatus)) {
		// if bad signature
		if (ntStatus == STATUS_BAD_SIGNATURE) {
			wprintf(L"Bad signature\n");
		}
		else {
			wprintf(L"**** Error 0x%x returned by VerifyHashSign\n", ntStatus);
		}
		return ntStatus;
	}
	wprintf(L"OK\n");
	return 0;
}

NTSTATUS EncryptChunksArgs(std::map<std::string, std::string>& params) {
	std::string inputPath, type, outputPath, keyPath, ivPath;
	std::string outputCoding, ivCoding, keyCoding;
	LPCWSTR lpAlgId, lpMode;
	DWORD dwKeyCoding = DO_NOT_USE_DECODING,
		dwIVCoding = DO_NOT_USE_DECODING,
		cbIV = 0,
		cbTmp = 0,
		dwKeyLen = 0,
		dwStatus = 0;
	PBYTE pbIV = NULL, pbTmp = NULL;
	BOOL boolResult = FALSE;
	CipherObject cObject;
	NTSTATUS ntStatus = 0;

	// Check algorithm param
	auto it = params.find(ALGO);
	if (it == params.cend()) {
		printf("Please specify algorithm\n");
		return STATUS_INVALID_PARAMETER;
	}
	lpAlgId = ConvertAlgorithmToId((*it).second);
	if (!lpAlgId) {
		printf("Undefined algorithm - '%s'\n", (*it).first.data());
		return STATUS_INVALID_PARAMETER;
	}

	// Check input param
	it = params.find(INPUT_DATA);
	if (it == params.cend()) {
		printf("Please specify input path\n");
		return STATUS_INVALID_PARAMETER;
	}

	inputPath = (*it).second;

	// Check output param
	it = params.find(OUTPUT_DATA);
	if (it == params.cend()) {
		printf("Output file path not specified\n");
		return STATUS_INVALID_PARAMETER;
	}
	else {
		outputPath = (*it).second;
	}

	// Check block cipher mode param
	it = params.find(MODE);
	if (it == params.cend()) {
		printf("*** Error: specify mode parameter\n");
		return STATUS_INVALID_PARAMETER;
	}

	lpMode = ConvertStrToMode((*it).second);
	if (!lpMode) {
		printf("*** Error: unsupported mode parameter\n");
		return STATUS_INVALID_PARAMETER;
	}

	// Check IV param
	it = params.find(IV);
	if (wcscmp(lpMode, BCRYPT_CHAIN_MODE_ECB) && it == params.cend()) {
		printf("*** Error: specify iv parameter\n");
		return STATUS_INVALID_PARAMETER;
	}
	if (wcscmp(lpMode, BCRYPT_CHAIN_MODE_ECB)) {
		ivPath = (*it).second;
		dwStatus = ReadBlobFromFileA(ivPath.data(), &pbIV, &cbIV);
		if (dwStatus) {
			printf("**** Error 0x%x returned by ReadBlobFromFileA\n", dwStatus);
			return STATUS_UNSUCCESSFUL;
		}
	}

	// Check IV coding param
	it = params.find(IV_CODING);
	if (it != params.cend() && wcscmp(lpMode, BCRYPT_CHAIN_MODE_ECB)) {
		ivCoding = (*it).second;
		dwIVCoding = GetCodingFlags(ivCoding);
		if (!dwIVCoding) {
			printf("Undefined coding type for iv\n");
			free(pbIV);
			return STATUS_INVALID_PARAMETER;
		}
		boolResult = DecodeBytes(&pbTmp, &cbTmp, dwIVCoding, (LPCSTR)pbIV);
		if (!boolResult) {
			dwStatus = GetLastError();
			printf("*** Error 0x%x in DecodeBytes\n", dwStatus);
			free(pbIV);
			return STATUS_UNSUCCESSFUL;
		}
		free(pbIV);
		pbIV = pbTmp;
		cbIV = cbTmp;
		pbTmp = NULL;
		cbTmp = 0;
	}

	// Check key coding param
	it = params.find(KEY_CODING);
	if (it != params.cend()) {
		keyCoding = (*it).second;
		dwKeyCoding = GetCodingFlags(keyCoding);
		if (!dwKeyCoding) {
			printf("Undefined key decoding type\n");
			free(pbIV);
			return STATUS_INVALID_PARAMETER;
		}
	}

	// Init Cipher Object struct
	ntStatus = InitCipherObject(&cObject, lpMode, lpAlgId, NULL);
	if (!NT_SUCCESS(ntStatus)) {
		printf("**** Error 0x%x returned by InitCipherObject\n", ntStatus);
		free(pbIV);
		return ntStatus;
	}


	// Check key generation or importing key
	it = params.find(GENKEY);
	auto it2 = params.find(SYMKEY);

	// Key generation and key importing conflict
	if (it != params.cend() && it2 != params.cend() || it == params.cend() && it2 == params.cend()) {
		printf("Choose only one key option: generation or importing\n");
		ClearCipherObject(&cObject);
		free(pbIV);
		return STATUS_INVALID_PARAMETER;
	}

	// Import or generate key
	if (it2 != params.cend()) {
		keyPath = (*it2).second;
		ntStatus = ImportSymKeyFromFileA(&cObject, BCRYPT_KEY_DATA_BLOB, keyPath.data(), dwKeyCoding);
		if (!NT_SUCCESS(ntStatus)) {
			printf("**** Error 0x%x returned by ImportSymKeyFromFileA\n", ntStatus);
			ClearCipherObject(&cObject);
			free(pbIV);
			return ntStatus;
		}
	}
	else {
		dwKeyLen = GetKeyLenForAlgId(lpAlgId);
		ntStatus = GenerateSymKey(&cObject, dwKeyLen / 8);
		if (!NT_SUCCESS(ntStatus)) {
			printf("**** Error 0x%x returned by GenerateSymKey\n", ntStatus);
			ClearCipherObject(&cObject);
			free(pbIV);
			return ntStatus;
		}

		keyPath = (*it).second;
		ntStatus = ExportSymKeyToFileA(&cObject, BCRYPT_KEY_DATA_BLOB, keyPath.data(), dwKeyCoding);
		if (!NT_SUCCESS(ntStatus)) {
			printf("**** Error 0x%x returned by ExportSymKeyToFileA\n", ntStatus);
			ClearCipherObject(&cObject);
			free(pbIV);
			return ntStatus;
		}
	}
	ntStatus = EncryptFileByChunksA(&cObject, inputPath.data(), outputPath.data(), pbIV);

	free(pbIV);
	ClearCipherObject(&cObject);

	if (!NT_SUCCESS(ntStatus)) {
		printf("**** Error 0x%x returned by EncryptFileByChunksA\n", ntStatus);
		return ntStatus;
	}
	return 0;
}
NTSTATUS DecryptChunksArgs(std::map<std::string, std::string>& params) {
	BOOL isPrint = FALSE;
	std::string inputPath, type, outputPath, keyPath, ivPath;
	std::string inputCoding, ivCoding, keyCoding;
	LPCWSTR lpAlgId, lpMode;
	DWORD dwKeyCoding = DO_NOT_USE_DECODING,
		dwIVCoding = DO_NOT_USE_DECODING,
		cbIV = 0,
		cbTmp = 0,
		dwStatus = 0;
	PBYTE pbIV = NULL, pbTmp = NULL;
	BOOL boolResult = FALSE;
	CipherObject cObject;
	NTSTATUS ntStatus = 0;

	// Check algorithm param
	auto it = params.find(ALGO);
	if (it == params.cend()) {
		printf("Please specify algorithm\n");
		return STATUS_INVALID_PARAMETER;
	}
	lpAlgId = ConvertAlgorithmToId((*it).second);
	if (!lpAlgId) {
		printf("Undefined algorithm - '%s'\n", (*it).first.data());
		return STATUS_INVALID_PARAMETER;
	}

	// Check input param
	it = params.find(INPUT_DATA);
	if (it == params.cend()) {
		printf("Please specify input path\n");
		return STATUS_INVALID_PARAMETER;
	}

	inputPath = (*it).second;

	// Check output param
	it = params.find(OUTPUT_DATA);
	if (it == params.cend()) {
		printf("Output file path not specified. Print to stdout\n");
		isPrint = TRUE;
	}
	else {
		outputPath = (*it).second;
	}

	// Check block cipher mode param
	it = params.find(MODE);
	if (it == params.cend()) {
		printf("*** Error: specify mode parameter\n");
		return STATUS_INVALID_PARAMETER;
	}

	lpMode = ConvertStrToMode((*it).second);
	if (!lpMode) {
		printf("*** Error: unsupported mode parameter\n");
		return STATUS_INVALID_PARAMETER;
	}

	// Check IV param
	it = params.find(IV);
	if (wcscmp(lpMode, BCRYPT_CHAIN_MODE_ECB) && it == params.cend()) {
		printf("*** Error: specify iv parameter\n");
		return STATUS_INVALID_PARAMETER;
	}
	if (wcscmp(lpMode, BCRYPT_CHAIN_MODE_ECB)) {
		ivPath = (*it).second;
		dwStatus = ReadBlobFromFileA(ivPath.data(), &pbIV, &cbIV);
		if (dwStatus) {
			printf("**** Error 0x%x returned by ReadBlobFromFileA\n", dwStatus);
			return STATUS_UNSUCCESSFUL;
		}
	}

	// Check IV coding param
	it = params.find(IV_CODING);
	if (it != params.cend() && wcscmp(lpMode, BCRYPT_CHAIN_MODE_ECB)) {
		ivCoding = (*it).second;
		dwIVCoding = GetCodingFlags(ivCoding);
		if (!dwIVCoding) {
			printf("Undefined coding type for iv\n");
			free(pbIV);
			return STATUS_INVALID_PARAMETER;
		}
		boolResult = DecodeBytes(&pbTmp, &cbTmp, dwIVCoding, (LPCSTR)pbIV);
		if (!boolResult) {
			dwStatus = GetLastError();
			printf("*** Error 0x%x in DecodeBytes\n", dwStatus);
			free(pbIV);
			return STATUS_UNSUCCESSFUL;
		}
		free(pbIV);
		pbIV = pbTmp;
		cbIV = cbTmp;
		pbTmp = NULL;
		cbTmp = 0;
	}

	// Check key coding param
	it = params.find(KEY_CODING);
	if (it != params.cend()) {
		keyCoding = (*it).second;
		dwKeyCoding = GetCodingFlags(keyCoding);
		if (!dwKeyCoding) {
			printf("Undefined key decoding type\n");
			free(pbIV);
			return STATUS_INVALID_PARAMETER;
		}
	}

	// Init Cipher Object struct
	ntStatus = InitCipherObject(&cObject, lpMode, lpAlgId, NULL);
	if (!NT_SUCCESS(ntStatus)) {
		printf("**** Error 0x%x returned by InitCipherObject\n", ntStatus);
		free(pbIV);
		return ntStatus;
	}


	// Check importing key
	it = params.find(SYMKEY);
	if (it == params.cend()) {
		printf("Import key for decryption\n");
		ClearCipherObject(&cObject);
		free(pbIV);
		return STATUS_INVALID_PARAMETER;
	}

	// Import key
	keyPath = (*it).second;
	ntStatus = ImportSymKeyFromFileA(&cObject, BCRYPT_KEY_DATA_BLOB, keyPath.data(), dwKeyCoding);
	if (!NT_SUCCESS(ntStatus)) {
		printf("**** Error 0x%x returned by ImportSymKeyFromFileA\n", ntStatus);
		ClearCipherObject(&cObject);
		free(pbIV);
		return ntStatus;
	}

	ntStatus = DecryptFileByChunksA(&cObject, inputPath.data(), outputPath.data(), pbIV);

	free(pbIV);
	ClearCipherObject(&cObject);

	if (!NT_SUCCESS(ntStatus)) {
		printf("**** Error 0x%x returned by DecryptFileByChunksA\n", ntStatus);
		return ntStatus;
	}
	return 0;
}