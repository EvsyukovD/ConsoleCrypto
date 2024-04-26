#include "apiservs.hpp"


int main(int argc, char* argv[])
{
	std::map<std::string, std::string> params;
	NTSTATUS ntStatus = 0;

	ntStatus = ArgParse(argc, (const char**)argv, params);
	if (!NT_SUCCESS(ntStatus)) {
		wprintf(L"**** Error 0x%x returned by ArgParse\n", ntStatus);
	}
	return 0;
}
