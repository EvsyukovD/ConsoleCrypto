#include "ProviderShellExtension_i.h"
#include "main.h"
ProviderShellExtensionModule _AtlModule;
HINSTANCE hInstanceShellExtension;
extern "C" BOOL WINAPI DllMain(HINSTANCE hInstance , DWORD dwReason , LPVOID lpReserved)
{
	hInstanceShellExtension = hInstance;
	return 	_AtlModule.DllMain(dwReason, lpReserved);
}