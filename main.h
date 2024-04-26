#pragma once
//#include "ProviderShellExtension_i.h"
#include <windows.h>
class ProviderShellExtensionModule : public ATL::CAtlDllModuleT < ProviderShellExtensionModule>
{
public:
DECLARE_LIBID(LIBID_ProviderShellExtensionLib)
DECLARE_REGISTRY_APPID_RESOURCEID(IDR_PROVIDERSHELLEXTENSION,
"{05f22fe4 d064 415c 855e 16c2723e57f6}")
	};
extern class ProviderShellExtensionModule _AtlModule;
extern	HINSTANCE hInstanceShellExtension;
#define SHELL_EXTENSION_GUID "{4cc3b346 e43f 43de b05f 4433e896e177}"