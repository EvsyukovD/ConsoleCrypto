cmake_minimum_required (VERSION 3.8)

# Включение горячей перезагрузки для компиляторов MSVC, если поддерживается.
if (POLICY CMP0141)
  cmake_policy(SET CMP0141 NEW)
  set(CMAKE_MSVC_DEBUG_INFORMATION_FORMAT "$<IF:$<AND:$<C_COMPILER_ID:MSVC>,$<CXX_COMPILER_ID:MSVC>>,$<$<CONFIG:Debug,RelWithDebInfo>:EditAndContinue>,$<$<CONFIG:Debug,RelWithDebInfo>:ProgramDatabase>>")
endif()

project ("ConCrypto")

add_library(bcrypt SHARED IMPORTED)
add_library(crypt32 SHARED IMPORTED)
add_library(shlwapi SHARED IMPORTED)

set_property(TARGET bcrypt PROPERTY
             IMPORTED_IMPLIB "C:\\Program Files (x86)\\Windows Kits\\10\\Lib\\10.0.22621.0\\um\\x64\\bcrypt.lib")
set_property(TARGET crypt32 PROPERTY
             IMPORTED_IMPLIB "C:\\Program Files (x86)\\Windows Kits\\10\\Lib\\10.0.22621.0\\um\\x64\\Crypt32.Lib")

set_property(TARGET shlwapi PROPERTY
             IMPORTED_IMPLIB "C:\\Program Files (x86)\\Windows Kits\\10\\Lib\\10.0.22621.0\\um\\x64\\ShLwApi.Lib")

add_executable (ConCrypto
"ConCrypto.cpp" 
"apibase.cpp"
"apiservs.cpp"
"cipher.cpp"
"crypto.cpp"
"hash.cpp"
"sign.cpp"
 "main.cpp")

target_link_libraries(ConCrypto PRIVATE bcrypt shlwapi crypt32)

if (CMAKE_VERSION VERSION_GREATER 3.12)
  set_property(TARGET ConCrypto PROPERTY CXX_STANDARD 20)
endif()
