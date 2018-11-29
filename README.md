#### **libpe** — win32 library for reading PE file format information. Supports x32 (PE32) and x64 (PE32+) binares.  
MSVS 2017, C++17.  
[Microsoft Visual C++ Redistributable for Visual Studio 2017 required.](https://aka.ms/vs/15/release/VC_redist.x86.exe)
___________________________________
**Usage:**  
```C++
#pragma comment(lib, "libpe.lib")
#include "libpe.h"
  
using namespace libpe;
libpe_ptr pLibpe;
Getlibpe(&pLibpe);

pLibpe->LoadPe(L"FileName");
pLibpe->GetFileSummary(PCDWORD*);
pLibpe->GetMSDOSHeader(PCLIBPE_DOSHEADER*);
pLibpe->GetRichHeader(PCLIBPE_RICHHEADER_VEC*);
pLibpe->GetNTHeader(PCLIBPE_NTHEADER_VAR*);
pLibpe->GetFileHeader(PCLIBPE_FILEHEADER*);
pLibpe->GetOptionalHeader(PCLIBPE_OPTHEADER_VAR*);
pLibpe->GetDataDirectories(PCLIBPE_DATADIRS_VEC*);
pLibpe->GetSectionsHeaders(PCLIBPE_SECHEADERS_VEC*);
pLibpe->GetExportTable(PCLIBPE_EXPORT_TUP*);
pLibpe->GetImportTable(PCLIBPE_IMPORT_VEC*);
pLibpe->GetResourceTable(PCLIBPE_RESOURCE_ROOT_TUP*);
pLibpe->GetExceptionTable(PCLIBPE_EXCEPTION_VEC*);
pLibpe->GetSecurityTable(PCLIBPE_SECURITY_VEC*);
pLibpe->GetRelocationTable(PCLIBPE_RELOCATION_VEC*);
pLibpe->GetDebugTable(PCLIBPE_DEBUG_VEC*);
pLibpe->GetTLSTable(PCLIBPE_TLS_TUP*);
pLibpe->GetLoadConfigTable(PCLIBPE_LOADCONFIGTABLE_VAR*);
pLibpe->GetBoundImportTable(PCLIBPE_BOUNDIMPORT_VEC*);
pLibpe->GetDelayImportTable(PCLIBPE_DELAYIMPORT_VEC*);
pLibpe->GetCOMDescriptorTable(PCLIBPE_COMDESCRIPTOR*);
```