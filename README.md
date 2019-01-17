## libpe 
#### Windows library for viewing PE file information, including all internal structures and tables.
Supports x32 (PE32) and x64 (PE32+) binares.  
MSVS 2017, C++17.  
[Microsoft Visual C++ Redistributable for Visual Studio 2017 required.](https://aka.ms/vs/15/release/VC_redist.x86.exe)
___________________________________
#### Usage:  
```C++
#include "libpe.h"
  
using namespace libpe;

libpe_ptr pLibpe;
Getlibpe(&pLibpe);

pLibpe->LoadPe(LPCWSTR);
pLibpe->GetImageFlags(DWORD&);
pLibpe->GetOffsetFromRVA(ULONGLONG ullRVA, DWORD& dwOffset);
pLibpe->GetMSDOSHeader(PCLIBPE_DOSHEADER&);
pLibpe->GetRichHeader(PCLIBPE_RICHHEADER_VEC&);
pLibpe->GetNTHeader(PCLIBPE_NTHEADER_VAR&);
pLibpe->GetFileHeader(PCLIBPE_FILEHEADER&);
pLibpe->GetOptionalHeader(PCLIBPE_OPTHEADER_VAR&);
pLibpe->GetDataDirectories(PCLIBPE_DATADIRS_VEC&);
pLibpe->GetSectionsHeaders(PCLIBPE_SECHEADERS_VEC&);
pLibpe->GetExport(PCLIBPE_EXPORT&);
pLibpe->GetImport(PCLIBPE_IMPORT_VEC&);
pLibpe->GetResources(PCLIBPE_RESOURCE_ROOT&);
pLibpe->GetExceptions(PCLIBPE_EXCEPTION_VEC&);
pLibpe->GetSecurity(PCLIBPE_SECURITY_VEC&);
pLibpe->GetRelocations(PCLIBPE_RELOCATION_VEC&);
pLibpe->GetDebug(PCLIBPE_DEBUG_VEC&);
pLibpe->GetTLS(PCLIBPE_TLS&);
pLibpe->GetLoadConfig(PCLIBPE_LOADCONFIG&);
pLibpe->GetBoundImport(PCLIBPE_BOUNDIMPORT_VEC&);
pLibpe->GetDelayImport(PCLIBPE_DELAYIMPORT_VEC&);
pLibpe->GetCOMDescriptor(PCLIBPE_COMDESCRIPTOR&);
```

## **License**
This software is available under the **MIT License** modified with **The Commons Clause**.
