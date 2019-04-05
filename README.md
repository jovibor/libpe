## Windows library for viewing PE and PE+ file's information, including all internal structures, tables and resources.
Supports x32 (PE32) and x64 (PE32+) binares.
MSVS 2017, C++17.  
[Microsoft Visual C++ Redistributable for Visual Studio 2017 might be needed.](https://aka.ms/vs/15/release/VC_redist.x86.exe)

## Table of Contents
* [Usage](#usage)
* [Examples](#examples)
  * [Export](#export)
  * [Import](#import)
* [Some related info](#some-related-info)
* [License](#license)

## [](#)Usage:  
```cpp
#include "libpe.h"
  
using namespace libpe;

libpe_ptr pLibpe;
Createlibpe(&pLibpe);

pLibpe->LoadPe(LPCWSTR);

pLibpe->GetImageInfo(DWORD&);
pLibpe->GetImageFlag(DWORD dwFlag, bool& f);
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
## [](#)Examples
### [](#)Export
Getting Export information is very simple:
```cpp
libpe_ptr pLibpe;
Createlibpe(pLibpe);
pLibpe->LoadPe(L"PATH_TO_PE_FILE")

PCLIBPE_EXPORT pExport;
pLibpe->GetExport(pExport)

pExport->stExportDesc; //IMAGE_EXPORT_DIRECTORY struct.
pExport->strModuleName; //Export module name.
pExport->vecFuncs; //Vector of exported functions.

for (auto& itFuncs : pExport->vecFuncs)
{
	itFuncs.strFuncName; //Function name.
	itFuncs.dwOrdinal; //Ordinal.
	itFuncs.dwRVA; //Function RVA.
	itFuncs.strForwarderName; //Forwarder name.
}
```
### [](#)Import
To obtain an **Import table** information from the PE file see the following code:
```cpp
libpe_ptr pLibpe;
Createlibpe(pLibpe);
pLibpe->LoadPe(L"PATH_TO_PE_FILE")

PCLIBPE_IMPORT_VEC pImport;
pLibpe->GetImport(pImport);

for (auto& itModule : *pImport) //Cycle through all imports that this PE file contains.
{
	const IMAGE_IMPORT_DESCRIPTOR* pImpDesc = &itModule.stImportDesc; //IMAGE_IMPORT_DESCRIPTOR struct.
	const std::string& str = itModule.strModuleName; //Name of the import module.
	
	for (auto& itFuncs : itModule.vecImportFunc) //Cycle through all the functions imported from itModule module.
	{
		itFuncs.strFuncName; 		//Imported function name (std::string).
		itFuncs.stImpByName;		//IMAGE_IMPORT_BY_NAME struct for this function.
		itFuncs.varThunk.stThunk32;	//Union of IMAGE_THUNK_DATA32 or IMAGE_THUNK_DATA64 (depending on the file type).
	}
}
```
All the `nullptr` checks are ommited for simplicity.
## [](#)Some related info:
https://en.wikipedia.org/wiki/Portable_Executable  
http://www.dependencywalker.com/

## [](#)**License**
This software is available under the **MIT License modified with The Commons Clause**.
