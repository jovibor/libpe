## libpe
**Windows library for reading PE32 and PE32+ files' inner information, including all internal structures, directories, tables and resources. Works with a x86 (PE32) and x64 (PE32+) binares.<br>
MSVS 2019, C++17.**

## Table of Contents
* [Usage](#usage)
* [Methods](#methods) <details><summary>_Expand_</summary>
  * [LoadPe](#loadpe)
  * [GetImageInfo](#getimageinfo)
  * [GetImageFlag](#getimageflag)
  * [GetOffsetFromRVA](#getoffsetfromrva)
  * [GetOffsetFromVA](#getoffsetfromva)
  * [GetMSDOSHeader](#getmsdosheader)
  * [GetRichHeader](#getrichheader)
  * [GetNTHeader](#getntheader)
  * [GetFileHeader](#getfileheader)
  * [GetOptionalHeader](#getoptionalheader)
  * [GetDataDirectories](#getdatadirectories)
  * [GetSectionsHeaders](#getsectionsheaders)
  * [GetExport](#getexport)
  * [GetImport](#getimport)
  * [GetResources](#getresources)
  * [GetExceptions](#getexceptions)
  * [GetSecurity](#getsecurity)
  * [GetRelocations](#getrelocations)
  * [GetDebug](#getdebug)
  * [GetTLS](#gettls)
  * [GetLoadConfig](#getloadconfig)
  * [GetBoundImport](#getboundimport)
  * [GetDelayImport](#getdelayimport)
  * [GetCOMDescriptor](#getcomdescriptor)
  * [Destroy](#destroy)
  </details>
* [Error Codes](#error-codes)
* [License](#license)
* [Help Point](#help-point)

## [](#)Usage
The usage of the library is quite simple:
1. Add *libpe.h* header file into your project.
1. Add `#include "libpe.h"` where you suppose to use it.
1. Add `using namespace libpe;` or use namespace prefix `libpe::`
1. Declare `libpe_ptr` variable: `libpe_ptr pLibpe { Createlibpe() };`
1. Put *libpe.lib* into your project's folder, so that linker can see it.
1. Put *libpe.dll* next to your executable.

## [](#)Methods
All **libpe** methods return `HRESULT`. <br>
When method executes successfully it returns `S_OK`, otherwise [error code](#error-codes) is returned.
### [](#)LoadPe
```cpp
HRESULT LoadPe(LPCWSTR);
```
This is the first method you call to proceed with a PE file.
```cpp
libpe_ptr pLibpe { Createlibpe() };
if(pLibpe->LoadPe(L"C:\\MyFile.exe") == S_OK)
{
    ...
}
```
After this method succeeds you can then call all the other methods to retrieve needed information. The PE file itself doesn't stay in memory any longer, so you don't have to explicitly unload it.
### [](#)GetImageInfo
```cpp
HRESULT GetImageInfo(DWORD&);
```
This method returns `DWORD` variable with the currently loaded file's flags.<br>
These flags are listed below:

| Flag                       | Value      | Meaning                            |
|----------------------------|------------|------------------------------------|
| IMAGE_FLAG_PE32            | 0x00000001 | Image is x32 file.                 |
| IMAGE_FLAG_PE64            | 0x00000002 | Image is x64 file.                 |
| IMAGE_FLAG_DOSHEADER       | 0x00000004 | Image has DOS header.              |
| IMAGE_FLAG_RICHHEADER      | 0x00000008 | Image has "Rich" header.           |
| IMAGE_FLAG_NTHEADER        | 0x00000010 | Image has NT header.               |
| IMAGE_FLAG_FILEHEADER      | 0x00000020 | Image has File header.             |
| IMAGE_FLAG_OPTHEADER       | 0x00000040 | Image has Optional header.         |
| IMAGE_FLAG_DATADIRECTORIES | 0x00000080 | Image has Data directories.        |
| IMAGE_FLAG_SECTIONS        | 0x00000100 | Image has one or more Sections.    |
| IMAGE_FLAG_EXPORT          | 0x00000200 | Image has Export table.            |
| IMAGE_FLAG_IMPORT          | 0x00000400 | Image has Import table.            |
| IMAGE_FLAG_RESOURCE        | 0x00000800 | Image has Resource table.          |
| IMAGE_FLAG_EXCEPTION       | 0x00001000 | Image has Exception table.         |
| IMAGE_FLAG_SECURITY        | 0x00002000 | Image has Security table.          |
| IMAGE_FLAG_BASERELOC       | 0x00004000 | Image has Relocations.             |
| IMAGE_FLAG_DEBUG           | 0x00008000 | Image has Debug directory.         |
| IMAGE_FLAG_ARCHITECTURE    | 0x00010000 | Image has Architecture table.      |
| IMAGE_FLAG_GLOBALPTR       | 0x00020000 | Image has GlobalPtr table.         |
| IMAGE_FLAG_TLS             | 0x00040000 | Image has TLS directory.           |
| IMAGE_FLAG_LOADCONFIG      | 0x00080000 | Image has Load config directory.   |
| IMAGE_FLAG_BOUNDIMPORT     | 0x00100000 | Image has Bound import table.      |
| IMAGE_FLAG_IAT             | 0x00200000 | Image has IAT table.               |
| IMAGE_FLAG_DELAYIMPORT     | 0x00400000 | Image has Delay import table.      |
| IMAGE_FLAG_COMDESCRIPTOR   | 0x00800000 | Image has .NET related stuff.      |

There can be any combination of these flags, they all can be **OR**'ed.<br>
You can also use a standalone tiny helper function `ImageHasFlag` to find out if the given flag is set in a variable.
```cpp
libpe_ptr pLibpe { Createlibpe() };
if(pLibpe->LoadPe(L"C:\\MyFile.exe") == S_OK)
{
    DWORD dwFlags;
    pLibpe->GetImageInfo(dwFlags);
    bool fIsDebugData = ImageHasFlag(dwFlags, IMAGE_FLAG_DEBUG); //Now we know if loaded image has embeded Debug info.
}
```
### [](#)GetImageFlag
```cpp
HRESULT GetImageFlag(DWORD dwFlag, bool& f);
```
This helper function is very similar to the [`GetImageInfo`](#getimageinfo), but, in contrast, it recieves information about just one given flar at a time.
```cpp
libpe_ptr pLibpe { Createlibpe() };
if(pLibpe->LoadPe(L"C:\\MyFile.exe") == S_OK)
{
    bool fIsDebugData;
    pLibpe->GetImageFlag(IMAGE_FLAG_DEBUG, fIsDebugData);
}
```
### [](#)GetOffsetFromRVA
```cpp
HRESULT GetOffsetFromRVA(ULONGLONG ullRVA, DWORD& dwOffset);
```
Converts file's **RVA** (Relative Virtual Address) to the raw file offset.
### [](#)GetOffsetFromVA
```cpp
HRESULT GetOffsetFromVA(ULONGLONG ullVA, DWORD& dwOffset);
```
Converts file's **VA**  (Virtual Address) to the raw file offset.
### [](#)GetMSDOSHeader
```cpp
HRESULT GetMSDOSHeader(PCLIBPE_DOSHEADER&);
```
Gets file's standard **MSDOS** header, in form of `PCLIBPE_DOSHEADER`
```cpp
using PCLIBPE_DOSHEADER = const IMAGE_DOS_HEADER*;
```
### [](#)GetRichHeader
```cpp
HRESULT GetRichHeader(PCLIBPE_RICHHEADER_VEC&);
```
Gets array of the unofficial and undocumented so called **«Rich»** header structures.
```cpp
struct LIBPE_RICH {
    DWORD dwOffsetRich; //File's raw offset of the entry.
    WORD  wId;          //Entry Id.
    WORD  wVersion;     //Entry version.
    DWORD dwCount;      //Amount of occurrences.
};
using LIBPE_RICHHEADER_VEC = std::vector<LIBPE_RICH>;
using PCLIBPE_RICHHEADER_VEC = const LIBPE_RICHHEADER_VEC*;
```
### [](#)GetNTHeader
```cpp
HRESULT GetNTHeader(PCLIBPE_NTHEADER_VAR&);
```
Gets file's **NT** header.
```cpp
struct LIBPE_NTHEADER {
    DWORD dwOffsetNTHdrDesc; //File's raw offset of the header.
    union LIBPE_NTHEADER_VAR {
    	IMAGE_NT_HEADERS32 stNTHdr32; //x86 Header.
    	IMAGE_NT_HEADERS64 stNTHdr64; //x64 Header.
    }varHdr;
};
using PCLIBPE_NTHEADER = const LIBPE_NTHEADER*;
```
### [](#)GetFileHeader
```cpp
HRESULT GetFileHeader(PCLIBPE_FILEHEADER&);
```
Gets file's **File** header.
```cpp
using PCLIBPE_FILEHEADER = const IMAGE_FILE_HEADER*;
```
### [](#)GetOptionalHeader
```cpp
HRESULT GetOptionalHeader(PCLIBPE_OPTHEADER_VAR&);
```
Gets file's **Optional** header.
```cpp
union LIBPE_OPTHEADER_VAR {
    IMAGE_OPTIONAL_HEADER32 stOptHdr32; //x86 header.
    IMAGE_OPTIONAL_HEADER64 stOptHdr64; //x64 header.
};
using PCLIBPE_OPTHEADER_VAR = const LIBPE_OPTHEADER_VAR*;
```
### [](#)GetDataDirectories
```cpp
HRESULT GetDataDirectories(PCLIBPE_DATADIRS_VEC&);
```
Gets array of the file's **Data directories** structs.
```cpp
struct LIBPE_DATADIR {
    IMAGE_DATA_DIRECTORY stDataDir;       //Standard header.
    std::string          strSecResidesIn; //Name of the section this directory resides in (points to).
};
using LIBPE_DATADIRS_VEC = std::vector<LIBPE_DATADIR>;
using PCLIBPE_DATADIRS_VEC = const LIBPE_DATADIRS_VEC*;
```
### [](#)GetSectionsHeaders
```cpp
HRESULT GetSectionsHeaders(PCLIBPE_SECHEADERS_VEC&);
```
Gets array of the file's **Sections headers** structs.
```cpp
struct LIBPE_SECHEADERS {
    DWORD                 dwOffsetSecHdrDesc; //File's raw offset of the section header descriptor.
    IMAGE_SECTION_HEADER  stSecHdr;           //Standard section header.
    std::string           strSecName;         //Section full name.
};
using LIBPE_SECHEADERS_VEC = std::vector<LIBPE_SECHEADERS>;
using PCLIBPE_SECHEADERS_VEC = const LIBPE_SECHEADERS_VEC*;
```
### [](#)GetExport
```cpp
HRESULT GetExport(PCLIBPE_EXPORT&);
```
Gets file's **Export** information.
```cpp
struct LIBPE_EXPORT_FUNC {
    DWORD       dwRVA;            //Function RVA.
    DWORD       dwOrdinal;        //Function ordinal.
    std::string strFuncName;      //Function name.
    std::string strForwarderName; //Function forwarder name.
};
struct LIBPE_EXPORT {
    DWORD				dwOffsetExportDesc; //File's raw offset of the Export header descriptor.
    IMAGE_EXPORT_DIRECTORY		stExportDesc;	    //Standard export header descriptor.
    std::string			strModuleName;	    //Actual module name.
    std::vector<LIBPE_EXPORT_FUNC>	vecFuncs;   	    //Array of the exported functions struct.
};
using PCLIBPE_EXPORT = const LIBPE_EXPORT*;
```
**Example**  
Getting Export information is very simple:
```cpp
libpe_ptr pLibpe { Createlibpe() };
pLibpe->LoadPe(L"PATH_TO_PE_FILE")

PCLIBPE_EXPORT pExport;
pLibpe->GetExport(pExport)

pExport->stExportDesc;  //IMAGE_EXPORT_DIRECTORY struct.
pExport->strModuleName; //Export module name.
pExport->vecFuncs;      //Vector of exported functions.

for (auto& itFuncs : pExport->vecFuncs)
{
    itFuncs.strFuncName;      //Function name.
    itFuncs.dwOrdinal;        //Ordinal.
    itFuncs.dwRVA;            //Function RVA.
    itFuncs.strForwarderName; //Forwarder name.
}
```
### [](#)GetImport
```cpp
HRESULT GetImport(PCLIBPE_IMPORT_VEC&);
```
Gets array of the file's **Import table** entries.
```cpp
struct LIBPE_IMPORT_FUNC {
    union LIBPE_IMPORT_THUNK_VAR {
    	IMAGE_THUNK_DATA32 stThunk32; //x86 standard thunk.
    	IMAGE_THUNK_DATA64 stThunk64; //x64 standard thunk.
    }varThunk;
    IMAGE_IMPORT_BY_NAME stImpByName; //Standard IMAGE_IMPORT_BY_NAME struct
    std::string          strFuncName; //Function name.
};
struct LIBPE_IMPORT_MODULE {
    DWORD                          dwOffsetImpDesc; //File's raw offset of the Import descriptor.
    IMAGE_IMPORT_DESCRIPTOR        stImportDesc;    //Standard Import descriptor.
    std::string                    strModuleName;   //Imported module name.
    std::vector<LIBPE_IMPORT_FUNC> vecImportFunc;   //Array of imported functions.
};
using LIBPE_IMPORT_VEC = std::vector<LIBPE_IMPORT_MODULE>;
using PCLIBPE_IMPORT_VEC = const LIBPE_IMPORT_VEC*;
```
**Example**  
To obtain **Import table** information from the file see the following code:
```cpp
libpe_ptr pLibpe { Createlibpe() };
pLibpe->LoadPe(L"PATH_TO_PE_FILE")

PCLIBPE_IMPORT_VEC pImport;
pLibpe->GetImport(pImport);

for (auto& itModule : *pImport) //Cycle through all imports that this PE file contains.
{
    const IMAGE_IMPORT_DESCRIPTOR* pImpDesc = &itModule.stImportDesc; //IMAGE_IMPORT_DESCRIPTOR struct.
    const std::string& str = itModule.strModuleName;                  //Name of the import module.
	
    for (auto& itFuncs : itModule.vecImportFunc) //Cycle through all the functions imported from itModule module.
    {
    	itFuncs.strFuncName;        //Imported function name (std::string).
        itFuncs.stImpByName;        //IMAGE_IMPORT_BY_NAME struct for this function.
        itFuncs.varThunk.stThunk32; //Union of IMAGE_THUNK_DATA32 or IMAGE_THUNK_DATA64 (depending on the file type).
    }
}
```

### [](#)GetResources
```cpp
HRESULT GetResources(PCLIBPE_RESOURCE_ROOT&);
```
Retrieves all file's embedded resources.
```cpp
//Level 3 (the lowest) Resources.
struct LIBPE_RESOURCE_LVL3_DATA {
    IMAGE_RESOURCE_DIRECTORY_ENTRY stResDirEntryLvL3;   //Level 3 standard IMAGE_RESOURCE_DIRECTORY_ENTRY struct.
    std::wstring                   wstrResNameLvL3;     //Level 3 resource name.
    IMAGE_RESOURCE_DATA_ENTRY      stResDataEntryLvL3;  //Level 3 standard IMAGE_RESOURCE_DATA_ENTRY struct.
    std::vector<std::byte>         vecResRawDataLvL3;   //Level 3 resource raw data.
};
struct LIBPE_RESOURCE_LVL3 {
    DWORD                                 dwOffsetResLvL3; //File's raw offset of the level 3 IMAGE_RESOURCE_DIRECTORY descriptor.
    IMAGE_RESOURCE_DIRECTORY              stResDirLvL3;    //Level 3 standard IMAGE_RESOURCE_DIRECTORY header.
    std::vector<LIBPE_RESOURCE_LVL3_DATA> vecResLvL3;      //Array of level 3 resource entries.
};
using PCLIBPE_RESOURCE_LVL3 = const LIBPE_RESOURCE_LVL3*;

//Level 2 Resources — Includes LVL3 Resourses.
struct LIBPE_RESOURCE_LVL2_DATA {
    IMAGE_RESOURCE_DIRECTORY_ENTRY stResDirEntryLvL2;  //Level 2 standard IMAGE_RESOURCE_DIRECTORY_ENTRY struct.
    std::wstring                   wstrResNameLvL2;    //Level 2 resource name.
    IMAGE_RESOURCE_DATA_ENTRY      stResDataEntryLvL2; //Level 2 standard IMAGE_RESOURCE_DATA_ENTRY struct.
    std::vector<std::byte>         vecResRawDataLvL2;  //Level 2 resource raw data.
    LIBPE_RESOURCE_LVL3            stResLvL3;          //Level 3 resource struct.
};
struct LIBPE_RESOURCE_LVL2 {
    DWORD                                 dwOffsetResLvL2; //File's raw offset of the level 2 IMAGE_RESOURCE_DIRECTORY descriptor.
    IMAGE_RESOURCE_DIRECTORY              stResDirLvL2;    //Level 2 standard IMAGE_RESOURCE_DIRECTORY header.
    std::vector<LIBPE_RESOURCE_LVL2_DATA> vecResLvL2;      //Array of level 2 resource entries.
};
using PCLIBPE_RESOURCE_LVL2 = const LIBPE_RESOURCE_LVL2*;

//Level 1 (Root) Resources — Includes LVL2 Resources.
struct LIBPE_RESOURCE_ROOT_DATA {
    IMAGE_RESOURCE_DIRECTORY_ENTRY stResDirEntryRoot;  //Level 1 standard IMAGE_RESOURCE_DIRECTORY_ENTRY struct.
    std::wstring                   wstrResNameRoot;    //Level 1 resource name.
    IMAGE_RESOURCE_DATA_ENTRY      stResDataEntryRoot; //Level 1 standard IMAGE_RESOURCE_DATA_ENTRY struct.
    std::vector<std::byte>         vecResRawDataRoot;  //Level 1 resource raw data.
    LIBPE_RESOURCE_LVL2            stResLvL2;          //Level 2 resource struct.
};
struct LIBPE_RESOURCE_ROOT {
	DWORD                                 dwOffsetResRoot; //File's raw offset of the level 1 IMAGE_RESOURCE_DIRECTORY descriptor.
	IMAGE_RESOURCE_DIRECTORY              stResDirRoot;    //Level 1 standard IMAGE_RESOURCE_DIRECTORY header.
	std::vector<LIBPE_RESOURCE_ROOT_DATA> vecResRoot;      //Array of level 1 resource entries.
};
using PCLIBPE_RESOURCE_ROOT = const LIBPE_RESOURCE_ROOT*;
```

### [](#)GetExceptions
```cpp
HRESULT GetExceptions(PCLIBPE_EXCEPTION_VEC&);
```
Gets array of the file's **Exception** entries.
```cpp
struct LIBPE_EXCEPTION {
    DWORD                         dwOffsetRuntimeFuncDesc; //File's raw offset of the exceptions descriptor.
    _IMAGE_RUNTIME_FUNCTION_ENTRY stRuntimeFuncEntry;      //Standard _IMAGE_RUNTIME_FUNCTION_ENTRY header.
};
using LIBPE_EXCEPTION_VEC = std::vector<LIBPE_EXCEPTION>;
using PCLIBPE_EXCEPTION_VEC = const LIBPE_EXCEPTION_VEC*;
```
### [](#)GetSecurity
```cpp
HRESULT GetSecurity(PCLIBPE_SECURITY_VEC&);
```
Gets array of the file's **Security** entries.
```cpp
struct LIBPE_SECURITY {
    DWORD           dwOffsetWinCertDesc; //File's raw offset of the security descriptor.
    WIN_CERTIFICATE stWinSert;           //Standard WIN_CERTIFICATE header.
};
using LIBPE_SECURITY_VEC = std::vector<LIBPE_SECURITY>;
using PCLIBPE_SECURITY_VEC = const LIBPE_SECURITY_VEC*;
```
### [](#)GetRelocations
```cpp
HRESULT GetRelocations(PCLIBPE_RELOCATION_VEC&);
```
Gets array of the file's relocation information.
```cpp
struct LIBPE_RELOC_DATA {
    DWORD dwOffsetRelocData; //File's raw offset of the Relocation data descriptor.
    WORD  wRelocType;        //Relocation type.
    WORD  wRelocOffset;      //Relocation offset (Offset the relocation must be applied to.)
};
struct LIBPE_RELOCATION {
    DWORD                         dwOffsetReloc; //File's raw offset of the Relocation descriptor.
    IMAGE_BASE_RELOCATION         stBaseReloc;   //Standard IMAGE_BASE_RELOCATION header.
    std::vector<LIBPE_RELOC_DATA> vecRelocData;  //Array of the Relocation data struct.
};
using LIBPE_RELOCATION_VEC = std::vector<LIBPE_RELOCATION>;
using PCLIBPE_RELOCATION_VEC = const LIBPE_RELOCATION_VEC*;
```
### [](#)GetDebug
```cpp
HRESULT GetDebug(PCLIBPE_DEBUG_VEC&);
```
Gets array of the file's **Debug** entries.
```cpp
struct LIBPE_DEBUG_DBGHDR
    {
    	DWORD       dwArr[6];   //First six DWORDs of IMAGE_DEBUG_DIRECTORY::PointerToRawData data (Debug info header).
                                //Their meaning vary depending on dwArr[0] (Signature) value.
    	std::string strPDBName; //PDB file name/path.
	}; 
	struct LIBPE_DEBUG {
		DWORD                 dwOffsetDebug;  //File's raw offset of the Debug descriptor.
		IMAGE_DEBUG_DIRECTORY stDebugDir;     //Standard IMAGE_DEBUG_DIRECTORY.
		LIBPE_DEBUG_DBGHDR    stDebugHdrInfo; //Debug info header.
	};
	using LIBPE_DEBUG_VEC = std::vector<LIBPE_DEBUG>;
	using PCLIBPE_DEBUG_VEC = const LIBPE_DEBUG_VEC*;
```
### [](#)GetTLS
```cpp
HRESULT GetTLS(PCLIBPE_TLS&);
```
Gets file's **Thread Local Storage** information.
```cpp
struct LIBPE_TLS {
    DWORD              dwOffsetTLS;       //File's raw offset of the TLS header descriptor.
    union LIBPE_TLS_VAR {
    	IMAGE_TLS_DIRECTORY32 stTLSDir32; //x86 standard TLS header.
    	IMAGE_TLS_DIRECTORY64 stTLSDir64; //x64 TLS header.
    }varTLS;
    std::vector<DWORD> vecTLSCallbacks;   //Array of the TLS callbacks.
};
using PCLIBPE_TLS = const LIBPE_TLS*;
```
### [](#)GetLoadConfig
```cpp
HRESULT GetLoadConfig(PCLIBPE_LOADCONFIG&);
```
Gets files's **LCD** info.
```cpp
struct LIBPE_LOADCONFIG {
    DWORD dwOffsetLCD; //File's raw offset of the LCD descriptor.
    union LIBPE_LOADCONFIG_VAR {
    	IMAGE_LOAD_CONFIG_DIRECTORY32 stLCD32; //x86 LCD descriptor.
    	IMAGE_LOAD_CONFIG_DIRECTORY64 stLCD64; //x64 LCD descriptor.
    }varLCD;
};
using PCLIBPE_LOADCONFIG = const LIBPE_LOADCONFIG*;
```
### [](#)GetBoundImport
```cpp
HRESULT GetBoundImport(PCLIBPE_BOUNDIMPORT_VEC&);
```
Gets array of the file's **Bound Import** entries.
```cpp
struct LIBPE_BOUNDFORWARDER {
    DWORD                     dwOffsetBoundForwDesc; //File's raw offset of the Bound Forwarder descriptor.
    IMAGE_BOUND_FORWARDER_REF stBoundForwarder;      //Standard IMAGE_BOUND_FORWARDER_REF struct.
    std::string               strBoundForwarderName; //Bound forwarder name.
};
struct LIBPE_BOUNDIMPORT {
    DWORD                             dwOffsetBoundImpDesc; //File's raw offset of the Bound Import descriptor.
    IMAGE_BOUND_IMPORT_DESCRIPTOR     stBoundImpDesc;       //Standard IMAGE_BOUND_IMPORT_DESCRIPTOR struct.
    std::string                       strBoundName;         //Bound Import name.
    std::vector<LIBPE_BOUNDFORWARDER> vecBoundForwarder;    //Array of the Bound Forwarder structs.
};
using LIBPE_BOUNDIMPORT_VEC = std::vector<LIBPE_BOUNDIMPORT>;
using PCLIBPE_BOUNDIMPORT_VEC = const LIBPE_BOUNDIMPORT_VEC*;
```
### [](#)GetDelayImport
```cpp
HRESULT GetDelayImport(PCLIBPE_DELAYIMPORT_VEC&);
```
Gets array of the file's **Delay Import** entries.
```cpp
struct LIBPE_DELAYIMPORT_FUNC {
    union LIBPE_DELAYIMPORT_THUNK_VAR
    {
    	struct x32 {
    	    IMAGE_THUNK_DATA32 stImportAddressTable;      //x86 Import Address Table struct.
    	    IMAGE_THUNK_DATA32 stImportNameTable;         //x86 Import Name Table struct.
    	    IMAGE_THUNK_DATA32 stBoundImportAddressTable; //x86 Bound Import Address Table struct.
    	    IMAGE_THUNK_DATA32 stUnloadInformationTable;  //x86 Unload Information Table struct.
    	}st32;
    	struct x64 {
    	    IMAGE_THUNK_DATA64 stImportAddressTable;      //x64 Import Address Table struct.
    	    IMAGE_THUNK_DATA64 stImportNameTable;         //x64 Import Name Table struct.
            IMAGE_THUNK_DATA64 stBoundImportAddressTable; //x64 Bound Import Address Table struct
            IMAGE_THUNK_DATA64 stUnloadInformationTable;  //x64 Unload Information Table struct.
    	}st64;
    }varThunk;
    IMAGE_IMPORT_BY_NAME stImpByName; //Standard IMAGE_IMPORT_BY_NAME struct.
    std::string          strFuncName; //Function name.
};
struct LIBPE_DELAYIMPORT {
    DWORD                               dwOffsetDelayImpDesc; //File's raw offset of the Delay Import descriptor.
    IMAGE_DELAYLOAD_DESCRIPTOR          stDelayImpDesc;       //Standard IMAGE_DELAYLOAD_DESCRIPTOR struct.
    std::string                         strModuleName;        //Import module name.
    std::vector<LIBPE_DELAYIMPORT_FUNC> vecDelayImpFunc;      //Array of the Delay Import module functions.
};
using LIBPE_DELAYIMPORT_VEC = std::vector<LIBPE_DELAYIMPORT>;
using PCLIBPE_DELAYIMPORT_VEC = const LIBPE_DELAYIMPORT_VEC*;

```
### [](#)GetCOMDescriptor
```cpp
HRESULT GetCOMDescriptor(PCLIBPE_COMDESCRIPTOR&);
```
Gets file's **.NET** info.
```cpp
struct LIBPE_COMDESCRIPTOR {
    DWORD              dwOffsetComDesc; //File's raw offset of the IMAGE_COR20_HEADER descriptor.
    IMAGE_COR20_HEADER stCorHdr;        //Standard IMAGE_COR20_HEADER struct.
};
using PCLIBPE_COMDESCRIPTOR = const LIBPE_COMDESCRIPTOR*;
```
### [](#)Destroy
```cpp
HRESULT Destroy();
```
Destroys the **libpe** object.

You don't usally call this method, it will be called automatically during object destruction. 

#### Lore
Factory function `Createlibpe` returns `IlibpeUnPtr` - `unique_ptr` with custom deleter.<br>
In the client code you should use `libpe_ptr` type which is an alias to either `IlibpeUnPtr` - a `unique_ptr`, or `IlibpeShPtr` - a `shared_ptr`.
```cpp
//using libpe_ptr = IlibpeUnPtr;
using libpe_ptr = IlibpeShPtr;
```
Uncomment what serves best for you, and comment out the other.<br>
If you, for some reason, need a raw pointer, you can directly call `CreateRawlibpe` function, which returns `Ilibpe` interface pointer, but in this case you will need to call `Ilibpe::Destroy` method manually afterwards - to destroy `Ilibpe` object.			

## [](#)Error Codes
All **libpe** methods return `S_OK` code when they executed successfully.<br>
Although, if something goes wrong the error codes come onto the scene.<br>

| Error code                          | Value  |
|-------------------------------------|--------|
| E_CALL_LOADPE_FIRST                 | 0xFFFF |
| E_FILE_CREATEFILE_FAILED            | 0x0010 |
| E_FILE_SIZE_TOO_SMALL               | 0x0011 |
| E_FILE_CREATEFILEMAPPING_FAILED     | 0x0012 |
| E_FILE_MAPVIEWOFFILE_FAILED         | 0x0013 |
| E_FILE_MAPVIEWOFFILE_SECTION_FAILED | 0x0014 |
| E_FILE_SECTION_DATA_CORRUPTED       | 0x0015 |
| E_IMAGE_TYPE_UNSUPPORTED            | 0x0016 |
| E_IMAGE_HAS_NO_DOSHEADER            | 0x0017 |
| E_IMAGE_HAS_NO_RICHHEADER           | 0x0018 |
| E_IMAGE_HAS_NO_NTHEADER             | 0x0019 |
| E_IMAGE_HAS_NO_FILEHEADER           | 0x001A |
| E_IMAGE_HAS_NO_OPTHEADER            | 0x001B |
| E_IMAGE_HAS_NO_DATADIRECTORIES      | 0x001C |
| E_IMAGE_HAS_NO_SECTIONS             | 0x001D |
| E_IMAGE_HAS_NO_EXPORT               | 0x001E |
| E_IMAGE_HAS_NO_IMPORT               | 0x001F |
| E_IMAGE_HAS_NO_RESOURCE             | 0x0020 |
| E_IMAGE_HAS_NO_EXCEPTION            | 0x0021 |
| E_IMAGE_HAS_NO_SECURITY             | 0x0022 |
| E_IMAGE_HAS_NO_BASERELOC            | 0x0023 |
| E_IMAGE_HAS_NO_DEBUG                | 0x0024 |
| E_IMAGE_HAS_NO_ARCHITECTURE         | 0x0025 |
| E_IMAGE_HAS_NO_GLOBALPTR            | 0x0026 |
| E_IMAGE_HAS_NO_TLS                  | 0x0027 |
| E_IMAGE_HAS_NO_LOADCONFIG           | 0x0028 |
| E_IMAGE_HAS_NO_BOUNDIMPORT          | 0x0029 |
| E_IMAGE_HAS_NO_IAT                  | 0x002A |
| E_IMAGE_HAS_NO_DELAYIMPORT          | 0x002B |
| E_IMAGE_HAS_NO_COMDESCRIPTOR        | 0x002C |

If you want to get these error codes in readable format here is the helper `std::map`
```cpp
#define TO_WSTR_MAP(x) {x, L## #x}
inline const std::map<DWORD, std::wstring> g_mapLibpeErrors {
    TO_WSTR_MAP(E_CALL_LOADPE_FIRST),
    TO_WSTR_MAP(E_FILE_CREATEFILE_FAILED),
    TO_WSTR_MAP(E_FILE_SIZE_TOO_SMALL),
    TO_WSTR_MAP(E_FILE_CREATEFILEMAPPING_FAILED),
    TO_WSTR_MAP(E_FILE_MAPVIEWOFFILE_FAILED),
    TO_WSTR_MAP(E_FILE_MAPVIEWOFFILE_SECTION_FAILED),
    TO_WSTR_MAP(E_FILE_SECTION_DATA_CORRUPTED),
    TO_WSTR_MAP(E_IMAGE_TYPE_UNSUPPORTED),
    TO_WSTR_MAP(E_IMAGE_HAS_NO_DOSHEADER),
    TO_WSTR_MAP(E_IMAGE_HAS_NO_RICHHEADER),
    TO_WSTR_MAP(E_IMAGE_HAS_NO_NTHEADER),
    TO_WSTR_MAP(E_IMAGE_HAS_NO_FILEHEADER),
    TO_WSTR_MAP(E_IMAGE_HAS_NO_OPTHEADER),
    TO_WSTR_MAP(E_IMAGE_HAS_NO_DATADIRECTORIES),
    TO_WSTR_MAP(E_IMAGE_HAS_NO_SECTIONS),
    TO_WSTR_MAP(E_IMAGE_HAS_NO_EXPORT),
    TO_WSTR_MAP(E_IMAGE_HAS_NO_IMPORT),
    TO_WSTR_MAP(E_IMAGE_HAS_NO_RESOURCE),
    TO_WSTR_MAP(E_IMAGE_HAS_NO_EXCEPTION),
    TO_WSTR_MAP(E_IMAGE_HAS_NO_SECURITY),
    TO_WSTR_MAP(E_IMAGE_HAS_NO_BASERELOC),
    TO_WSTR_MAP(E_IMAGE_HAS_NO_DEBUG),
    TO_WSTR_MAP(E_IMAGE_HAS_NO_ARCHITECTURE),
    TO_WSTR_MAP(E_IMAGE_HAS_NO_GLOBALPTR),
    TO_WSTR_MAP(E_IMAGE_HAS_NO_TLS),
    TO_WSTR_MAP(E_IMAGE_HAS_NO_LOADCONFIG),
    TO_WSTR_MAP(E_IMAGE_HAS_NO_BOUNDIMPORT),
    TO_WSTR_MAP(E_IMAGE_HAS_NO_IAT),
    TO_WSTR_MAP(E_IMAGE_HAS_NO_DELAYIMPORT),
    TO_WSTR_MAP(E_IMAGE_HAS_NO_COMDESCRIPTOR)
};
```
You can use it as follows:
```cpp
libpe_ptr pLibpe { Createlibpe() };

HRESULT hr = pLibpe->LoadPe(L"C:\\MyFile.exe");
if (hr != S_OK)
{
    WCHAR wstr[MAX_PATH];
    const auto it = g_mapLibpeErrors.find(hr);
    if (it != g_mapLibpeErrors.end())
    	swprintf_s(wstr, L"File load failed with libpe error code: 0x0%X\n%s", hr, it->second.data());
    else
    	swprintf_s(wstr, L"File load failed with libpe error code: 0x0%X", hr);

    MessageBoxW(nullptr, wstr, L"File load failed.", MB_ICONERROR);
}
```

## [](#)**License**
This software is available under the **MIT License**.

## [](#)Help Point
If you would like to help the author in further project's development you can do it in form of donation:

[![paypal](https://www.paypalobjects.com/en_US/i/btn/btn_donateCC_LG.gif)](https://www.paypal.com/cgi-bin/webscr?cmd=_donations&business=M6CX4QH8FJJDL&currency_code=USD&source=url)