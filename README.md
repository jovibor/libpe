## libpe
**PE32**/**PE32+** binaries viewer library.

## Table of Contents
* [Introduction](#introduction)
* [Usage](#usage)
* [Methods](#methods) <details><summary>_Expand_</summary>
  * [LoadPe (from disk)](#loadpedisk)
  * [LoadPe (from memory)](#loadpemem)
  * [GetFileInfo](#getfileinfo)
  * [GetOffsetFromRVA](#getoffsetfromrva)
  * [GetOffsetFromVA](#getoffsetfromva)
  * [GetMSDOSHeader](#getmsdosheader)
  * [GetRichHeader](#getrichheader)
  * [GetNTHeader](#getntheader)
  * [GetDataDirs](#getdatadirs)
  * [GetSecHeaders](#getsecheaders)
  * [GetExport](#getexport)
  * [GetImport](#getimport)
  * [GetResources](#getresources)
  * [FlatResources](#flatresources)
  * [GetExceptions](#getexceptions)
  * [GetSecurity](#getsecurity)
  * [GetRelocations](#getrelocations)
  * [GetDebug](#getdebug)
  * [GetTLS](#gettls)
  * [GetLoadConfig](#getloadconfig)
  * [GetBoundImport](#getboundimport)
  * [GetDelayImport](#getdelayimport)
  * [GetCOMDescriptor](#getcomdescriptor)
  * [Clear](#clear)
  * [Destroy](#destroy)
  </details>
* [Maps](#maps) <details><summary>_Expand_</summary>
  * [MapFileHdrMachine](#mapfilehdrmachine)
  * [MapFileHdrCharact](#mapfilehdrcharact)
  * [MapOptHdrMagic](#mapopthdrmagic)
  * [MapOptHdrSubsystem](#mapopthdrsubsystem)
  * [MapOptHdrDllCharact](#mapophdrdllcharact)
  * [MapSecHdrCharact](#mapsechdrcharact)
  * [MapResID](#mapresid)
  * [MapWinCertRevision](#mapwincertrevision)
  * [MapWinCertType](#mapwincerttype)
  * [MapRelocType](#mapreloctype)
  * [MapDbgType](#mapdbgtype)
  * [MapTLSCharact](#maptlscharact)
  * [MapLCDGuardFlags](#maplcdguardflags)
  * [MapCOR20Flags](#mapcor20flags)
  </details>
* [Global Functions](#global-functions)
  * [CreateRawlibpe](#createrawlibpe)
  * [GetLibInfo](#getlibinfo)
* [License](#license)

## [](#)Introduction
**libpe** is a Windows library for obtaining inner information from the [Portable Executable Format](https://docs.microsoft.com/en-us/windows/win32/debug/pe-format) binaries. The library is implemented as a pure abstract virtual interface with a decent amount of methods. 

* Works with PE32(x86) and PE32+(x64) binaries
* Supports PE32/PE32+ binaries of any size (although PE format is restricted to **4GB**)
* All inner PE32/PE32+ data structures, headers and layouts
    * MSDOS Header
    * «Rich» Header
    * NT/File/Optional Headers
    * Data Directories
    * Sections
    * Export Table
    * Import Table
    * Resource Table
    * Exceptions Table
    * Security Table
    * Relocations Table
    * Debug Table
    * TLS Table
    * Load Config Directory
    * Bound Import Table
    * Delay Import Table
    * COM Table
* Built with **/std:c++20** standard conformance

[Pepper](https://github.com/jovibor/Pepper) is one of the gui apps that is built on top of the **libpe**, and using it extensively.

## [](#)Usage
The usage of the library is quite simple:
1. Add *libpe.h/libpe.cpp* into your project
2. Declare `IlibpePtr` variable as: `IlibpePtr m_pLibpe { Createlibpe() };`

Factory function `Createlibpe` returns `IlibpePtr` - a `std::unique_ptr` with custom deleter.  

If you, for some reason, need a raw interface pointer, you can directly call [`CreateRawlibpe`](#createrawlibpe) function, which returns `Ilibpe*` interface pointer, but in this case you will need to call [`Destroy`](#destroy) method manually afterwards, to destroy `Ilibpe` object.

To use `libpe` as a shared `.dll`:
1. Compile `libpe` as a `.dll` from the MSVS solution
2. Put the `#define LIBPE_SHARED_DLL` macro into your project, before `#include "libpe.h"`.

The **libpe** uses its own `libpe` namespace.

## [](#)Methods
### <a name="loadpedisk"></a>LoadPe
```cpp
auto LoadPe(LPCWSTR)->int;
```
This is the first method you call to proceed a PE file.
```cpp
IlibpePtr pLibpe { Createlibpe() };
if(pLibpe->LoadPe(L"C:\\MyFile.exe") == PEOK)
{
    ...
}
```
After this method succeeds you then can call all the other methods to retrieve needed information. The PE file itself doesn't stay in memory any longer, so you don't have to explicitly unload it.

### <a name="loadpemem"></a>LoadPe
```cpp
auto LoadPe(std::span<const std::byte> spnFile)->int;
```
This method overload is used to parse a PE file that is already in memory.

## [](#)GetFileInfo
```cpp
auto GetFileInfo()const->PEFILEINFO;
```
Retrieves `PEFILEINFO` structure that contains all service information about the loaded file.
```cpp
struct PEFILEINFO {
    bool fIsx86 : 1 {};
    bool fIsx64 : 1 {};
    bool fHasDosHdr : 1 {};
    bool fHasRichHdr : 1 {};
    bool fHasNTHdr : 1 {};
    bool fHasDataDirs : 1 {};
    bool fHasSections : 1 {};
    bool fHasExport : 1 {};
    bool fHasImport : 1 {};
    bool fHasResource : 1 {};
    bool fHasException : 1 {};
    bool fHasSecurity : 1 {};
    bool fHasReloc : 1 {};
    bool fHasDebug : 1 {};
    bool fHasArchitect : 1 {};
    bool fHasGlobalPtr : 1 {};
    bool fHasTLS : 1 {};
    bool fHasLoadCFG : 1 {};
    bool fHasBoundImp : 1 {};
    bool fHasIAT : 1 {};
    bool fHasDelayImp : 1 {};
    bool fHasCOMDescr : 1 {};
};
```

### [](#)GetOffsetFromRVA
```cpp
auto GetOffsetFromRVA(ULONGLONG ullRVA)const->DWORD;
```
Converts file's **RVA** (Relative Virtual Address) to the raw file offset.

### [](#)GetOffsetFromVA
```cpp
auto GetOffsetFromVA(ULONGLONG ullVA)const->DWORD;
```
Converts file's **VA**  (Virtual Address) to the raw file offset.

### [](#)GetMSDOSHeader
```cpp
auto GetMSDOSHeader()->IMAGE_DOS_HEADER*;
```
Gets file's standard **MSDOS** header.

### [](#)GetRichHeader
```cpp
auto GetRichHeader()->PERICHHDR_VEC*;
```
Gets array of the unofficial and undocumented, so called, **«Rich»** header structures.
```cpp
struct PERICHHDR {
    DWORD dwOffset; //File's raw offset of the entry.
    WORD  wId;      //Entry Id.
    WORD  wVersion; //Entry version.
    DWORD dwCount;  //Amount of occurrences.
};
using PERICHHDR_VEC = std::vector<PERICHHDR>;
```

### [](#)GetNTHeader
```cpp
auto GetNTHeader()->PENTHDR*;
```
Gets file's **NT** header.
```cpp
struct PENTHDR {
    DWORD dwOffset; //File's raw offset of the header.
    union UNPENTHDR { //Union of either x86 or x64 NT header.
        IMAGE_NT_HEADERS32 stNTHdr32; //x86 Header.
        IMAGE_NT_HEADERS64 stNTHdr64; //x64 Header.
    } unHdr;
};
```

### [](#)GetDataDirs
```cpp
auto GetDataDirs()->PEDATADIR_VEC*;
```
Gets array of the file's **Data directories** structs.
```cpp
struct PEDATADIR {
	IMAGE_DATA_DIRECTORY stDataDir;  //Standard header.
	std::string          strSection; //Name of the section this directory resides in (points to).
};
using PEDATADIR_VEC = std::vector<PEDATADIR>;
```

### [](#)GetSecHeaders
```cpp
auto GetSecHeaders()->PESECHDR_VEC*
```
Gets array of the file's **Sections headers** structs.
```cpp
struct PESECHDR {
	DWORD                dwOffset;   //File's raw offset of the section header descriptor.
	IMAGE_SECTION_HEADER stSecHdr;   //Standard section header.
	std::string          strSecName; //Section full name.
};
using PESECHDR_VEC = std::vector<PESECHDR>;
```

### [](#)GetExport
```cpp
auto GetExport()->PEEXPORT*;
```
Gets file's **Export** information.
```cpp
struct PEEXPORTFUNC {
    DWORD       dwFuncRVA;        //Function RVA.
    DWORD       dwOrdinal;        //Function ordinal.
    DWORD       dwNameRVA;        //Name RVA.
    std::string strFuncName;      //Function name.
    std::string strForwarderName; //Function forwarder name.
};
struct PEEXPORT {
    DWORD                     dwOffset;      //File's raw offset of the Export header descriptor.
    IMAGE_EXPORT_DIRECTORY    stExportDesc;  //Standard export header descriptor.
    std::string               strModuleName; //Actual module name.
    std::vector<PEEXPORTFUNC> vecFuncs;      //Array of the exported functions struct.	
};
```
**Example**  
Getting Export information is very simple:
```cpp
IlibpePtr pLibpe { Createlibpe() };
pLibpe->LoadPe(L"PATH_TO_PE_FILE");
const auto pExport = pLibpe->GetExport();

pExport->stExportDesc;  //IMAGE_EXPORT_DIRECTORY struct.
pExport->strModuleName; //Export module name.
pExport->vecFuncs;      //Vector of exported functions.

for (const auto& itFuncs : pExport->vecFuncs)
{
    itFuncs.strFuncName;      //Function name.
    itFuncs.dwOrdinal;        //Ordinal.
    itFuncs.dwRVA;            //Function RVA.
    itFuncs.strForwarderName; //Forwarder name.
}
```

### [](#)GetImport
```cpp
auto GetImport()->PEIMPORT_VEC*;
```
Gets array of the file's **Import table** entries.
```cpp
struct PEIMPORTFUNC {
    union UNPEIMPORTTHUNK {
    	IMAGE_THUNK_DATA32 stThunk32; //x86 standard thunk.
	    IMAGE_THUNK_DATA64 stThunk64; //x64 standard thunk.
	} unThunk;
    IMAGE_IMPORT_BY_NAME stImpByName; //Standard IMAGE_IMPORT_BY_NAME struct
    std::string          strFuncName; //Function name.
};
struct PEIMPORT {
    DWORD                     dwOffset;      //File's raw offset of the Import descriptor.
    IMAGE_IMPORT_DESCRIPTOR   stImportDesc;  //Standard Import descriptor.
    std::string               strModuleName; //Imported module name.
    std::vector<PEIMPORTFUNC> vecImportFunc; //Array of imported functions.
};
using PEIMPORT_VEC = std::vector<PEIMPORT>;
```

**Example**  
To obtain **Import table** information from the file see the following code:
```cpp
IlibpePtr pLibpe { Createlibpe() };
pLibpe->LoadPe(L"PATH_TO_PE_FILE");
const auto pImport = pLibpe->GetImport();

for (auto& itModule : *pImport) //Cycle through all imports that this PE file contains.
{
    auto pImpDesc = &itModule.stImportDesc; //IMAGE_IMPORT_DESCRIPTOR struct.
    auto& str = itModule.strModuleName;     //Name of the import module.
	
    for (auto& itFuncs : itModule.vecImportFunc) //Cycle through all the functions imported from itModule module.
    {
    	itFuncs.strFuncName;        //Imported function name (std::string).
        itFuncs.stImpByName;        //IMAGE_IMPORT_BY_NAME struct for this function.
       
        itFuncs.varThunk.stThunk32; //Union of IMAGE_THUNK_DATA32 or IMAGE_THUNK_DATA64 (depending on the binary type).
        if(pLibpe->GetFileInfo().fIsx86)
            itFuncs.unThunk.stThunk32 //Process stThunk32 data
        else
            itFuncs.unThunk.stThunk64 //Process stThunk64 data
    }
}
```

### [](#)GetResources
```cpp
auto GetResources()->PERESROOT*;
```
Retrieves all the binary's resources.

##### Example:
The next code excerpt populates `std::wstring` with all resources' types and names that PE binary possesses, and prints it to the standard `std::wcout`.
```cpp
#include <iostream>
#include <map>
#include "libpe.h"

int main()
{
	using namespace libpe;
	IlibpePtr pLibpe { Createlibpe() };
	if (pLibpe->LoadPe(PATH_TO_FILE) != PEOK)
		return -1;

	const auto pResRoot = pLibpe->GetResources();

	wchar_t wstr[MAX_PATH];
	long ilvlRoot = 0, ilvl2 = 0, ilvl3 = 0;
	std::wstring wstring; // This wstring will contain all resources by name.

	//Main loop to extract Resources.
	for (auto& iterRoot : pResRoot->vecResData)
	{
		auto pResDirEntry = &iterRoot.stResDirEntry; //ROOT IMAGE_RESOURCE_DIRECTORY_ENTRY
		if (pResDirEntry->NameIsString)
			swprintf(wstr, MAX_PATH, L"Entry: %li [Name: %s]", ilvlRoot, iterRoot.wstrResName.data());
		else
		{
			if (const auto iter = MapResID.find(pResDirEntry->Id); iter != MapResID.end())
				swprintf(wstr, MAX_PATH, L"Entry: %li [Id: %u, %s]", ilvlRoot, pResDirEntry->Id, iter->second.data());
			else
				swprintf(wstr, MAX_PATH, L"Entry: %li [Id: %u]", ilvlRoot, pResDirEntry->Id);
		}

		if (pResDirEntry->DataIsDirectory)
		{
			wstring += wstr;
			wstring += L"\r\n";
			ilvl2 = 0;

			auto pstResLvL2 = &iterRoot.stResLvL2;
			for (auto& iterLvL2 : pstResLvL2->vecResData)
			{
				pResDirEntry = &iterLvL2.stResDirEntry; //Level 2 IMAGE_RESOURCE_DIRECTORY_ENTRY
				if (pResDirEntry->NameIsString)
					swprintf(wstr, MAX_PATH, L"Entry: %li, Name: %s", ilvl2, iterLvL2.wstrResName.data());
				else
					swprintf(wstr, MAX_PATH, L"Entry: %li, Id: %u", ilvl2, pResDirEntry->Id);

				if (pResDirEntry->DataIsDirectory)
				{
					wstring += L"    ";
					wstring += wstr;
					wstring += L"\r\n";
					ilvl3 = 0;

					auto pstResLvL3 = &iterLvL2.stResLvL3;
					for (auto& iterLvL3 : pstResLvL3->vecResData)
					{
						pResDirEntry = &iterLvL3.stResDirEntry; //Level 3 IMAGE_RESOURCE_DIRECTORY_ENTRY
						if (pResDirEntry->NameIsString)
							swprintf(wstr, MAX_PATH, L"Entry: %li, Name: %s", ilvl3, iterLvL3.wstrResName.data());
						else
							swprintf(wstr, MAX_PATH, L"Entry: %li, lang: %u", ilvl3, pResDirEntry->Id);

						wstring += L"        ";
						wstring += wstr;
						wstring += L"\r\n";
						++ilvl3;
					}
				}
				++ilvl2;
			}
		}
		++ilvlRoot;
	}
	std::wcout << wstring;
}
```

### [](#)FlatResources
```cpp
static auto FlatResources(PERESROOT& stResRoot)->PERESFLAT_VEC;
```
This `static` function is kind of a light version of the `GetResources` method. It takes `PERESROOT` struct returned by the `GetResources`, and returns `std::vector` of `PERESFLAT` structures.  
`PERESFLAT` is a light struct that only possesses a pointers to the actual resources data, unlike heavy `PERESROOT`. `FlatResources` flattens all the resources, making accessing them more convenient.
```cpp
struct PERESFLAT {
    std::span<const std::byte> spnData { };    //Resource data.
    std::wstring_view          wsvTypeStr { }; //Resource Type name.
    std::wstring_view          wsvNameStr { }; //Resource Name name (resource itself name).
    std::wstring_view          wsvLangStr { }; //Resource Lang name.
    WORD                       wTypeID { };    //Resource Type ID (RT_CURSOR, RT_BITMAP, etc...).
    WORD                       wNameID { };    //Resource Name ID (resource itself ID).
    WORD                       wLangID { };    //Resource Lang ID.
};
using PERESFLAT_VEC = std::vector<PERESFLAT>;
```

### [](#)GetExceptions
```cpp
auto GetExceptions()->PEEXCEPTION_VEC*;
```
Gets array of the file's **Exception** entries.
```cpp
struct PEEXCEPTION {
    DWORD                         dwOffset;           //File's raw offset of the exceptions descriptor.
    _IMAGE_RUNTIME_FUNCTION_ENTRY stRuntimeFuncEntry; //Standard _IMAGE_RUNTIME_FUNCTION_ENTRY header.
};
using PEEXCEPTION_VEC = std::vector<PEEXCEPTION>;
```

### [](#)GetSecurity
```cpp
auto GetSecurity()->PESECURITY_VEC*;
```
Gets array of the file's **Security** entries.
```cpp
struct PESECURITY {
    DWORD           dwOffset;  //File's raw offset of the security descriptor.
    WIN_CERTIFICATE stWinSert; //Standard WIN_CERTIFICATE header.
};
using PESECURITY_VEC = std::vector<PESECURITY>;
```

### [](#)GetRelocations
```cpp
auto GetRelocations()->PERELOC_VEC*;
```
Gets array of the file's relocation information.
```cpp
struct PERELOCDATA {
    DWORD dwOffset;     //File's raw offset of the Relocation data descriptor.
    WORD  wRelocType;   //Relocation type.
    WORD  wRelocOffset; //Relocation offset (Offset the relocation must be applied to.)
};
struct PERELOC {
    DWORD                    dwOffset;     //File's raw offset of the Relocation descriptor.
    IMAGE_BASE_RELOCATION    stBaseReloc;  //Standard IMAGE_BASE_RELOCATION header.
    std::vector<PERELOCDATA> vecRelocData; //Array of the Relocation data struct.
};
using PERELOC_VEC = std::vector<PERELOC>;
```

### [](#)GetDebug
```cpp
auto GetDebug()->PEDEBUG_VEC*;
```
Gets array of the file's **Debug** entries.
```cpp
struct PEDEBUGDBGHDR {
    //dwHdr[6] is an array of the first six DWORDs of IMAGE_DEBUG_DIRECTORY::PointerToRawData data (Debug info header).
    //Their meaning varies depending on dwHdr[0] (Signature) value.
    //If dwHdr[0] == 0x53445352 (Ascii "RSDS") it's PDB 7.0 file:
    // Then dwHdr[1]-dwHdr[4] is GUID (*((GUID*)&dwHdr[1])). dwHdr[5] is Counter/Age.
    //If dwHdr[0] == 0x3031424E (Ascii "NB10") it's PDB 2.0 file:
    // Then dwHdr[1] is Offset. dwHdr[2] is Time/Signature. dwHdr[3] is Counter/Age.
    DWORD       dwHdr[6];
    std::string strPDBName; //PDB file name/path.
};
struct PEDEBUG {
    DWORD                 dwOffset;       //File's raw offset of the Debug descriptor.
    IMAGE_DEBUG_DIRECTORY stDebugDir;     //Standard IMAGE_DEBUG_DIRECTORY header.
    PEDEBUGDBGHDR         stDebugHdrInfo; //Debug info header.
};
using PEDEBUG_VEC = std::vector<PEDEBUG>;
```

### [](#)GetTLS
```cpp
auto GetTLS()->PETLS*;
```
Gets file's **Thread Local Storage** information.
```cpp
struct PETLS {
    DWORD              dwOffset;          //File's raw offset of the TLS header descriptor.
    union UNPETLS {
    	IMAGE_TLS_DIRECTORY32 stTLSDir32; //x86 standard TLS header.
    	IMAGE_TLS_DIRECTORY64 stTLSDir64; //x64 TLS header.
    } unTLS;
    std::vector<DWORD> vecTLSCallbacks;   //Array of the TLS callbacks.
};
```

### [](#)GetLoadConfig
```cpp
auto GetLoadConfig()->PELOADCONFIG*;
```
Gets files's **LCD** info.
```cpp
struct PELOADCONFIG {
    DWORD dwOffset;                            //File's raw offset of the LCD descriptor.
    union UNPELOADCONFIG {
    	IMAGE_LOAD_CONFIG_DIRECTORY32 stLCD32; //x86 LCD descriptor.
    	IMAGE_LOAD_CONFIG_DIRECTORY64 stLCD64; //x64 LCD descriptor.
    } unLCD;
};
```

### [](#)GetBoundImport
```cpp
auto GetBoundImport()->PEBOUNDIMPORT_VEC*;
```
Gets array of the file's **Bound Import** entries.
```cpp
struct PEBOUNDFORWARDER {
    DWORD                     dwOffset;              //File's raw offset of the Bound Forwarder descriptor.
    IMAGE_BOUND_FORWARDER_REF stBoundForwarder;      //Standard IMAGE_BOUND_FORWARDER_REF struct.
    std::string               strBoundForwarderName; //Bound forwarder name.
};
struct PEBOUNDIMPORT {
    DWORD                         dwOffset;          //File's raw offset of the Bound Import descriptor.
    IMAGE_BOUND_IMPORT_DESCRIPTOR stBoundImpDesc;    //Standard IMAGE_BOUND_IMPORT_DESCRIPTOR struct.
    std::string                   strBoundName;      //Bound Import name.
    std::vector<PEBOUNDFORWARDER> vecBoundForwarder; //Array of the Bound Forwarder structs.
};
using PEBOUNDIMPORT_VEC = std::vector<PEBOUNDIMPORT>;
```

### [](#)GetDelayImport
```cpp
auto GetDelayImport()->PEDELAYIMPORT_VEC*;
```
Gets array of the file's **Delay Import** entries.
```cpp
struct PEDELAYIMPORTFUNC {
    union UNPEDELAYIMPORTTHUNK
    {
    	struct x32 {
    		IMAGE_THUNK_DATA32 stImportAddressTable;      //x86 Import Address Table struct.
    		IMAGE_THUNK_DATA32 stImportNameTable;         //x86 Import Name Table struct.
    		IMAGE_THUNK_DATA32 stBoundImportAddressTable; //x86 Bound Import Address Table struct.
    		IMAGE_THUNK_DATA32 stUnloadInformationTable;  //x86 Unload Information Table struct.
    	} st32;
    	struct x64 {
    		IMAGE_THUNK_DATA64 stImportAddressTable;      //x64 Import Address Table struct.
    		IMAGE_THUNK_DATA64 stImportNameTable;         //x64 Import Name Table struct.
    		IMAGE_THUNK_DATA64 stBoundImportAddressTable; //x64 Bound Import Address Table struct
    		IMAGE_THUNK_DATA64 stUnloadInformationTable;  //x64 Unload Information Table struct.
    	} st64;
    } unThunk;
    IMAGE_IMPORT_BY_NAME stImpByName; //Standard IMAGE_IMPORT_BY_NAME struct.
    std::string          strFuncName; //Function name.
};
struct PEDELAYIMPORT {
    DWORD                          dwOffset;        //File's raw offset of the Delay Import descriptor.
    IMAGE_DELAYLOAD_DESCRIPTOR     stDelayImpDesc;  //Standard IMAGE_DELAYLOAD_DESCRIPTOR struct.
    std::string                    strModuleName;   //Import module name.
    std::vector<PEDELAYIMPORTFUNC> vecDelayImpFunc; //Array of the Delay Import module functions.
};
using PEDELAYIMPORT_VEC = std::vector<PEDELAYIMPORT>;
```

### [](#)GetCOMDescriptor
```cpp
auto GetCOMDescriptor()->PECOMDESCRIPTOR*;
```
Gets file's **.NET** info.
```cpp
struct PECOMDESCRIPTOR {
    DWORD              dwOffset; //File's raw offset of the IMAGE_COR20_HEADER descriptor.
    IMAGE_COR20_HEADER stCorHdr; //Standard IMAGE_COR20_HEADER struct.
};
```

### [](#)Clear
```cpp
void Clear();
```
Clears all internal structs to free the memory. Call this method if you don't need loaded PE information anymore. When calling `LoadPe` method the `Clear` is invoked automatically.

### [](#)Destroy
```cpp
void Destroy();
```
Destroys the **libpe** object.  
You don't usally call this method, it will be called automatically during object destruction. 

## [](#)Maps
A **PE** file consists of many structures, they in turn possess many fields some of which have predefined values.  
These maps are meant to alleviate such fields' conversion to a human-reading format. They are simple `std::unordered_map<DWORD, std::wstring_view>` maps.

Note that some fields can only have one value, while the others can combine many values with bitwise `or |` operation.

### [](#)MapFileHdrMachine
This map forms one of the values from `IMAGE_NT_HEADERS::IMAGE_FILE_HEADER::Machine` field.

### [](#)MapFileHdrCharact
This map forms one or more values from `IMAGE_NT_HEADERS::IMAGE_FILE_HEADER::Characteristics` field.
```cpp
const auto pNTHdr = m_pLibpe->GetNTHeader();
const auto pDescr = &pNTHdr->unHdr.stNTHdr32.FileHeader; //Same for both x86/x64.
std::wstring  wstrCharact;
for (const auto& flags : MapFileHdrCharact) {
    if (flags.first & pDescr->Characteristics) {
        wstrCharact += flags.second;
        wstrCharact += L"\n";
    }
}
```

### [](#)MapOptHdrMagic
This map forms one of the values from `IMAGE_NT_HEADERS::IMAGE_OPTIONAL_HEADER::Magic` field.

### [](#)MapOptHdrSubsystem
This map forms one of the values from `IMAGE_NT_HEADERS::IMAGE_OPTIONAL_HEADER::Subsystem` field.

### [](#)MapOptHdrDllCharact
This map forms one or more values from `IMAGE_NT_HEADERS::IMAGE_OPTIONAL_HEADER::DllCharacteristics` field.
```cpp
const auto pNTHdr = m_pLibpe->GetNTHeader();
const auto pOptHdr = &pNTHdr->unHdr.stNTHdr32.OptionalHeader //For x64: pNTHdr->unHdr.stNTHdr64.OptionalHeader
std::wstring wstrCharact;
for (const auto& flags : MapOptHdrDllCharact) {
    if (flags.first & pOptHdr->DllCharacteristics) {
        wstrCharact += flags.second;
        wstrCharact += L"\n";
    }
}
```

### [](#)MapSecHdrCharact
This map forms one or more values from `IMAGE_SECTION_HEADER::Characteristics` field.
```cpp
const auto pSecHeaders = m_pLibpe->GetSecHeaders();
std::wstring wstrCharact;
auto IdOfSection = 0; //ID of desired section.
for (const auto& flags : MapSecHdrCharact) {
    if (flags.first & pSecHeaders->at(IdOfSection).stSecHdr.Characteristics) {
        wstrCharact += flags.second;
        wstrCharact += L"\n";
    }
}
```

### [](#)MapResID
This map forms one of the values from `IMAGE_RESOURCE_DIRECTORY_ENTRY::Id` field.

### [](#)MapWinCertRevision
This map forms one of the values from  `WIN_CERTIFICATE::wRevision` field.

### [](#)MapWinCertType
This map forms one of the values from `WIN_CERTIFICATE::wCertificateType` field.

### [](#)MapRelocType
This map forms one of the values from `PERELOCDATA::wRelocType` field.

### [](#)MapDbgType
This map forms one of the values from `IMAGE_DEBUG_DIRECTORY::Type` field.

### [](#)MapTLSCharact
This map forms one of the values from `IMAGE_TLS_DIRECTORY::Characteristics` field.

### [](#)MapLCDGuardFlags
This map forms one or more values from `IMAGE_LOAD_CONFIG_DIRECTORY::GuardFlags` field.
```cpp
const auto pLCD = m_pLibpe->GetLoadConfig();
const auto pPELCD = &pLCD->unLCD.stLCD32; //For x64: pLCD->unLCD.stLCD64
std::wstring wstrGFlags;
for (const auto& flags : MapLCDGuardFlags) {
    if (flags.first & pPELCD->GuardFlags) {
        wstrGFlags += flags.second;
        wstrGFlags += L"\n";
    }
}
```

### [](#)MapCOR20Flags
This map forms one or more values from `IMAGE_COR20_HEADER::Flags` field.
```cpp
const auto pCOMDesc = m_pLibpe->GetCOMDescriptor();
std::wstring wstrFlags;
for (const auto& flags : MapCOR20Flags) {
    if (flags.first & pCOMDesc->stCorHdr.Flags) {
        wstrFlags += flags.second;
        wstrFlags += L"\n";
    }
}
```

## [](#)Global Functions

### [](#)CreateRawlibpe
```cpp
extern "C" ILIBPEAPI Ilibpe * __cdecl CreateRawlibpe();
```
It's the main function that creates raw `Ilibpe` interface pointer, but you barely need to use it in your code.  
See the [**Usage**](#usage) section for more info.

### [](#)GetLibInfo
```cpp
extern "C" ILIBPEAPI PLIBPE_INFO __cdecl GetLibInfo();
```
Returns pointer to `LIBPE_INFO`, which is **libpe** service information structure.
```cpp
struct LIBPEINFO
{
    const wchar_t* pwszVersion { };        //wchar_t string Version.
    union {
    	unsigned long long ullVersion { }; //long long number Version.
    	struct {
    		short wMajor;
    		short wMinor;
    		short wMaintenance;
    		short wRevision;
    	} stVersion;
    };
};
```

## [](#)**License**
This software is available under the **MIT License**.