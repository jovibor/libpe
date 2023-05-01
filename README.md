## Introduction
**libpe** is a lightweight and very fast library for parsing **PE32(x86)** and **PE32+(x64)** binaries, implemented as a C++20 module.

## Table of Contents
* [Features](#features)
* [Usage](#usage)
* [Class Methods](#class-methods) <details><summary>_Expand_</summary>
  * [OpenFile](#openfile)
  * [CloseFile](#closefile)
  * [GetDOSHeader](#getdosheader)
  * [GetRichHeader](#getrichheader)
  * [GetNTHeader](#getntheader)
  * [GetDataDirs](#getdatadirs)
  * [GetSecHeaders](#getsecheaders)
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
  </details>
* [Helper Methods](#helper-methods) <details><summary>_Expand_</summary>
  * [GetFileType](#getfiletype)
  * [GetImageBase](#getimagebase)
  * [GetOffsetFromRVA](#getoffsetfromrva)
  * [FlatResources](#flatresources)
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
* [License](#license)

## [](#)Features
* Works with both **PE32(x86)** and **PE32+(x64)** binaries
* Obtains all **PE32/PE32+** data structures:
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

[Pepper](https://github.com/jovibor/Pepper) is one of the apps that is built on top of the **libpe**.

## [](#)Usage
```cpp
import libpe;

int main() {
    libpe::Clibpe pe(L"C:\\myFile.exe"); //or pe.OpenFile(L"C:\\myFile.exe");
    const auto peImp = pe.GetImport();
    if(peImp) {
    ...
    }
    ...
}
```

## [](#)Methods
### OpenFile
```cpp
auto OpenFile(const wchar_t* pwszFile)->int;
```
Opens a file for further processing, until [`CloseFile`](#closefile) is called or `Clibpe` object goes out of scope and file closes automatically in destructor.
```cpp
libpe::Clibpe pe;
if(pe.OpenFile(L"C:\\MyFile.exe") == PEOK) {
    ...
}
```

### [](#)CloseFile();
```cpp
void CloseFile();
```
Explicitly closes file that was previously opened with the [`OpenFile(const wchar_t*)`](#openfile). This method is invoked automatically in `Clibpe` destructor.

### [](#)GetDOSHeader
```cpp
[[nodiscard]] auto GetDOSHeader()const->std::optional<IMAGE_DOS_HEADER>;
```
Returns a file's standard **MSDOS** header.

### [](#)GetRichHeader
```cpp
[[nodiscard]] auto GetRichHeader()const->std::optional<PERICHHDR_VEC>;
```
Returns an array of the unofficial and undocumented so called **«Rich»** structures.
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
[[nodiscard]] auto GetNTHeader()const->std::optional<PENTHDR>;
```
Returns a file's **NT** header.
```cpp
struct PENTHDR {
    DWORD dwOffset;   //File's raw offset of the header.
    union UNPENTHDR { //Union of either x86 or x64 NT header.
        IMAGE_NT_HEADERS32 stNTHdr32; //x86 Header.
        IMAGE_NT_HEADERS64 stNTHdr64; //x64 Header.
    } unHdr;
};
```

### [](#)GetDataDirs
```cpp
[[nodiscard]] auto GetDataDirs()const->std::optional<PEDATADIR_VEC>;
```
Returns an array of file's **Data directories** structs.
```cpp
struct PEDATADIR {
    IMAGE_DATA_DIRECTORY stDataDir;  //Standard header.
    std::string          strSection; //Name of the section this directory resides in (points to).
};
using PEDATADIR_VEC = std::vector<PEDATADIR>;
```

### [](#)GetSecHeaders
```cpp
[[nodiscard]] auto GetSecHeaders()const->std::optional<PESECHDR_VEC>;
```
Returns an array of file's **Sections headers** structs.
```cpp
struct PESECHDR {
    DWORD                dwOffset;   //File's raw offset of this section header descriptor.
    IMAGE_SECTION_HEADER stSecHdr;   //Standard section header.
    std::string          strSecName; //Section full name.
};
using PESECHDR_VEC = std::vector<PESECHDR>;
```

### [](#)GetExport
```cpp
[[nodiscard]] auto GetExport()const->std::optional<PEEXPORT>;
```
Returns a file's **Export** information.
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
**Example:**
```cpp
libpe::Clibpe pe(L"PATH_TO_PE_FILE");
const auto peExport = pe.GetExport();
if (!peExport) {
    return;
}

peExport->stExportDesc;  //IMAGE_EXPORT_DIRECTORY struct.
peExport->strModuleName; //Export module name.
peExport->vecFuncs;      //Vector of exported functions.

for (const auto& itFuncs : peExport->vecFuncs) {
    itFuncs.strFuncName;      //Function name.
    itFuncs.dwOrdinal;        //Ordinal.
    itFuncs.dwFuncRVA;        //Function RVA.
    itFuncs.strForwarderName; //Forwarder name.
}
```

### [](#)GetImport
```cpp
[[nodiscard]] auto GetImport()const->std::optional<PEIMPORT_VEC>;
```
Returns an array of file's **Import table** entries.
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
```cpp
libpe::Clibpe pe(L"C:\\Windows\\notepad.exe");
const auto peImp = pe.GetImport();
if (!peImp) {
    return -1;
}

for (const auto& itModule : *peImp) { //Cycle through all imports that this PE file contains.
    std::cout << std::format("{}, Imported funcs: {}\r\n", itModule.strModuleName, itModule.vecImportFunc.size());
    for (const auto& itFuncs : itModule.vecImportFunc) { //Cycle through all the functions imported from itModule module.
        itFuncs.strFuncName;       //Imported function name.
        itFuncs.stImpByName;       //IMAGE_IMPORT_BY_NAME struct for this function.
        itFuncs.unThunk.stThunk32; //Union of IMAGE_THUNK_DATA32 or IMAGE_THUNK_DATA64 (depending on the PE type).
    }
}
```

### [](#)GetResources
```cpp
[[nodiscard]] auto GetResources()const->std::optional<PERESROOT>;
```
Returns all file's resources.

##### Example:
The next code snippet populates `std::wstring` with all resources' types and names that PE binary possesses, and prints it to the standard `std::wcout`.
```cpp
#include <format>
#include <iostream>
#include <string>

import libpe;
using namespace libpe;

int main()
{
    libpe::Clibpe pe;
    if (pe.OpenFile(L"C:\\Windows\\notepad.exe") != PEOK) {
        return -1;
    }

    const auto peResRoot = pe.GetResources();
    if (!peResRoot) {
        return -1;
    }

    std::wstring wstrResData; //This wstring will contain all resources by name.
    for (const auto& iterRoot : peResRoot->vecResData) { //Main loop to extract Resources.
        auto ilvlRoot = 0;
        auto pResDirEntry = &iterRoot.stResDirEntry; //ROOT IMAGE_RESOURCE_DIRECTORY_ENTRY
        if (pResDirEntry->NameIsString) {
            wstrResData += std::format(L"Entry: {} [Name: {}]\r\n", ilvlRoot, iterRoot.wstrResName);
        }
        else {
            if (const auto iter = MapResID.find(pResDirEntry->Id); iter != MapResID.end()) {
                wstrResData += std::format(L"Entry: {} [Id: {}, {}]\r\n", ilvlRoot, pResDirEntry->Id, iter->second);
            }
            else {
                wstrResData += std::format(L"Entry: {} [Id: {}]\r\n", ilvlRoot, pResDirEntry->Id);
            }
        }

        if (pResDirEntry->DataIsDirectory) {
            auto ilvl2 = 0;
            auto pstResLvL2 = &iterRoot.stResLvL2;
            for (const auto& iterLvL2 : pstResLvL2->vecResData) {
                pResDirEntry = &iterLvL2.stResDirEntry; //Level 2 IMAGE_RESOURCE_DIRECTORY_ENTRY
                if (pResDirEntry->NameIsString) {
                    wstrResData += std::format(L"    Entry: {}, Name: {}\r\n", ilvl2, iterLvL2.wstrResName);
                }
                else {
                    wstrResData += std::format(L"    Entry: {}, Id: {}\r\n", ilvl2, pResDirEntry->Id);
                }

                if (pResDirEntry->DataIsDirectory) {
                    auto ilvl3 = 0;
                    auto pstResLvL3 = &iterLvL2.stResLvL3;
                    for (const auto& iterLvL3 : pstResLvL3->vecResData) {
                        pResDirEntry = &iterLvL3.stResDirEntry; //Level 3 IMAGE_RESOURCE_DIRECTORY_ENTRY
                        if (pResDirEntry->NameIsString) {
                            wstrResData += std::format(L"        Entry: {}, Name: {}\r\n", ilvl3, iterLvL3.wstrResName);
                        }
                        else {
                            wstrResData += std::format(L"        Entry: {}, lang: {}\r\n", ilvl3, pResDirEntry->Id);
                        }
                        ++ilvl3;
                    }
                }
                ++ilvl2;
            }
        }
        ++ilvlRoot;
    }
    std::wcout << wstrResData;
```

### [](#)GetExceptions
```cpp
[[nodiscard]] auto GetExceptions()const->std::optional<PEEXCEPTION_VEC>;
```
Returns an array of file's **Exception** entries.
```cpp
struct PEEXCEPTION {
    DWORD                         dwOffset;           //File's raw offset of the exceptions descriptor.
    _IMAGE_RUNTIME_FUNCTION_ENTRY stRuntimeFuncEntry; //Standard _IMAGE_RUNTIME_FUNCTION_ENTRY header.
};
using PEEXCEPTION_VEC = std::vector<PEEXCEPTION>;
```

### [](#)GetSecurity
```cpp
[[nodiscard]] auto GetSecurity()const->std::optional<PESECURITY_VEC>;
```
Returns an array of file's **Security** entries.
```cpp
struct PEWIN_CERTIFICATE { //Full replica of the WIN_CERTIFICATE struct from the <WinTrust.h>.
    DWORD dwLength;
    WORD  wRevision;
    WORD  wCertificateType;
    BYTE  bCertificate[1];
};
struct PESECURITY {
    DWORD             dwOffset;  //File's raw offset of this security descriptor.
    PEWIN_CERTIFICATE stWinSert; //Standard WIN_CERTIFICATE struct.
};
using PESECURITY_VEC = std::vector<PESECURITY>;
```

### [](#)GetRelocations
```cpp
[[nodiscard]] auto GetRelocations()const->std::optional<PERELOC_VEC>;
```
Returns an array of file's relocation information.
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
[[nodiscard]] auto GetDebug()const->std::optional<PEDEBUG_VEC>;
```
Returns an array of file's **Debug** entries.
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
[[nodiscard]] auto GetTLS()const->std::optional<PETLS>;
```
Returns file's **Thread Local Storage** information.
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
[[nodiscard]] auto GetLoadConfig()const->std::optional<PELOADCONFIG>;
```
Returns file's **Load Config Directory** info.
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
[[nodiscard]] auto GetBoundImport()const->std::optional<PEBOUNDIMPORT_VEC>;
```
Returns an array of file's **Bound Import** entries.
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
[[nodiscard]] auto GetDelayImport()const->std::optional<PEDELAYIMPORT_VEC>;
```
Returns an array of file's **Delay Import** entries.
```cpp
struct PEDELAYIMPORTFUNC {
    union UNPEDELAYIMPORTTHUNK {
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
    DWORD                          dwOffset;        //File's raw offset of this Delay Import descriptor.
    IMAGE_DELAYLOAD_DESCRIPTOR     stDelayImpDesc;  //Standard IMAGE_DELAYLOAD_DESCRIPTOR struct.
    std::string                    strModuleName;   //Import module name.
    std::vector<PEDELAYIMPORTFUNC> vecDelayImpFunc; //Array of the Delay Import module functions.
};
using PEDELAYIMPORT_VEC = std::vector<PEDELAYIMPORT>;
```

### [](#)GetCOMDescriptor
```cpp
[[nodiscard]] auto GetCOMDescriptor()const->std::optional<PECOMDESCRIPTOR>;
```
Gets file's **.NET** info.
```cpp
struct PECOMDESCRIPTOR {
    DWORD              dwOffset; //File's raw offset of the IMAGE_COR20_HEADER descriptor.
    IMAGE_COR20_HEADER stCorHdr; //Standard IMAGE_COR20_HEADER struct.
};
```

## [](#)Helper Methods
These freestanding methods do not need an active `Clibpe` object with an opened file. They instead take references to the previously obtained structures.

### [](#)GetFileType
```cpp
[[nodiscard]] inline constexpr auto GetFileType(const PENTHDR& stNTHdr)->EFileType
```
Returns **PE** file type in form of the `EFileType` enum.
```cpp
enum class EFileType : std::uint8_t {
    UNKNOWN = 0, PE32, PE64, PEROM
};
```

### [](#)GetImageBase
```cpp
[[nodiscard]] inline constexpr auto GetImageBase(const PENTHDR& stNTHdr)->ULONGLONG
```
Returns file's **Image Base**.

### [](#)GetOffsetFromRVA
```cpp
[[nodiscard]] inline constexpr auto GetOffsetFromRVA(ULONGLONG ullRVA, const PESECHDR_VEC& vecSecHdr)->DWORD
```
Converts file's RVA to the file's physical raw offset on disk.

### [](#)FlatResources
```cpp
[[nodiscard]] inline constexpr auto FlatResources(const PERESROOT& stResRoot)
```
This function is kind of a light version of the `GetResources` method. It takes `PERESROOT` struct returned by the `GetResources`, and returns `std::vector` of `PERESFLAT` structures.  
`PERESFLAT` is a light struct that only possesses pointers to an actual resources data, unlike heavy `PERESROOT`. `FlatResources` flattens all resources, making accessing them more convenient.
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

## [](#)Maps
A **PE** file consists of many structures, they in turn possess many fields some of which have predefined values.  
These maps are meant to alleviate such fields' conversion to a human-reading format. They are simple `std::unordered_map<DWORD, std::wstring_view>` maps.

Note that some fields can only have one value, while the others can combine many values with a bitwise `or |` operation.

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

## [](#)**License**
This software is available under the **MIT License**.