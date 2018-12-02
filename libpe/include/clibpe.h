/*********************************************************************
* Copyright (C) 2018, Jovibor: https://github.com/jovibor/			 *
* PE viewer library for x86 (PE32) and x64 (PE32+) binares.			 *
* This code is provided «AS IS» without any warranty, and			 *
* can be used without any limitations for non-commercial usage.		 *
* Additional info can be found at https://github.com/jovibor/libpe	 *
*********************************************************************/
#pragma once
#include "libpe.h"

using namespace libpe;

//Implementation of pure virtual class Ilibpe.
class Clibpe : public Ilibpe
{
public:
	Clibpe() = default;	
	virtual ~Clibpe() = default;
	Clibpe(const Clibpe&) = delete;
	Clibpe(Clibpe&&) = delete;
	Clibpe& operator=(const Clibpe&) = delete;
	Clibpe& operator=(Clibpe&&) = delete;
	HRESULT LoadPe(LPCWSTR) override;
	HRESULT GetFileSummary(PCDWORD*) override;
	HRESULT GetMSDOSHeader(PCLIBPE_DOSHEADER*) override;
	HRESULT GetRichHeader(PCLIBPE_RICHHEADER_VEC*) override;
	HRESULT GetNTHeader(PCLIBPE_NTHEADER_VAR*) override;
	HRESULT GetFileHeader(PCLIBPE_FILEHEADER*) override;
	HRESULT GetOptionalHeader(PCLIBPE_OPTHEADER_VAR*) override;
	HRESULT GetDataDirectories(PCLIBPE_DATADIRS_VEC*) override;
	HRESULT GetSectionsHeaders(PCLIBPE_SECHEADERS_VEC*) override;
	HRESULT GetExportTable(PCLIBPE_EXPORT_TUP*) override;
	HRESULT GetImportTable(PCLIBPE_IMPORT_VEC*) override;
	HRESULT GetResourceTable(PCLIBPE_RESOURCE_ROOT_TUP*) override;
	HRESULT GetExceptionTable(PCLIBPE_EXCEPTION_VEC*) override;
	HRESULT GetSecurityTable(PCLIBPE_SECURITY_VEC*) override;
	HRESULT GetRelocationTable(PCLIBPE_RELOCATION_VEC*) override;
	HRESULT GetDebugTable(PCLIBPE_DEBUG_VEC*) override;
	HRESULT GetTLSTable(PCLIBPE_TLS_TUP*) override;
	HRESULT GetLoadConfigTable(PCLIBPE_LOADCONFIGTABLE_VAR*) override;
	HRESULT GetBoundImportTable(PCLIBPE_BOUNDIMPORT_VEC*) override;
	HRESULT GetDelayImportTable(PCLIBPE_DELAYIMPORT_VEC*) override;
	HRESULT GetCOMDescriptorTable(PCLIBPE_COMDESCRIPTOR*) override;
private:
	PIMAGE_SECTION_HEADER getSecHdrFromRVA(ULONGLONG ullRVA) const;
	PIMAGE_SECTION_HEADER getSecHdrFromName(LPCSTR lpszName) const;
	LPVOID rVAToPtr(ULONGLONG ullRVA) const;
	DWORD getDirEntryRVA(UINT uiDirEntry) const;
	DWORD getDirEntrySize(UINT uiDirEntry) const;
	template<typename T> bool isPtrSafe(const T tPtr, bool fCanReferenceBoundary = false) const;
	HRESULT getDirByMappingSec(DWORD dwDirectory);
	void resetAll();
	HRESULT getMSDOSHeader();
	HRESULT getRichHeader();
	HRESULT getNTFileOptHeader();
	HRESULT getDataDirectories();
	HRESULT getSectionsHeaders();
	HRESULT getExportTable();
	HRESULT getImportTable();
	HRESULT getResourceTable();
	HRESULT getExceptionTable();
	HRESULT getSecurityTable();
	HRESULT getRelocationTable();
	HRESULT getDebugTable();
	HRESULT getArchitectureTable();
	HRESULT getGlobalPtrTable();
	HRESULT getTLSTable();
	HRESULT getLoadConfigTable();
	HRESULT getBoundImportTable();
	HRESULT getIATTable();
	HRESULT getDelayImportTable();
	HRESULT getCOMDescriptorTable();

	/************************************
	* Internal variables.				*
	*************************************/
	//Size of the loaded PE file.
	LARGE_INTEGER m_stFileSize { };

	//Maximum address that can be dereferensed.
	ULONGLONG m_dwMaxPointerBound { };

	//Reserved 16K of memory that we can delete to properly handle 
	//E_OUTOFMEMORY exceptions, in case we catch one.
	std::unique_ptr<char []> m_pEmergencyMemory = std::make_unique<char []>(0x8FFF);

	//Minimum bytes to map, if it's not possible to map file as a whole.
	const DWORD m_dwMinBytesToMap { 0xFFFF };

	//System information getting from GetSystemInfo().
	//Needed for dwAllocationGranularity.
	SYSTEM_INFO m_stSysInfo { };

	//For big files that can't be mapped completely
	//shows offset the mapping begins from.
	DWORD m_dwFileOffsetToMap { };

	//Delta after file mapping alignment.
	//m_dwDeltaFileOffsetToMap = m_dwFileOffsetToMap - dwAlignedAddressToMap;
	//dwAlignedAddressToMap = (m_dwFileOffsetToMap < SysInfo.dwAllocationGranularity) ? 0 :
	//(m_dwFileOffsetToMap - (m_dwFileOffsetToMap % SysInfo.dwAllocationGranularity));
	DWORD m_dwDeltaFileOffsetToMap { };

	//Is file loaded (mapped) completely, or section by section?
	bool m_fMapViewOfFileWhole { };

	//Flag shows PE load succession.
	bool m_fLoaded { false };

	//File summary info (type, sections, directories, etc...).
	DWORD m_dwFileSummary { };

	//Returned by CreateFileMappingW.
	HANDLE m_hMapObject { };

	//Pointer to file mapping beginning,
	//no matter if mapped completely or section by section.
	LPVOID m_lpBase { };

	//Pointer to beginning of mapping if mapped section by section.
	LPVOID m_lpSectionBase { };

	//DOS header pointer.
	PIMAGE_DOS_HEADER m_pDosHeader { };

	//NT header pointer, if file is PE32 (x86).
	PIMAGE_NT_HEADERS32 m_pNTHeader32 { };

	//NT header pointer, if file is PE32+ (x64).
	PIMAGE_NT_HEADERS64 m_pNTHeader64 { };

	//ImageBase.
	ULONGLONG m_ulImageBase { };

	/******************************************************
	* Next go vars for all of the loaded file structures: *
	* headers, sections, tables, etc..., that's gonna be  *
	* given to client code.								  *
	******************************************************/
	//DOS Header.
	IMAGE_DOS_HEADER m_stDOSHeader { };

	//«Rich» header.
	LIBPE_RICHHEADER_VEC m_vecRichHeader { };

	//NT header.
	LIBPE_NTHEADER_VAR m_varNTHeader { };

	//File header.
	IMAGE_FILE_HEADER m_stFileHeader { };

	//Optional header.
	LIBPE_OPTHEADER_VAR m_varOptHeader { };

	//DataDirectories.
	LIBPE_DATADIRS_VEC m_vecDataDirectories { };

	//Sections.
	LIBPE_SECHEADERS_VEC m_vecSectionHeaders { };

	//Export table.
	LIBPE_EXPORT_TUP m_tupExport { };

	//Import table.
	LIBPE_IMPORT_VEC m_vecImportTable { };

	//Resources.
	LIBPE_RESOURCE_ROOT_TUP m_tupResourceTable { };

	//Exceptions.
	LIBPE_EXCEPTION_VEC m_vecExceptionTable;

	//Security table.
	LIBPE_SECURITY_VEC m_vecSecurity { };

	//Relocations.
	LIBPE_RELOCATION_VEC m_vecRelocationTable { };

	//Debug Table.
	LIBPE_DEBUG_VEC m_vecDebugTable { };

	//TLS.
	LIBPE_TLS_TUP m_tupTLS { };

	//LoadConfigTable.
	LIBPE_LOADCONFIGTABLE_VAR m_varLoadConfigDir { };

	//Bound import.
	LIBPE_BOUNDIMPORT_VEC m_vecBoundImportTable { };

	//Delay import.
	LIBPE_DELAYIMPORT_VEC m_vecDelayImportTable { };

	//COM table descriptor.
	IMAGE_COR20_HEADER m_stCOR20Header { };
};