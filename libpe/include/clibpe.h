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
	HRESULT GetPESummary(PCDWORD&) override;
	HRESULT GetMSDOSHeader(PCLIBPE_DOSHEADER&) override;
	HRESULT GetRichHeader(PCLIBPE_RICHHEADER_VEC&) override;
	HRESULT GetNTHeader(PCLIBPE_NTHEADER_VAR&) override;
	HRESULT GetFileHeader(PCLIBPE_FILEHEADER&) override;
	HRESULT GetOptionalHeader(PCLIBPE_OPTHEADER_VAR&) override;
	HRESULT GetDataDirectories(PCLIBPE_DATADIRS_VEC&) override;
	HRESULT GetSectionsHeaders(PCLIBPE_SECHEADERS_VEC&) override;
	HRESULT GetExport(PCLIBPE_EXPORT&) override;
	HRESULT GetImport(PCLIBPE_IMPORT_VEC&) override;
	HRESULT GetResources(PCLIBPE_RESOURCE_ROOT&) override;
	HRESULT GetExceptions(PCLIBPE_EXCEPTION_VEC&) override;
	HRESULT GetSecurity(PCLIBPE_SECURITY_VEC&) override;
	HRESULT GetRelocations(PCLIBPE_RELOCATION_VEC&) override;
	HRESULT GetDebug(PCLIBPE_DEBUG_VEC&) override;
	HRESULT GetTLS(PCLIBPE_TLS&) override;
	HRESULT GetLoadConfig(PCLIBPE_LOADCONFIG&) override;
	HRESULT GetBoundImport(PCLIBPE_BOUNDIMPORT_VEC&) override;
	HRESULT GetDelayImport(PCLIBPE_DELAYIMPORT_VEC&) override;
	HRESULT GetCOMDescriptor(PCLIBPE_COMDESCRIPTOR&) override;
private:
	PIMAGE_SECTION_HEADER getSecHdrFromRVA(ULONGLONG ullRVA) const;
	PIMAGE_SECTION_HEADER getSecHdrFromName(LPCSTR lpszName) const;
	LPVOID rVAToPtr(ULONGLONG ullRVA) const;
	DWORD ptrToOffset(LPCVOID lp) const;
	DWORD getDirEntryRVA(UINT uiDirEntry) const;
	DWORD getDirEntrySize(UINT uiDirEntry) const;
	template<typename T> bool isPtrSafe(const T tPtr, bool fCanReferenceBoundary = false) const;
	bool isSumOverflow(DWORD_PTR, DWORD_PTR);
	HRESULT getDirBySecMapping(DWORD dwDirectory);
	void resetAll();
	HRESULT getMSDOSHeader();
	HRESULT getRichHeader();
	HRESULT getNTFileOptHeader();
	HRESULT getDataDirectories();
	HRESULT getSectionsHeaders();
	HRESULT getExport();
	HRESULT getImport();
	HRESULT getResources();
	HRESULT getExceptions();
	HRESULT getSecurity();
	HRESULT getRelocations();
	HRESULT getDebug();
	HRESULT getArchitecture();
	HRESULT getGlobalPtr();
	HRESULT getTLS();
	HRESULT getLCD();
	HRESULT getBoundImport();
	HRESULT getIAT();
	HRESULT getDelayImport();
	HRESULT getCOMDescriptor();

	/************************************
	* Internal variables.				*
	*************************************/
	//Size of the loaded PE file.
	LARGE_INTEGER m_stFileSize { };

	//Maximum address that can be dereferensed.
	ULONGLONG m_ullwMaxPointerBound { };

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
	ULONGLONG m_ullImageBase { };

	/******************************************************
	* Next go vars for all of the loaded file structures: *
	* headers, sections, tables, etc..., that's gonna be  *
	* given to client code.								  *
	******************************************************/
	//DOS Header.
	IMAGE_DOS_HEADER m_stMSDOSHeader { };

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
	LIBPE_SECHEADERS_VEC m_vecSecHeaders { };

	//Export table.
	LIBPE_EXPORT m_stExport { };

	//Import table.
	LIBPE_IMPORT_VEC m_vecImport { };

	//Resources.
	LIBPE_RESOURCE_ROOT m_stResource { };

	//Exceptions.
	LIBPE_EXCEPTION_VEC m_vecException;

	//Security table.
	LIBPE_SECURITY_VEC m_vecSecurity { };

	//Relocations.
	LIBPE_RELOCATION_VEC m_vecRelocs { };

	//Debug Table.
	LIBPE_DEBUG_VEC m_vecDebug { };

	//TLS.
	LIBPE_TLS m_stTLS { };

	//LoadConfigTable.
	LIBPE_LOADCONFIG m_stLCD { };

	//Bound import.
	LIBPE_BOUNDIMPORT_VEC m_vecBoundImport { };

	//Delay import.
	LIBPE_DELAYIMPORT_VEC m_vecDelayImport { };

	//COM table descriptor.
	LIBPE_COMDESCRIPTOR m_stCOR20Desc { };
};