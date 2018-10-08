/*********************************************************************
* Copyright (C) 2018, Jovibor: https://github.com/jovibor/			 *
* PE viewer library for x86 (PE32) and x64 (PE32+) binares.			 *
* This code is provided «AS IS» without any warranty, and			 *
* can be used without any limitations for non-commercial usage.		 *
* Additional info can be found at https://github.com/jovibor/libpe	 *
*********************************************************************/
#pragma once

//Implementation of pure virtual class Ilibpe.
class Clibpe : public Ilibpe
{
public:
	Clibpe() {};
	virtual ~Clibpe();
	virtual HRESULT LoadPe(LPCWSTR);
	virtual HRESULT GetFileSummary(PCDWORD*);
	virtual HRESULT GetMSDOSHeader(PCLIBPE_DOSHEADER*);
	virtual HRESULT GetRichHeader(PCLIBPE_RICH_VEC*);
	virtual HRESULT GetNTHeader(PCLIBPE_NTHEADER*);
	virtual HRESULT GetFileHeader(PCLIBPE_FILEHEADER*);
	virtual HRESULT GetOptionalHeader(PCLIBPE_OPTHEADER*);
	virtual HRESULT GetDataDirectories(PCLIBPE_DATADIRS_VEC*);
	virtual HRESULT GetSectionHeaders(PCLIBPE_SECHEADER_VEC*);
	virtual HRESULT GetExportTable(PCLIBPE_EXPORT*);
	virtual HRESULT GetImportTable(PCLIBPE_IMPORT_VEC*);
	virtual HRESULT GetResourceTable(PCLIBPE_RESOURCE_ROOT*);
	virtual HRESULT GetExceptionTable(PCLIBPE_EXCEPTION_VEC*);
	virtual HRESULT GetSecurityTable(PCLIBPE_SECURITY_VEC*);
	virtual HRESULT GetRelocationTable(PCLIBPE_RELOCATION_VEC*);
	virtual HRESULT GetDebugTable(PCLIBPE_DEBUG_VEC*);
	virtual HRESULT GetTLSTable(PCLIBPE_TLS*);
	virtual HRESULT GetLoadConfigTable(PCLIBPE_LOADCONFIGTABLE*);
	virtual HRESULT GetBoundImportTable(PCLIBPE_BOUNDIMPORT_VEC*);
	virtual HRESULT GetDelayImportTable(PCLIBPE_DELAYIMPORT_VEC*);
	virtual HRESULT GetCOMDescriptorTable(PCLIBPE_COM_DESCRIPTOR*);
	virtual HRESULT Release();
private:
	PIMAGE_SECTION_HEADER PEGetSecHeaderFromRVA(ULONGLONG ullRVA);
	PIMAGE_SECTION_HEADER PEGetSecHeaderFromName(LPCSTR lpszName);
	LPVOID PERVAToPTR(ULONGLONG ullRVA);
	DWORD PEGetDirEntryRVA(UINT uiDirEntry);
	DWORD PEGetDirEntrySize(UINT uiDirEntry);
	void PEResetAll();
	HRESULT PEGetHeaders();
	HRESULT PEGetRichHeader();
	HRESULT PEGetDataDirs();
	HRESULT PEGetSectionHeaders();
	HRESULT PEGetExportTable();
	HRESULT PEGetImportTable();
	HRESULT PEGetResourceTable();
	HRESULT PEGetExceptionTable();
	HRESULT PEGetSecurityTable();
	HRESULT PEGetRelocationTable();
	HRESULT PEGetDebugTable();
	HRESULT PEGetArchitectureTable();
	HRESULT PEGetGlobalPTRTable();
	HRESULT PEGetTLSTable();
	HRESULT PEGetLoadConfigTable();
	HRESULT PEGetBoundImportTable();
	HRESULT PEGetIATTable();
	HRESULT PEGetDelayImportTable();
	HRESULT PEGetCOMDescriptorTable();

	//Size of the loaded PE file.
	LARGE_INTEGER m_stFileSize { };
	
	//Maximum address that can be dereferensed.
	ULONGLONG m_dwMaxPointerBound { };

	//Reserve 16K of memory that we can delete 
	//to properly handle E_OUTOFMEMORY exceptions,
	//in case we catch one.
	char* m_lpszEmergencyMemory = new char [16384];
	
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
	bool m_fLoaded = false;

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
	
	//Pointer to NT header if file type is PE32.
	PIMAGE_NT_HEADERS32 m_pNTHeader32 { };
	
	//Pointer to NT header if file type is PE32+.
	PIMAGE_NT_HEADERS64 m_pNTHeader64 { };

/************************************************
* Next go all structures of the loaded file:	*
* headers, sections, etc...						*
************************************************/
	//DOS Header.
	IMAGE_DOS_HEADER m_stDOSHeader { };

	//Vector of "Rich" header entries.
	LIBPE_RICH_VEC m_vecRichHeader { };

	//Filled depending on file type (PE32/PE32+).
	LIBPE_NTHEADER m_tupNTHeader { };

	//File header.
	IMAGE_FILE_HEADER m_stFileHeader { };
	
	//Filled depending on file type (PE32/PE32+).
	LIBPE_OPTHEADER m_tupOptionalHeader { };

	//Vector of DataDirectories.
	LIBPE_DATADIRS_VEC m_vecDataDirectories { };

	//Vector of all sections.
	LIBPE_SECHEADER_VEC m_vecSectionHeaders { };

	//Tuple of Export.
	LIBPE_EXPORT m_tupExport { };

	//Vector of Imports.
	LIBPE_IMPORT_VEC m_vecImportTable { };

	//Tuple of Resources.
	LIBPE_RESOURCE_ROOT m_tupResourceTable { };

	//Vector of Exceptions.
	LIBPE_EXCEPTION_VEC m_vecExceptionTable;

	//Vector of Security table.
	LIBPE_SECURITY_VEC m_vecSecurity { };

	//Vector of Relocations.
	LIBPE_RELOCATION_VEC m_vecRelocationTable { };

	//Vector of Debug Table.
	LIBPE_DEBUG_VEC m_vecDebugTable { };

	//TLS tuple.
	LIBPE_TLS m_tupTLS { };

	//LoadConfigTable tuple.
	LIBPE_LOADCONFIGTABLE m_tupLoadConfigDir { };

	//Bound import vector.
	LIBPE_BOUNDIMPORT_VEC m_vecBoundImportTable { };

	//Delay import vector.
	LIBPE_DELAYIMPORT_VEC m_vecDelayImportTable { };

	//COM table descriptor.
	IMAGE_COR20_HEADER m_stCOR20Header { };
};