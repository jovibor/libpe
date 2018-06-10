#pragma once

//Implementation of pure virtual class Ilibpe.
class Clibpe : public Ilibpe
{
public:
	Clibpe() {};
	virtual ~Clibpe();
	virtual HRESULT LoadPe(LPCWSTR lpszFileName);
	virtual HRESULT GetFileSummary(PCDWORD* pFileSummary);
	virtual HRESULT GetMSDOSHeader(PLIBPE_DOSHEADER*);
	virtual HRESULT GetMSDOSRichHeader(PLIBPE_RICH_VEC*);
	virtual HRESULT GetNTHeader(PLIBPE_NTHEADER*);
	virtual HRESULT GetFileHeader(PLIBPE_FILEHEADER*);
	virtual HRESULT GetOptionalHeader(PLIBPE_OPTHEADER*);
	virtual HRESULT GetDataDirectories(PLIBPE_DATADIRS_VEC*);
	virtual HRESULT GetSectionHeaders(PLIBPE_SECHEADER_VEC*);
	virtual HRESULT GetExportTable(PLIBPE_EXPORT*);
	virtual HRESULT GetImportTable(PLIBPE_IMPORT_VEC*);
	virtual HRESULT GetResourceTable(PLIBPE_RESOURCE_ROOT*);
	virtual HRESULT GetExceptionTable(PLIBPE_EXCEPTION_VEC*);
	virtual HRESULT GetSecurityTable(PLIBPE_SECURITY_VEC*);
	virtual HRESULT GetRelocationTable(PLIBPE_RELOCATION_VEC*);
	virtual HRESULT GetDebugTable(PLIBPE_DEBUG_VEC*);
	virtual HRESULT GetTLSTable(PLIBPE_TLS*);
	virtual HRESULT GetLoadConfigTable(PLIBPE_LOADCONFIGTABLE*);
	virtual HRESULT GetBoundImportTable(PLIBPE_BOUNDIMPORT_VEC*);
	virtual HRESULT GetDelayImportTable(PLIBPE_DELAYIMPORT_VEC*);
	virtual HRESULT GetCOMDescriptorTable(PLIBPE_COM_DESCRIPTOR*);
	virtual HRESULT Release();
private:
	PIMAGE_SECTION_HEADER PEGetSecHeaderFromRVA(ULONGLONG RVA);
	PIMAGE_SECTION_HEADER PEGetSecHeaderFromName(LPCSTR pName);
	LPVOID PERVAToPTR(ULONGLONG RVA);
	DWORD PEGetDirEntryRVA(UINT dirEntry);
	DWORD PEGetDirEntrySize(UINT dirEntry);
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
	//Clear all containers and nullify all pointers.
	void PEResetAll();

	//File size of the loaded pe
	LARGE_INTEGER m_stFileSize { };
	
	//Maximum address that can be dereferensed.
	ULONGLONG m_dwMaxPointerBound { };

	//Reserve 16K memory that we can delete to properly handle E_OUTOFMEMORY exceptions,
	//in case we catch one.
	char* m_szEmergencyMemory = new char [16384];

	//Delta after file mapping alignment.
	DWORD m_dwDeltaFileOffsetToMap { };

	//For big files that can't be mapped completely
	//shows offset a mapping begins from.
	DWORD m_dwFileOffsetToMap { };

	//Is file loaded (Mapped) completely, or section by section?
	bool m_fMapViewOfFileWhole { };

	//Flag shows PE load succession.
	bool m_fLoaded = false;

	//File summary info (type, sections, directories, etc...).
	DWORD m_dwFileSummary { };

	//Returned by CreateFileMappingW
	HANDLE m_hMapObject { };
	
	//Pointer to file mapping beginning, if mapped completely or section by section.
	LPVOID m_lpBase { };
	
	//Pointer to beginning of mapping if mapped section by section.
	LPVOID m_lpSectionBase { };
	
	//DOS header pointer.
	PIMAGE_DOS_HEADER m_pDosHeader { };
	
	//Pointer to NT header if file type is PE32.
	PIMAGE_NT_HEADERS32 m_pNTHeader32 { };
	
	//Pointer to NT header if file type is PE32+.
	PIMAGE_NT_HEADERS64 m_pNTHeader64 { };
	
	//File DOS Header
	IMAGE_DOS_HEADER m_stDOSHeader { };

	//Vector of "Rich" header entries.
	LIBPE_RICH_VEC m_vecRichHeader { };

	//Filled depending on file type (PE32/PE32+)
	LIBPE_NTHEADER m_tupNTHeader { };

	//File header
	IMAGE_FILE_HEADER m_stFileHeader { };
	
	//Filled depending on file type (PE32/PE32+)
	LIBPE_OPTHEADER m_tupOptionalHeader { };

	//Vector of DataDirectories.
	LIBPE_DATADIRS_VEC m_vecDataDirectories { };

	//Vector of all sections.
	LIBPE_SECHEADER_VEC m_vecSectionHeaders { };

	//Tuple of Export.
	LIBPE_EXPORT m_tupExport { };

	//Vector of Imports.
	LIBPE_IMPORT_VEC m_vecImportTable { };

	//Tuple of Resources
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

	//COM table descriptor
	IMAGE_COR20_HEADER m_stCOR20Header { };
};