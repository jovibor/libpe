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
	virtual HRESULT GetMSDOSRichHeader(PLIBPE_RICH*);
	virtual HRESULT GetNTHeader(PLIBPE_NTHEADER*);
	virtual HRESULT GetFileHeader(PLIBPE_FILEHEADER*);
	virtual HRESULT GetOptionalHeader(PLIBPE_OPTHEADER*);
	virtual HRESULT GetDataDirectories(PLIBPE_DATADIRS*);
	virtual HRESULT GetSectionHeaders(PLIBPE_SECHEADER*);
	virtual HRESULT GetExportTable(PLIBPE_EXPORT*);
	virtual HRESULT GetImportTable(PLIBPE_IMPORT*);
	virtual HRESULT GetResourceTable(PLIBPE_RESOURCE_ROOT*);
	virtual HRESULT GetExceptionTable(PLIBPE_EXCEPTION*);
	virtual HRESULT GetSecurityTable(PLIBPE_SECURITY*);
	virtual HRESULT GetRelocationTable(PLIBPE_RELOCATION*);
	virtual HRESULT GetDebugTable(PLIBPE_DEBUG*);
	virtual HRESULT GetTLSTable(PLIBPE_TLS*);
	virtual HRESULT GetLoadConfigTable(PLIBPE_LOADCONFIGTABLE*);
	virtual HRESULT GetBoundImportTable(PLIBPE_BOUNDIMPORT*);
	virtual HRESULT GetDelayImportTable(PLIBPE_DELAYIMPORT*);
	virtual HRESULT GetCOMDescriptorTable(PLIBPE_COM_DESCRIPTOR*);
	virtual HRESULT Release();
private:
	PIMAGE_SECTION_HEADER PEGetSectionHeaderFromRVA(ULONGLONG RVA);
	PIMAGE_SECTION_HEADER PEGetSectionHeaderFromName(LPCSTR pName);
	LPVOID PERVAToPTR(ULONGLONG RVA);
	DWORD PEGetDirectoryEntryRVA(UINT dirEntry);
	DWORD PEGetDirectoryEntrySize(UINT dirEntry);
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

	//File size structure
	LARGE_INTEGER m_stFileSize { };
	//Maximum address that can be dereferensed.
	ULONGLONG m_dwMaxPointerBound { };
	//Reserve 16K memory that we can delete to properly handle E_OUTOFMEMORY exceptions,
	//in case we catch one.
	char* m_lpszEmergencyMemory = new char [16384];
	//Delta after file mapping alignment.
	DWORD m_dwDeltaFileOffsetToMap { };
	//For big files that can't be mapped completely
	//shows offset which mapping begins from.
	DWORD m_dwFileOffsetToMap { };
	//Is file loaded (Mapped) completely, or section by section?
	bool m_fMapViewOfFileWhole { };
	//Flag shows PE load succession.
	bool m_fLoaded = false;
	//File summary info (type, sections, directories...).
	DWORD m_dwFileSummary { };
	HANDLE m_hMapObject { };
	//Pointer to file mapping beginning, if mapped completely or section by section.
	LPVOID m_lpBase { };
	//Pointer to beginning of mapping, if file mapped section by section.
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
	LIBPE_RICH m_vecRichHeader { };
	//Filled depending on file type (PE32/PE32+)
	LIBPE_NTHEADER m_tupleNTHeader { };
	//File header
	IMAGE_FILE_HEADER m_stFileHeader { };
	//Filled depending on file type (PE32/PE32+)
	LIBPE_OPTHEADER m_tupleOptionalHeader { };
	//Vector of DataDirectories.
	LIBPE_DATADIRS m_vecDataDirectories { };
	//Vector of all sections.
	LIBPE_SECHEADER m_vecSectionHeaders { };
	//Tuple of Export.
	LIBPE_EXPORT m_tupleExport { };
	//Vector of Imports.
	LIBPE_IMPORT m_vecImportTable { };
	//Tuple of Resources
	LIBPE_RESOURCE_ROOT m_tupleResourceTable { };
	//Vector of Exceptions.
	LIBPE_EXCEPTION m_vecExceptionTable;
	//Vector of Security table.
	LIBPE_SECURITY m_vecSecurity { };
	//Vector of Relocations.
	LIBPE_RELOCATION m_vecRelocationTable { };
	//Vector of Debug Table.
	LIBPE_DEBUG m_vecDebugTable { };
	//TLS tuple.
	LIBPE_TLS m_tupleTLS { };
	//LoadConfigTable tuple.
	LIBPE_LOADCONFIGTABLE m_tupleLoadConfigDir { };
	//Bound import vector.
	LIBPE_BOUNDIMPORT m_vecBoundImportTable { };
	//Delay import vector.
	LIBPE_DELAYIMPORT m_vecDelayImportTable { };
	//COM Descriptor
	IMAGE_COR20_HEADER m_stCOR20Header { };
};