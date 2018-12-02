/*********************************************************************
* Copyright (C) 2018, Jovibor: https://github.com/jovibor/			 *
* PE viewer library for x86 (PE32) and x64 (PE32+) binares.			 *
* This code is provided «AS IS» without any warranty, and			 *
* can be used without any limitations for non-commercial usage.		 *
* Additional info can be found at https://github.com/jovibor/libpe	 *
*********************************************************************/
#include "stdafx.h"
#include "clibpe.h"

extern "C" HRESULT ILIBPEAPI Getlibpe(libpe::libpe_ptr& libpe_ptr)
{
	libpe_ptr = std::make_shared<Clibpe>();
	if (!libpe_ptr)
		return E_FAIL;

	return S_OK;
}

HRESULT Clibpe::LoadPe(LPCWSTR lpszFileName)
{
	if (m_fLoaded) //If other PE file was already, previously loaded.
		resetAll();

	const HANDLE hFile = CreateFileW(lpszFileName, GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
	if (hFile == INVALID_HANDLE_VALUE)
		return E_FILE_OPEN_FAILED;

	::GetFileSizeEx(hFile, &m_stFileSize);
	if (m_stFileSize.QuadPart < sizeof(IMAGE_DOS_HEADER))
	{
		CloseHandle(hFile);
		return E_FILE_SIZE_TOO_SMALL;
	}

	m_hMapObject = CreateFileMappingW(hFile, nullptr, PAGE_READONLY, 0, 0, nullptr);
	if (!m_hMapObject)
	{
		CloseHandle(hFile);
		return E_FILE_CREATE_FILE_MAPPING_FAILED;
	}

	m_lpBase = MapViewOfFile(m_hMapObject, FILE_MAP_READ, 0, 0, 0);
	if (!m_lpBase) //Not enough memory? File is too big?
	{
		if (GetLastError() == ERROR_NOT_ENOUGH_MEMORY)
		{
			//If file is too big to fit process VirtualSize limit
			//we try to allocate at least some memory to map file's beginning, where PE HEADER resides.
			//Then going to MapViewOfFile/Unmap every section individually. 
			if (!(m_lpBase = MapViewOfFile(m_hMapObject, FILE_MAP_READ, 0, 0, (DWORD_PTR)m_dwMinBytesToMap)))
			{
				CloseHandle(m_hMapObject);
				CloseHandle(hFile);
				return E_FILE_MAP_VIEW_OF_FILE_FAILED;
			}
			m_fMapViewOfFileWhole = false;
			m_dwMaxPointerBound = (DWORD_PTR)m_lpBase + (DWORD_PTR)m_dwMinBytesToMap;
			::GetSystemInfo(&m_stSysInfo);
		}
		else
		{
			CloseHandle(m_hMapObject);
			CloseHandle(hFile);
			return E_FILE_MAP_VIEW_OF_FILE_FAILED;
		}
	}
	else
	{
		m_fMapViewOfFileWhole = true;
		m_dwMaxPointerBound = (DWORD_PTR)m_lpBase + m_stFileSize.QuadPart;
	}

	if (getMSDOSHeader() != S_OK)
	{
		UnmapViewOfFile(m_lpBase);
		CloseHandle(m_hMapObject);
		CloseHandle(hFile);
		return E_IMAGE_HAS_NO_DOSHEADER;
	}
	getRichHeader();
	getNTFileOptHeader();
	getDataDirectories();
	getSectionsHeaders();

	//If file succeeded to fully map,
	//then just proceed getting all structures.
	if (m_fMapViewOfFileWhole)
	{
		getExportTable();
		getImportTable();
		getResourceTable();
		getExceptionTable();
		getSecurityTable();
		getRelocationTable();
		getDebugTable();
		getArchitectureTable();
		getGlobalPtrTable();
		getTLSTable();
		getLoadConfigTable();
		getBoundImportTable();
		getIATTable();
		getDelayImportTable();
		getCOMDescriptorTable();
	}
	else //Otherwise mapping each section separately.
	{
		getDirByMappingSec(IMAGE_DIRECTORY_ENTRY_EXPORT);
		getDirByMappingSec(IMAGE_DIRECTORY_ENTRY_IMPORT);
		getDirByMappingSec(IMAGE_DIRECTORY_ENTRY_RESOURCE);
		getDirByMappingSec(IMAGE_DIRECTORY_ENTRY_EXCEPTION);
		getDirByMappingSec(IMAGE_DIRECTORY_ENTRY_SECURITY);
		getDirByMappingSec(IMAGE_DIRECTORY_ENTRY_BASERELOC);
		getDirByMappingSec(IMAGE_DIRECTORY_ENTRY_DEBUG);
		getDirByMappingSec(IMAGE_DIRECTORY_ENTRY_ARCHITECTURE);
		getDirByMappingSec(IMAGE_DIRECTORY_ENTRY_GLOBALPTR);
		getDirByMappingSec(IMAGE_DIRECTORY_ENTRY_TLS);
		getDirByMappingSec(IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG);
		getDirByMappingSec(IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT);
		getDirByMappingSec(IMAGE_DIRECTORY_ENTRY_IAT);
		getDirByMappingSec(IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT);
		getDirByMappingSec(IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR);
	}

	UnmapViewOfFile(m_lpBase);
	CloseHandle(m_hMapObject);
	CloseHandle(hFile);

	return S_OK;
}

HRESULT Clibpe::GetFileSummary(PCDWORD* pdwFileSummary)
{
	if (!m_fLoaded)
		return E_CALL_LOADPE_FIRST;

	*pdwFileSummary = &m_dwFileSummary;

	return S_OK;
}

HRESULT Clibpe::GetMSDOSHeader(PCLIBPE_DOSHEADER* pDosHeader)
{
	if (!m_fLoaded)
		return E_CALL_LOADPE_FIRST;

	if (!ImageHasFlag(m_dwFileSummary, IMAGE_FLAG_DOSHEADER))
		return E_IMAGE_HAS_NO_DOSHEADER;

	*pDosHeader = &m_stDOSHeader;

	return S_OK;
}

HRESULT Clibpe::GetRichHeader(PCLIBPE_RICHHEADER_VEC* pVecRich)
{
	if (!m_fLoaded)
		return E_CALL_LOADPE_FIRST;

	if (!ImageHasFlag(m_dwFileSummary, IMAGE_FLAG_RICHHEADER))
		return E_IMAGE_HAS_NO_RICHHEADER;

	*pVecRich = &m_vecRichHeader;

	return S_OK;
}

HRESULT Clibpe::GetNTHeader(PCLIBPE_NTHEADER_VAR *pVarNTHdr)
{
	if (!m_fLoaded)
		return E_CALL_LOADPE_FIRST;

	if (!ImageHasFlag(m_dwFileSummary, IMAGE_FLAG_NTHEADER))
		return E_IMAGE_HAS_NO_NTHEADER;

	*pVarNTHdr = &m_varNTHeader;

	return S_OK;
}

HRESULT Clibpe::GetFileHeader(PCLIBPE_FILEHEADER* pFileHeader)
{
	if (!m_fLoaded)
		return E_CALL_LOADPE_FIRST;

	if (!ImageHasFlag(m_dwFileSummary, IMAGE_FLAG_FILEHEADER))
		return E_IMAGE_HAS_NO_FILEHEADER;

	*pFileHeader = &m_stFileHeader;

	return S_OK;
}

HRESULT Clibpe::GetOptionalHeader(PCLIBPE_OPTHEADER_VAR* pVarOptHeader)
{
	if (!m_fLoaded)
		return E_CALL_LOADPE_FIRST;

	if (!ImageHasFlag(m_dwFileSummary, IMAGE_FLAG_OPTHEADER))
		return E_IMAGE_HAS_NO_OPTHEADER;

	*pVarOptHeader = &m_varOptHeader;

	return S_OK;
}

HRESULT Clibpe::GetDataDirectories(PCLIBPE_DATADIRS_VEC* pVecDataDir)
{
	if (!m_fLoaded)
		return E_CALL_LOADPE_FIRST;

	if (!ImageHasFlag(m_dwFileSummary, IMAGE_FLAG_DATADIRECTORIES))
		return E_IMAGE_HAS_NO_DATADIRECTORIES;

	*pVecDataDir = &m_vecDataDirectories;

	return S_OK;
}

HRESULT Clibpe::GetSectionsHeaders(PCLIBPE_SECHEADERS_VEC* pVecSections)
{
	if (!m_fLoaded)
		return E_CALL_LOADPE_FIRST;

	if (!ImageHasFlag(m_dwFileSummary, IMAGE_FLAG_SECTIONS))
		return E_IMAGE_HAS_NO_SECTIONS;

	*pVecSections = &m_vecSectionHeaders;

	return S_OK;
}

HRESULT Clibpe::GetExportTable(PCLIBPE_EXPORT_TUP* pTupExport)
{
	if (!m_fLoaded)
		return E_CALL_LOADPE_FIRST;

	if (!ImageHasFlag(m_dwFileSummary, IMAGE_FLAG_EXPORT))
		return E_IMAGE_HAS_NO_EXPORT;

	*pTupExport = &m_tupExport;

	return S_OK;
}

HRESULT Clibpe::GetImportTable(PCLIBPE_IMPORT_VEC* pVecImport)
{
	if (!m_fLoaded)
		return E_CALL_LOADPE_FIRST;

	if (!ImageHasFlag(m_dwFileSummary, IMAGE_FLAG_IMPORT))
		return E_IMAGE_HAS_NO_IMPORT;

	*pVecImport = &m_vecImportTable;

	return S_OK;
}

HRESULT Clibpe::GetResourceTable(PCLIBPE_RESOURCE_ROOT_TUP* pTupRes)
{
	if (!m_fLoaded)
		return E_CALL_LOADPE_FIRST;

	if (!ImageHasFlag(m_dwFileSummary, IMAGE_FLAG_RESOURCE))
		return E_IMAGE_HAS_NO_RESOURCE;

	*pTupRes = &m_tupResourceTable;

	return S_OK;
}

HRESULT Clibpe::GetExceptionTable(PCLIBPE_EXCEPTION_VEC* pVecException)
{
	if (!m_fLoaded)
		return E_CALL_LOADPE_FIRST;

	if (!ImageHasFlag(m_dwFileSummary, IMAGE_FLAG_EXCEPTION))
		return E_IMAGE_HAS_NO_EXCEPTION;

	*pVecException = &m_vecExceptionTable;

	return S_OK;

}

HRESULT Clibpe::GetSecurityTable(PCLIBPE_SECURITY_VEC* pVecSecurity)
{
	if (!m_fLoaded)
		return E_CALL_LOADPE_FIRST;

	if (!ImageHasFlag(m_dwFileSummary, IMAGE_FLAG_SECURITY))
		return E_IMAGE_HAS_NO_SECURITY;

	*pVecSecurity = &m_vecSecurity;

	return S_OK;
}

HRESULT Clibpe::GetRelocationTable(PCLIBPE_RELOCATION_VEC* pVecRelocs)
{
	if (!m_fLoaded)
		return E_CALL_LOADPE_FIRST;

	if (!ImageHasFlag(m_dwFileSummary, IMAGE_FLAG_BASERELOC))
		return E_IMAGE_HAS_NO_BASERELOC;

	*pVecRelocs = &m_vecRelocationTable;

	return S_OK;
}

HRESULT Clibpe::GetDebugTable(PCLIBPE_DEBUG_VEC* pVecDebug)
{
	if (!m_fLoaded)
		return E_CALL_LOADPE_FIRST;

	if (!ImageHasFlag(m_dwFileSummary, IMAGE_FLAG_DEBUG))
		return E_IMAGE_HAS_NO_DEBUG;

	*pVecDebug = &m_vecDebugTable;

	return S_OK;
}

HRESULT Clibpe::GetTLSTable(PCLIBPE_TLS_TUP* pTupTLS)
{
	if (!m_fLoaded)
		return E_CALL_LOADPE_FIRST;

	if (!ImageHasFlag(m_dwFileSummary, IMAGE_FLAG_TLS))
		return E_IMAGE_HAS_NO_TLS;

	*pTupTLS = &m_tupTLS;

	return S_OK;
}

HRESULT Clibpe::GetLoadConfigTable(PCLIBPE_LOADCONFIGTABLE_VAR* pVarLCD)
{
	if (!m_fLoaded)
		return E_CALL_LOADPE_FIRST;

	if (!ImageHasFlag(m_dwFileSummary, IMAGE_FLAG_LOADCONFIG))
		return E_IMAGE_HAS_NO_LOADCONFIG;

	*pVarLCD = &m_varLoadConfigDir;

	return S_OK;
}

HRESULT Clibpe::GetBoundImportTable(PCLIBPE_BOUNDIMPORT_VEC* pVecBoundImport)
{
	if (!m_fLoaded)
		return E_CALL_LOADPE_FIRST;

	if (!ImageHasFlag(m_dwFileSummary, IMAGE_FLAG_BOUNDIMPORT))
		return E_IMAGE_HAS_NO_BOUNDIMPORT;

	*pVecBoundImport = &m_vecBoundImportTable;

	return S_OK;
}

HRESULT Clibpe::GetDelayImportTable(PCLIBPE_DELAYIMPORT_VEC* pVecDelayImport)
{
	if (!m_fLoaded)
		return E_CALL_LOADPE_FIRST;

	if (!ImageHasFlag(m_dwFileSummary, IMAGE_FLAG_DELAYIMPORT))
		return 	E_IMAGE_HAS_NO_DELAYIMPORT;

	*pVecDelayImport = &m_vecDelayImportTable;

	return S_OK;
}

HRESULT Clibpe::GetCOMDescriptorTable(PCLIBPE_COMDESCRIPTOR* pCOMDescriptor)
{
	if (!m_fLoaded)
		return E_CALL_LOADPE_FIRST;

	if (!ImageHasFlag(m_dwFileSummary, IMAGE_FLAG_COMDESCRIPTOR))
		return E_IMAGE_HAS_NO_COMDESCRIPTOR;

	*pCOMDescriptor = &m_stCOR20Header;

	return S_OK;
}

PIMAGE_SECTION_HEADER Clibpe::getSecHdrFromRVA(ULONGLONG ullRVA) const
{
	PIMAGE_SECTION_HEADER pSecHdr;
	WORD wNumberOfSections;

	if (ImageHasFlag(m_dwFileSummary, IMAGE_FLAG_PE32) && ImageHasFlag(m_dwFileSummary, IMAGE_FLAG_FILEHEADER))
	{
		pSecHdr = IMAGE_FIRST_SECTION(m_pNTHeader32);
		wNumberOfSections = m_pNTHeader32->FileHeader.NumberOfSections;
	}
	else if (ImageHasFlag(m_dwFileSummary, IMAGE_FLAG_PE64) && ImageHasFlag(m_dwFileSummary, IMAGE_FLAG_FILEHEADER))
	{
		pSecHdr = IMAGE_FIRST_SECTION(m_pNTHeader64);
		wNumberOfSections = m_pNTHeader64->FileHeader.NumberOfSections;
	}
	else
		return nullptr;

	for (unsigned i = 0; i < wNumberOfSections; i++, pSecHdr++)
	{
		if (!isPtrSafe(pSecHdr))
			return nullptr;
		//Is RVA within this section?
		if ((ullRVA >= pSecHdr->VirtualAddress) && (ullRVA < (pSecHdr->VirtualAddress + pSecHdr->Misc.VirtualSize)))
			return pSecHdr;
	}

	return nullptr;
}

PIMAGE_SECTION_HEADER Clibpe::getSecHdrFromName(LPCSTR lpszName) const
{
	PIMAGE_SECTION_HEADER pSecHdr;
	WORD wNumberOfSections;

	if (ImageHasFlag(m_dwFileSummary, IMAGE_FLAG_PE32) && ImageHasFlag(m_dwFileSummary, IMAGE_FLAG_FILEHEADER))
	{
		pSecHdr = IMAGE_FIRST_SECTION(m_pNTHeader32);
		wNumberOfSections = m_pNTHeader32->FileHeader.NumberOfSections;
	}
	else if (ImageHasFlag(m_dwFileSummary, IMAGE_FLAG_PE64) && ImageHasFlag(m_dwFileSummary, IMAGE_FLAG_FILEHEADER))
	{
		pSecHdr = IMAGE_FIRST_SECTION(m_pNTHeader64);
		wNumberOfSections = m_pNTHeader64->FileHeader.NumberOfSections;
	}
	else
		return nullptr;

	for (unsigned i = 0; i < wNumberOfSections; i++, pSecHdr++)
	{
		if (!isPtrSafe(pSecHdr))
			break;
		if (strncmp((char*)pSecHdr->Name, lpszName, IMAGE_SIZEOF_SHORT_NAME) == 0)
			return pSecHdr;
	}

	return nullptr;
}

LPVOID Clibpe::rVAToPtr(ULONGLONG ullRVA) const
{
	const PIMAGE_SECTION_HEADER pSecHdr = getSecHdrFromRVA(ullRVA);
	if (!pSecHdr)
		return nullptr;

	LPVOID ptr;
	if (m_fMapViewOfFileWhole)
		ptr = (LPVOID)((DWORD_PTR)m_lpBase + ullRVA - (DWORD_PTR)(pSecHdr->VirtualAddress - pSecHdr->PointerToRawData));
	else
		ptr = (LPVOID)((DWORD_PTR)m_lpSectionBase + (DWORD_PTR)m_dwDeltaFileOffsetToMap +
			(ullRVA - (DWORD_PTR)(pSecHdr->VirtualAddress - pSecHdr->PointerToRawData) - m_dwFileOffsetToMap));

	return isPtrSafe(ptr, true) ? ptr : nullptr;
}

DWORD Clibpe::getDirEntryRVA(UINT uiDirEntry) const
{
	if (ImageHasFlag(m_dwFileSummary, IMAGE_FLAG_PE32) && ImageHasFlag(m_dwFileSummary, IMAGE_FLAG_OPTHEADER))
		return m_pNTHeader32->OptionalHeader.DataDirectory[uiDirEntry].VirtualAddress;
	else if (ImageHasFlag(m_dwFileSummary, IMAGE_FLAG_PE64) && ImageHasFlag(m_dwFileSummary, IMAGE_FLAG_OPTHEADER))
		return m_pNTHeader64->OptionalHeader.DataDirectory[uiDirEntry].VirtualAddress;
	
	return 0;
}

DWORD Clibpe::getDirEntrySize(UINT uiDirEntry) const
{
	if (ImageHasFlag(m_dwFileSummary, IMAGE_FLAG_PE32) && ImageHasFlag(m_dwFileSummary, IMAGE_FLAG_OPTHEADER))
		return m_pNTHeader32->OptionalHeader.DataDirectory[uiDirEntry].Size;
	else if (ImageHasFlag(m_dwFileSummary, IMAGE_FLAG_PE64) && ImageHasFlag(m_dwFileSummary, IMAGE_FLAG_OPTHEADER))
		return m_pNTHeader64->OptionalHeader.DataDirectory[uiDirEntry].Size;

	return 0;
}

/****************************************************************
* This func checks given pointer for nullptr and, more			*
* important, whether it fits allowed bounds.					*
* In PE headers there are plenty of places where wrong (bogus)	*
* values for pointers might reside, causing many runtime «fun»	*
* if trying to dereference them.								*
* Second arg (fCanReferenceBoundary) shows if ptr can point to	*
* the very end of a file, it's valid for some PE structures.	*
* Template is used just for convenience, sometimes there is a	*
* need to check pure address DWORD_PTR instead of a pointer.	*
****************************************************************/
template<typename T> bool Clibpe::isPtrSafe(const T tPtr, bool fCanReferenceBoundary) const
{
	return !tPtr ? false : (fCanReferenceBoundary ?
		((DWORD_PTR)tPtr <= m_dwMaxPointerBound && (DWORD_PTR)tPtr >= (DWORD_PTR)m_lpBase) :
		((DWORD_PTR)tPtr < m_dwMaxPointerBound && (DWORD_PTR)tPtr >= (DWORD_PTR)m_lpBase));
}

HRESULT Clibpe::getDirByMappingSec(DWORD dwDirectory)
{
	DWORD dwAlignedAddressToMap;
	DWORD_PTR dwSizeToMap;
	PIMAGE_SECTION_HEADER pSecHdr;

	if (dwDirectory == IMAGE_DIRECTORY_ENTRY_SECURITY)
	{
		if (getDirEntryRVA(IMAGE_DIRECTORY_ENTRY_SECURITY))
		{
			//This is an actual file RAW offset.
			m_dwFileOffsetToMap = getDirEntryRVA(IMAGE_DIRECTORY_ENTRY_SECURITY);

			//Checking for exceeding file size bound.
			if (m_dwFileOffsetToMap < m_stFileSize.QuadPart)
			{
				if (m_dwFileOffsetToMap % m_stSysInfo.dwAllocationGranularity > 0)
				{
					dwAlignedAddressToMap = (m_dwFileOffsetToMap < m_stSysInfo.dwAllocationGranularity) ? 0 :
						(m_dwFileOffsetToMap - (m_dwFileOffsetToMap % m_stSysInfo.dwAllocationGranularity));
				}
				else
					dwAlignedAddressToMap = m_dwFileOffsetToMap;

				m_dwDeltaFileOffsetToMap = m_dwFileOffsetToMap - dwAlignedAddressToMap;

				dwSizeToMap = (DWORD_PTR)getDirEntrySize(IMAGE_DIRECTORY_ENTRY_SECURITY) + (DWORD_PTR)m_dwDeltaFileOffsetToMap;
				//Checking for out of bounds file's size to map.
				if (((LONGLONG)m_dwFileOffsetToMap + (LONGLONG)getDirEntrySize(IMAGE_DIRECTORY_ENTRY_SECURITY)) <= (m_stFileSize.QuadPart))
				{
					if (!(m_lpSectionBase = MapViewOfFile(m_hMapObject, FILE_MAP_READ, 0, dwAlignedAddressToMap, dwSizeToMap)))
						return E_FILE_MAP_VIEW_OF_FILE_FAILED;

					m_dwMaxPointerBound = (DWORD_PTR)m_lpSectionBase + dwSizeToMap;
					getSecurityTable();
					UnmapViewOfFile(m_lpSectionBase);
				}
			}
		}
	}
	else if ((pSecHdr = getSecHdrFromRVA(getDirEntryRVA(dwDirectory))))
	{
		m_dwFileOffsetToMap = pSecHdr->PointerToRawData;

		if (m_dwFileOffsetToMap % m_stSysInfo.dwAllocationGranularity > 0)
		{
			dwAlignedAddressToMap = (m_dwFileOffsetToMap < m_stSysInfo.dwAllocationGranularity) ? 0 :
				(m_dwFileOffsetToMap - (m_dwFileOffsetToMap % m_stSysInfo.dwAllocationGranularity));
		}
		else
			dwAlignedAddressToMap = m_dwFileOffsetToMap;

		m_dwDeltaFileOffsetToMap = m_dwFileOffsetToMap - dwAlignedAddressToMap;
		dwSizeToMap = DWORD_PTR(pSecHdr->Misc.VirtualSize + m_dwDeltaFileOffsetToMap);
		if (((LONGLONG)dwAlignedAddressToMap + dwSizeToMap) > m_stFileSize.QuadPart)
			return E_FILE_SECTION_DATA_CORRUPTED;
		if (!(m_lpSectionBase = MapViewOfFile(m_hMapObject, FILE_MAP_READ, 0, dwAlignedAddressToMap, dwSizeToMap)))
			return E_FILE_MAP_VIEW_OF_FILE_FAILED;

		m_dwMaxPointerBound = (DWORD_PTR)m_lpSectionBase + dwSizeToMap;
		switch (dwDirectory)
		{
		case IMAGE_DIRECTORY_ENTRY_EXPORT:
			getExportTable();
			break;
		case IMAGE_DIRECTORY_ENTRY_IMPORT:
			getImportTable();
			break;
		case IMAGE_DIRECTORY_ENTRY_RESOURCE:
			getResourceTable();
			break;
		case IMAGE_DIRECTORY_ENTRY_EXCEPTION:
			getExceptionTable();
			break;
		case IMAGE_DIRECTORY_ENTRY_BASERELOC:
			getRelocationTable();
			break;
		case IMAGE_DIRECTORY_ENTRY_DEBUG:
			getDebugTable();
			break;
		case IMAGE_DIRECTORY_ENTRY_ARCHITECTURE:
			getArchitectureTable();
			break;
		case IMAGE_DIRECTORY_ENTRY_GLOBALPTR:
			getGlobalPtrTable();
			break;
		case IMAGE_DIRECTORY_ENTRY_TLS:
			getTLSTable();
			break;
		case IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG:
			getLoadConfigTable();
			break;
		case IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT:
			getBoundImportTable();
			break;
		case IMAGE_DIRECTORY_ENTRY_IAT:
			getIATTable();
			break;
		case IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT:
			getDelayImportTable();
			break;
		case IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR:
			getCOMDescriptorTable();
			break;
		}

		UnmapViewOfFile(m_lpSectionBase);
	}

	return S_OK;
}

/****************************************************
* Clearing all vectors and nullify all private		*
* member vars — pointers and flags.					*
* Called if LoadPe is invoked second time by the	*
* same Ilibpe pointer.								*
****************************************************/
void Clibpe::resetAll()
{
	m_lpBase = nullptr;
	m_hMapObject = nullptr;
	m_pNTHeader32 = nullptr;
	m_pNTHeader64 = nullptr;
	m_dwFileSummary = 0;
	m_fLoaded = false;

	m_vecRichHeader.clear();
	m_vecDataDirectories.clear();
	m_vecSectionHeaders.clear();
	std::get<2>(m_tupExport).clear();
	m_vecImportTable.clear();
	std::get<1>(m_tupResourceTable).clear();
	m_vecExceptionTable.clear();
	m_vecSecurity.clear();
	m_vecRelocationTable.clear();
	m_vecDebugTable.clear();
	std::get<1>(m_tupTLS).clear(); std::get<2>(m_tupTLS).clear();
	m_vecBoundImportTable.clear();
	m_vecDelayImportTable.clear();
}

HRESULT Clibpe::getMSDOSHeader()
{
	m_pDosHeader = (PIMAGE_DOS_HEADER)m_lpBase;

	//If file has at least MSDOS header signature then we can assume, 
	//that this is a minimum correct PE file, and process further.
	if (m_pDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
		return E_IMAGE_HAS_NO_DOSHEADER;

	m_stDOSHeader = *m_pDosHeader;
	m_dwFileSummary |= IMAGE_FLAG_DOSHEADER;
	m_fLoaded = true;

	return S_OK;
}

/********************************************
* Undocumented, so called «Rich», header.	*
* Dwells not in all PE files.				*
********************************************/
HRESULT Clibpe::getRichHeader()
{
	//«Rich» stub starts at 0x80 offset,
	//before m_pDosHeader->e_lfanew (PE header start offset)
	//If e_lfanew <= 0x80 — there is no «Rich» header.
	if (m_pDosHeader->e_lfanew <= 0x80 || !isPtrSafe(m_pDosHeader->e_lfanew))
		return E_IMAGE_HAS_NO_RICHHEADER;

	const PDWORD pRichStartVA = (PDWORD)((DWORD_PTR)m_pDosHeader + 0x80);
	PDWORD pRichIter = pRichStartVA;

	for (int i = 0; i < ((m_pDosHeader->e_lfanew - 0x80) / 4); i++, pRichIter++)
	{
		//Check "Rich" (ANSI) sign, it's always at the end of the «Rich» header.
		//Then take DWORD right after the "Rich" sign — it's a xor mask.
		//Apply this mask to the first DWORD of «Rich» header,
		//it must be "DanS" (ANSI) after xoring.
		if ((*pRichIter == 0x68636952/*"Rich"*/) && ((*pRichStartVA ^ *(pRichIter + 1)) == 0x536E6144/*"Dans"*/)
			&& ((DWORD_PTR)pRichIter >= (DWORD_PTR)m_pDosHeader + 0x90 /*To avoid too small (bogus) «Rich» header*/))
		{
			//Amount of all «Rich» DOUBLE_DWORD structs.
			//First 16 bytes in «Rich» header are irrelevant. It's "DansS" itself and 12 more zeroed bytes.
			//That's why we subtracting 0x90 to find out amount of all «Rich» structures:
			//0x80 («Rich» start) + 16 (0xF) = 0x90.
			const DWORD dwRichSize = (DWORD)(((DWORD_PTR)pRichIter - (DWORD_PTR)m_pDosHeader) - 0x90) / 8;
			const DWORD dwRichXORMask = *(pRichIter + 1); //xor mask of «Rich» header.
			pRichIter = (PDWORD)((DWORD_PTR)m_pDosHeader + 0x90);//VA of «Rich» DOUBLE_DWORD structs start.

			for (unsigned j = 0; j < dwRichSize; j++)
			{
				//Pushing double DWORD of «Rich» structure.
				//Disassembling first DWORD by two WORDs.
				m_vecRichHeader.emplace_back(HIWORD(dwRichXORMask ^ *pRichIter),
					LOWORD(dwRichXORMask ^ *pRichIter), dwRichXORMask ^ *(pRichIter + 1));
				pRichIter += 2; //Jump to the next DOUBLE_DWORD.
			}

			m_dwFileSummary |= IMAGE_FLAG_RICHHEADER;

			return S_OK;
		}
	}

	return E_IMAGE_HAS_NO_RICHHEADER;
}

HRESULT Clibpe::getNTFileOptHeader()
{
	PIMAGE_NT_HEADERS32 pNTHeader = (PIMAGE_NT_HEADERS32)((DWORD_PTR)m_pDosHeader + (DWORD_PTR)m_pDosHeader->e_lfanew);
	if (!isPtrSafe((DWORD_PTR)pNTHeader + sizeof(IMAGE_NT_HEADERS32)))
		return E_IMAGE_HAS_NO_NTHEADER;

	if (pNTHeader->Signature != IMAGE_NT_SIGNATURE)
		return E_IMAGE_HAS_NO_NTHEADER;

	switch (pNTHeader->OptionalHeader.Magic)
	{
	case IMAGE_NT_OPTIONAL_HDR32_MAGIC:
		m_dwFileSummary |= IMAGE_FLAG_PE32;
		m_pNTHeader32 = pNTHeader;
		m_varNTHeader = *m_pNTHeader32;
		m_stFileHeader = m_pNTHeader32->FileHeader;
		m_varOptHeader = m_pNTHeader32->OptionalHeader;
		m_ulImageBase = m_pNTHeader32->OptionalHeader.ImageBase;
		break;
	case IMAGE_NT_OPTIONAL_HDR64_MAGIC:
		m_dwFileSummary |= IMAGE_FLAG_PE64;
		m_pNTHeader64 = (PIMAGE_NT_HEADERS64)pNTHeader;
		m_varNTHeader = *m_pNTHeader64;
		m_stFileHeader = m_pNTHeader64->FileHeader;
		m_varOptHeader = m_pNTHeader64->OptionalHeader;
		m_ulImageBase = m_pNTHeader64->OptionalHeader.ImageBase;
		break;
	case IMAGE_ROM_OPTIONAL_HDR_MAGIC:
		return E_NOTIMPL; //not implemented yet
	default:
		return E_IMAGE_TYPE_UNSUPPORTED;
	}

	m_dwFileSummary |= IMAGE_FLAG_NTHEADER | IMAGE_FLAG_FILEHEADER | IMAGE_FLAG_OPTHEADER;

	return S_OK;
}

HRESULT Clibpe::getDataDirectories()
{
	PIMAGE_DATA_DIRECTORY pDataDir;
	PIMAGE_SECTION_HEADER pSecHdr;
	DWORD dwRVAAndSizes;

	if (ImageHasFlag(m_dwFileSummary, IMAGE_FLAG_PE32) && ImageHasFlag(m_dwFileSummary, IMAGE_FLAG_OPTHEADER))
	{
		pDataDir = (PIMAGE_DATA_DIRECTORY)m_pNTHeader32->OptionalHeader.DataDirectory;
		dwRVAAndSizes = m_pNTHeader32->OptionalHeader.NumberOfRvaAndSizes;
	}
	else if (ImageHasFlag(m_dwFileSummary, IMAGE_FLAG_PE64) && ImageHasFlag(m_dwFileSummary, IMAGE_FLAG_OPTHEADER))
	{
		pDataDir = (PIMAGE_DATA_DIRECTORY)m_pNTHeader64->OptionalHeader.DataDirectory;
		dwRVAAndSizes = m_pNTHeader64->OptionalHeader.NumberOfRvaAndSizes;
	}
	else
		return E_IMAGE_HAS_NO_DATADIRECTORIES;

	//Filling DataDirectories vector.
	for (unsigned i = 0; i < (dwRVAAndSizes > 15 ? 15 : dwRVAAndSizes); i++, pDataDir++)
	{
		std::string strSecName { };

		pSecHdr = getSecHdrFromRVA(pDataDir->VirtualAddress);
		//RVA of IMAGE_DIRECTORY_ENTRY_SECURITY is file RAW offset.
		if (pSecHdr && (i != IMAGE_DIRECTORY_ENTRY_SECURITY))
			strSecName.assign((char * const)pSecHdr->Name, 8);

		m_vecDataDirectories.emplace_back(*pDataDir, std::move(strSecName));
	}

	if (m_vecDataDirectories.empty())
		return E_IMAGE_HAS_NO_DATADIRECTORIES;

	m_dwFileSummary |= IMAGE_FLAG_DATADIRECTORIES;

	return S_OK;
}

HRESULT Clibpe::getSectionsHeaders()
{
	PIMAGE_SECTION_HEADER pSecHdr;
	WORD wNumSections;
	DWORD dwSymbolTable, dwNumberOfSymbols;

	if (ImageHasFlag(m_dwFileSummary, IMAGE_FLAG_PE32) && ImageHasFlag(m_dwFileSummary, IMAGE_FLAG_FILEHEADER))
	{
		pSecHdr = IMAGE_FIRST_SECTION(m_pNTHeader32);
		wNumSections = m_pNTHeader32->FileHeader.NumberOfSections;
		dwSymbolTable = (DWORD_PTR)m_pNTHeader32->FileHeader.PointerToSymbolTable;
		dwNumberOfSymbols = (DWORD_PTR)m_pNTHeader32->FileHeader.NumberOfSymbols;
	}
	else if (ImageHasFlag(m_dwFileSummary, IMAGE_FLAG_PE64) && ImageHasFlag(m_dwFileSummary, IMAGE_FLAG_FILEHEADER))
	{
		pSecHdr = IMAGE_FIRST_SECTION(m_pNTHeader64);
		wNumSections = m_pNTHeader64->FileHeader.NumberOfSections;
		dwSymbolTable = (DWORD_PTR)m_pNTHeader64->FileHeader.PointerToSymbolTable;
		dwNumberOfSymbols = (DWORD_PTR)m_pNTHeader64->FileHeader.NumberOfSymbols;
	}
	else
		return E_IMAGE_HAS_NO_SECTIONS;

	m_vecSectionHeaders.reserve(wNumSections);

	for (unsigned i = 0; i < wNumSections; i++, pSecHdr++)
	{
		if (!isPtrSafe(pSecHdr))
			break;

		std::string strSecRealName { };

		if (pSecHdr->Name[0] == '/')
		{	//Deprecated, but still used "feature" of section name.
			//https://docs.microsoft.com/en-us/windows/desktop/api/winnt/ns-winnt-_image_section_header#members
			//«An 8-byte, null-padded UTF-8 string. There is no terminating null character 
			//if the string is exactly eight characters long.
			//For longer names, this member contains a forward slash (/) followed by an ASCII representation 
			//of a decimal number that is an offset into the string table.»
			//String Table dwells right after the end of Symbol Table.
			//Each symbol in Symbol Table occupies exactly 18 bytes.
			//So String Table's beginning can be calculated like this:
			//FileHeader.PointerToSymbolTable + FileHeader.NumberOfSymbols * 18;
			const long lOffset = strtol((const char*)&pSecHdr->Name[1], nullptr, 10);
			if (lOffset != LONG_MAX && lOffset != LONG_MIN && lOffset != 0)
			{
				const char* lpszSecRealName = (const char*)((DWORD_PTR)m_lpBase + dwSymbolTable +
					dwNumberOfSymbols * 18 + (DWORD_PTR)lOffset);
				if (isPtrSafe(lpszSecRealName))
					strSecRealName = lpszSecRealName;
			}
		}

		m_vecSectionHeaders.emplace_back(*pSecHdr, std::move(strSecRealName));
	}

	if (m_vecSectionHeaders.empty())
		return E_IMAGE_HAS_NO_SECTIONS;

	m_dwFileSummary |= IMAGE_FLAG_SECTIONS;

	return S_OK;
}

HRESULT Clibpe::getExportTable()
{
	const DWORD dwExportStartRVA = getDirEntryRVA(IMAGE_DIRECTORY_ENTRY_EXPORT);
	const DWORD dwExportEndRVA = dwExportStartRVA + getDirEntrySize(IMAGE_DIRECTORY_ENTRY_EXPORT);

	const PIMAGE_EXPORT_DIRECTORY pExportDir = (PIMAGE_EXPORT_DIRECTORY)rVAToPtr(dwExportStartRVA);
	if (!pExportDir)
		return E_IMAGE_HAS_NO_EXPORT;

	const PDWORD pFuncs = (PDWORD)rVAToPtr(pExportDir->AddressOfFunctions);
	if (!pFuncs)
		return E_IMAGE_HAS_NO_EXPORT;

	std::vector<std::tuple<DWORD/*Exported func RVA/Forwarder RVA*/, DWORD/*func Ordinal*/, std::string /*Func Name*/,
		std::string/*Forwarder func name*/>> vecFuncs { };
	std::string strExportName { };
	const PWORD pOrdinals = (PWORD)rVAToPtr(pExportDir->AddressOfNameOrdinals);
	LPCSTR* szNames = (LPCSTR*)rVAToPtr(pExportDir->AddressOfNames);

	try {

		vecFuncs.reserve(pExportDir->NumberOfFunctions);
		for (DWORD iterFuncs = 0; iterFuncs < pExportDir->NumberOfFunctions; iterFuncs++)
		{
			if (pFuncs[iterFuncs]) //if RVA==0 —> going next entry.
			{
				std::string strFuncName { }, strFuncNameForwarder { };
				if (szNames && pOrdinals)
					for (DWORD iterFuncNames = 0; iterFuncNames < pExportDir->NumberOfNames; iterFuncNames++)
						//Cycling through ordinals table to get func name.
						if (pOrdinals[iterFuncNames] == iterFuncs)
						{
							const LPCSTR szFuncName = (LPCSTR)rVAToPtr((DWORD_PTR)szNames[iterFuncNames]);
							//Checking func name for length correctness.
							if (szFuncName && (StringCchLengthA(szFuncName, MAX_PATH, nullptr) != STRSAFE_E_INVALID_PARAMETER))
								strFuncName = szFuncName;
							break;
						}
				if ((pFuncs[iterFuncs] >= dwExportStartRVA) && (pFuncs[iterFuncs] <= dwExportEndRVA))
				{
					const LPCSTR szFuncNameForwarder = (LPCSTR)rVAToPtr(pFuncs[iterFuncs]);
					//Checking forwarder name for length correctness.
					if (szFuncNameForwarder && (StringCchLengthA(szFuncNameForwarder, MAX_PATH, nullptr) != STRSAFE_E_INVALID_PARAMETER))
						strFuncNameForwarder = szFuncNameForwarder;
				}
				vecFuncs.emplace_back(pFuncs[iterFuncs], iterFuncs, std::move(strFuncName), std::move(strFuncNameForwarder));
			}
		}
		const LPCSTR szExportName = (LPCSTR)rVAToPtr(pExportDir->Name);
		//Checking Export name for length correctness.
		if (szExportName && (StringCchLengthA(szExportName, MAX_PATH, nullptr) != STRSAFE_E_INVALID_PARAMETER))
			strExportName = szExportName;

		m_tupExport = { *pExportDir, std::move(strExportName) /*Actual IMG name*/, std::move(vecFuncs) };
	}
	catch (const std::bad_alloc&)
	{
		m_pEmergencyMemory.reset();
		MessageBox(nullptr, L"E_OUTOFMEMORY error while trying to get Export table.\nFile seems to be corrupted.",
			L"Error", MB_ICONERROR);

		vecFuncs.clear();
		m_pEmergencyMemory = std::make_unique<char []>(0x8FFF);
	}
	catch (...)
	{
		MessageBox(nullptr, L"Unknown exception raised while trying to get Export table.\r\nFile seems to be corrupted.",
			L"Error", MB_ICONERROR);
	}

	m_dwFileSummary |= IMAGE_FLAG_EXPORT;

	return S_OK;
}

HRESULT Clibpe::getImportTable()
{
	PIMAGE_IMPORT_DESCRIPTOR pImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)rVAToPtr(getDirEntryRVA(IMAGE_DIRECTORY_ENTRY_IMPORT));

	if (!pImportDescriptor)
		return E_IMAGE_HAS_NO_IMPORT;

	const DWORD dwTLSDirRVA = getDirEntryRVA(IMAGE_DIRECTORY_ENTRY_TLS);

	try {
		if (ImageHasFlag(m_dwFileSummary, IMAGE_FLAG_PE32))
		{
			const PIMAGE_TLS_DIRECTORY32 pTLSDir32 = (PIMAGE_TLS_DIRECTORY32)rVAToPtr(dwTLSDirRVA);

			while (pImportDescriptor->Name)
			{
				std::vector<std::tuple<ULONGLONG/*Ordinal/Hint*/, std::string/*Func name*/, ULONGLONG/*Thunk table RVA*/>> vecFunc { };
				std::string strDllName { };

				//Checking for TLS Index patching trick, to strip fake imports.
				//The trick is: OS loader, while loading PE file, patches address in memory 
				//that is pointed to by PIMAGE_TLS_DIRECTORY->AddressOfIndex.
				//If at this address file had, say, Import descriptor with fake imports
				//it will be zeroed, and PE file will be executed just fine.
				//But trying to read this fake Import descriptor from file on disk
				//may lead to many «interesting» things. Import table can be enormous,
				//with absolutely unreadable import names.
				if (pTLSDir32 && pTLSDir32->AddressOfIndex && (((DWORD_PTR)pImportDescriptor + offsetof(IMAGE_IMPORT_DESCRIPTOR, FirstThunk)) ==
					(DWORD_PTR)rVAToPtr(pTLSDir32->AddressOfIndex - m_ulImageBase) ||
					((DWORD_PTR)pImportDescriptor + offsetof(IMAGE_IMPORT_DESCRIPTOR, Name)) ==
					(DWORD_PTR)rVAToPtr(pTLSDir32->AddressOfIndex - m_ulImageBase)))
				{
					const LPCSTR szName = (LPCSTR)rVAToPtr(pImportDescriptor->Name);
					if (szName && (StringCchLengthA(szName, MAX_PATH, nullptr) != STRSAFE_E_INVALID_PARAMETER))
						strDllName = szName;

					strDllName += " (--> stripped by TLS::AddressOfIndex trick)";

					m_vecImportTable.emplace_back(*pImportDescriptor, std::move(strDllName), std::move(vecFunc));
					break;
				}

				PIMAGE_THUNK_DATA32 pThunk32 = (PIMAGE_THUNK_DATA32)(DWORD_PTR)pImportDescriptor->OriginalFirstThunk;
				if (!pThunk32)
					pThunk32 = (PIMAGE_THUNK_DATA32)(DWORD_PTR)pImportDescriptor->FirstThunk;

				if (pThunk32)
				{
					pThunk32 = (PIMAGE_THUNK_DATA32)rVAToPtr((DWORD_PTR)pThunk32);
					if (!pThunk32)
						break;

					while (pThunk32->u1.AddressOfData)
					{
						if (pThunk32->u1.Ordinal & IMAGE_ORDINAL_FLAG32)
							//If funcs are imported only by ordinals then filling only ordinal leaving Name as "".
							vecFunc.emplace_back(IMAGE_ORDINAL32(pThunk32->u1.Ordinal), "", pThunk32->u1.AddressOfData);
						else
						{
							std::string strFuncName { };
							//Filling Hint, Name and Thunk RVA.
							const PIMAGE_IMPORT_BY_NAME pName = (PIMAGE_IMPORT_BY_NAME)rVAToPtr(pThunk32->u1.AddressOfData);
							if (pName && (StringCchLengthA(pName->Name, MAX_PATH, nullptr) != STRSAFE_E_INVALID_PARAMETER))
								strFuncName = pName->Name;

							vecFunc.emplace_back(pName ? pName->Hint : 0, std::move(strFuncName), pThunk32->u1.AddressOfData);
						}
						if (!isPtrSafe(++pThunk32))
							break;
					}
					const LPCSTR szName = (LPCSTR)rVAToPtr(pImportDescriptor->Name);
					if (szName && (StringCchLengthA(szName, MAX_PATH, nullptr) != STRSAFE_E_INVALID_PARAMETER))
						strDllName = szName;

					m_vecImportTable.emplace_back(*pImportDescriptor, std::move(strDllName), std::move(vecFunc));

					if (!isPtrSafe(++pImportDescriptor))
						break;
				}
				else //No IMPORT pointers for that DLL?...
					if (!isPtrSafe(++pImportDescriptor))  //Going next dll.
						break;
			}
		}
		else if (ImageHasFlag(m_dwFileSummary, IMAGE_FLAG_PE64))
		{
			const PIMAGE_TLS_DIRECTORY64 pTLSDir64 = (PIMAGE_TLS_DIRECTORY64)rVAToPtr(dwTLSDirRVA);

			while (pImportDescriptor->Name)
			{
				std::vector<std::tuple<ULONGLONG/*Ordinal/Hint*/, std::string/*Func name*/, ULONGLONG/*Thunk table RVA*/>> vecFunc { };
				std::string strDllName { };

				if (pTLSDir64 && pTLSDir64->AddressOfIndex && (((DWORD_PTR)pImportDescriptor + offsetof(IMAGE_IMPORT_DESCRIPTOR, FirstThunk)) ==
					(DWORD_PTR)rVAToPtr(pTLSDir64->AddressOfIndex - m_ulImageBase) ||
					((DWORD_PTR)pImportDescriptor + offsetof(IMAGE_IMPORT_DESCRIPTOR, Name)) ==
					(DWORD_PTR)rVAToPtr(pTLSDir64->AddressOfIndex - m_ulImageBase)))
				{
					const LPCSTR szName = (LPCSTR)rVAToPtr(pImportDescriptor->Name);
					if (szName && (StringCchLengthA(szName, MAX_PATH, nullptr) != STRSAFE_E_INVALID_PARAMETER))
						strDllName = szName;

					strDllName += " (--> stripped by TLS::AddressOfIndex trick)";

					m_vecImportTable.emplace_back(*pImportDescriptor, std::move(strDllName), std::move(vecFunc));
					break;
				}

				PIMAGE_THUNK_DATA64 pThunk64 = (PIMAGE_THUNK_DATA64)(DWORD_PTR)pImportDescriptor->OriginalFirstThunk;
				if (!pThunk64)
					pThunk64 = (PIMAGE_THUNK_DATA64)(DWORD_PTR)pImportDescriptor->FirstThunk;

				if (pThunk64)
				{
					pThunk64 = (PIMAGE_THUNK_DATA64)rVAToPtr((DWORD_PTR)pThunk64);
					if (!pThunk64)
						return E_IMAGE_HAS_NO_IMPORT;

					while (pThunk64->u1.AddressOfData)
					{
						if (pThunk64->u1.Ordinal & IMAGE_ORDINAL_FLAG64)
							//If funcs are imported only by ordinals then filling only ordinal leaving Name as "".
							vecFunc.emplace_back(IMAGE_ORDINAL64(pThunk64->u1.Ordinal), "", pThunk64->u1.AddressOfData);
						else
						{
							std::string strFuncName { };

							//Filling Hint, Name and Thunk RVA.
							const PIMAGE_IMPORT_BY_NAME pName = (PIMAGE_IMPORT_BY_NAME)rVAToPtr(pThunk64->u1.AddressOfData);
							if (pName && (StringCchLengthA(pName->Name, MAX_PATH, nullptr) != STRSAFE_E_INVALID_PARAMETER))
								strFuncName = pName->Name;

							vecFunc.emplace_back(pName ? pName->Hint : 0, std::move(strFuncName), pThunk64->u1.AddressOfData);
						}
						pThunk64++;
					}

					const LPCSTR szName = (LPCSTR)rVAToPtr(pImportDescriptor->Name);
					if (szName && (StringCchLengthA(szName, MAX_PATH, nullptr) != STRSAFE_E_INVALID_PARAMETER))
						strDllName = szName;

					m_vecImportTable.emplace_back(*pImportDescriptor, std::move(strDllName), std::move(vecFunc));

					if (!isPtrSafe(++pImportDescriptor))
						break;
				}
				else
					if (!isPtrSafe(++pImportDescriptor))
						break;
			}
		}
	}
	catch (const std::bad_alloc&)
	{
		m_pEmergencyMemory.reset();
		MessageBox(nullptr, L"E_OUTOFMEMORY error while trying to get Import table.\r\n"
			L"Too many import entries!\nFile seems to be corrupted.", L"Error", MB_ICONERROR);

		m_vecImportTable.clear();
		m_pEmergencyMemory = std::make_unique<char []>(0x8FFF);
	}
	catch (...)
	{
		MessageBox(nullptr, L"Unknown exception raised while trying to get Import table.\r\nFile seems to be corrupted.",
			L"Error", MB_ICONERROR);
	}

	m_dwFileSummary |= IMAGE_FLAG_IMPORT;

	return S_OK;
}

HRESULT Clibpe::getResourceTable()
{
	PIMAGE_RESOURCE_DIRECTORY pRootResDir = (PIMAGE_RESOURCE_DIRECTORY)rVAToPtr(getDirEntryRVA(IMAGE_DIRECTORY_ENTRY_RESOURCE));
	if (!pRootResDir)
		return E_IMAGE_HAS_NO_RESOURCE;

	PIMAGE_RESOURCE_DIRECTORY_ENTRY pRootResDirEntry = (PIMAGE_RESOURCE_DIRECTORY_ENTRY)(pRootResDir + 1);
	if (!isPtrSafe(pRootResDirEntry))
		return E_IMAGE_HAS_NO_RESOURCE;

	PIMAGE_RESOURCE_DIR_STRING_U pResDirStr;

	try {
		LIBPE_RESOURCE_ROOT_VEC vecResLvLRoot { };
		vecResLvLRoot.reserve(pRootResDir->NumberOfNamedEntries + pRootResDir->NumberOfIdEntries);

		for (int iLvL1 = 0; iLvL1 < pRootResDir->NumberOfNamedEntries + pRootResDir->NumberOfIdEntries; iLvL1++)
		{
			PIMAGE_RESOURCE_DATA_ENTRY pRootResDataEntry { };
			std::wstring strRootResName { };
			std::vector<std::byte> vecRootResRawData { };
			LIBPE_RESOURCE_LVL2_TUP tupResLvL2 { };

			//Name of Resource Type (ICON, BITMAP, MENU, etc...).
			if (pRootResDirEntry->NameIsString)
			{
				pResDirStr = PIMAGE_RESOURCE_DIR_STRING_U((DWORD_PTR)pRootResDir + (DWORD_PTR)pRootResDirEntry->NameOffset);
				if (isPtrSafe(pResDirStr))
					//Copy not more then MAX_PATH chars into strRootResName, avoiding overflow.
					strRootResName.assign(pResDirStr->NameString, pResDirStr->Length < MAX_PATH ? pResDirStr->Length : MAX_PATH);
			}
			if (pRootResDirEntry->DataIsDirectory)
			{
				const PIMAGE_RESOURCE_DIRECTORY pSecondResDir = (PIMAGE_RESOURCE_DIRECTORY)((DWORD_PTR)pRootResDir + (DWORD_PTR)pRootResDirEntry->OffsetToDirectory);
				LIBPE_RESOURCE_LVL2_VEC vecResLvL2 { };

				if (!isPtrSafe(pSecondResDir))
					break;
				if (pSecondResDir == pRootResDir /*Resource loop hack*/)
					tupResLvL2 = { *pSecondResDir, vecResLvL2 };
				else
				{
					PIMAGE_RESOURCE_DIRECTORY_ENTRY pSecondResDirEntry = (PIMAGE_RESOURCE_DIRECTORY_ENTRY)(pSecondResDir + 1);
					vecResLvL2.reserve(pSecondResDir->NumberOfNamedEntries + pSecondResDir->NumberOfIdEntries);
					for (int iLvL2 = 0; iLvL2 < pSecondResDir->NumberOfNamedEntries + pSecondResDir->NumberOfIdEntries; iLvL2++)
					{
						PIMAGE_RESOURCE_DATA_ENTRY pSecondResDataEntry { };
						std::wstring strSecondResName { };
						std::vector<std::byte> vecSecondResRawData { };
						LIBPE_RESOURCE_LVL3_TUP tupResLvL3 { };

						//Name of resource itself if not presented by ID ("AFX_MY_SUPER_DIALOG"...).
						if (pSecondResDirEntry->NameIsString)
						{
							pResDirStr = PIMAGE_RESOURCE_DIR_STRING_U((DWORD_PTR)pRootResDir + (DWORD_PTR)pSecondResDirEntry->NameOffset);
							if (isPtrSafe(pResDirStr))
								//Copy not more then MAX_PATH chars into strSecondResName, avoiding overflow.
								strSecondResName.assign(pResDirStr->NameString, pResDirStr->Length < MAX_PATH ? pResDirStr->Length : MAX_PATH);
						}

						if (pSecondResDirEntry->DataIsDirectory)
						{
							const PIMAGE_RESOURCE_DIRECTORY pThirdResDir = (PIMAGE_RESOURCE_DIRECTORY)((DWORD_PTR)pRootResDir + (DWORD_PTR)pSecondResDirEntry->OffsetToDirectory);
							LIBPE_RESOURCE_LVL3_VEC vecResLvL3 { };

							if (!isPtrSafe(pThirdResDir))
								break;
							if (pThirdResDir == pSecondResDir || pThirdResDir == pRootResDir)
								tupResLvL3 = { *pThirdResDir, vecResLvL3 };
							else
							{
								PIMAGE_RESOURCE_DIRECTORY_ENTRY pThirdResDirEntry = (PIMAGE_RESOURCE_DIRECTORY_ENTRY)(pThirdResDir + 1);
								vecResLvL3.reserve(pThirdResDir->NumberOfNamedEntries + pThirdResDir->NumberOfIdEntries);
								for (int iLvL3 = 0; iLvL3 < pThirdResDir->NumberOfNamedEntries + pThirdResDir->NumberOfIdEntries; iLvL3++)
								{
									std::wstring strThirdResName { };
									std::vector<std::byte> vecThirdResRawData { };

									if (pThirdResDirEntry->NameIsString)
									{
										pResDirStr = PIMAGE_RESOURCE_DIR_STRING_U((DWORD_PTR)pRootResDir + (DWORD_PTR)pThirdResDirEntry->NameOffset);
										if (isPtrSafe(pResDirStr))
											//Copy not more then MAX_PATH chars into strSecondResName, avoiding overflow.
											strThirdResName.assign(pResDirStr->NameString, pResDirStr->Length < MAX_PATH ? pResDirStr->Length : MAX_PATH);
									}

									const PIMAGE_RESOURCE_DATA_ENTRY pThirdResDataEntry = (PIMAGE_RESOURCE_DATA_ENTRY)((DWORD_PTR)pRootResDir + (DWORD_PTR)
										pThirdResDirEntry->OffsetToData);
									if (isPtrSafe(pThirdResDataEntry))
									{	//Resource LvL 3 RAW Data.
										//IMAGE_RESOURCE_DATA_ENTRY::OffsetToData is actually a general RVA,
										//not an offset from root IMAGE_RESOURCE_DIRECTORY,
										//like IMAGE_RESOURCE_DIRECTORY_ENTRY::OffsetToData.
										//MS doesn't tend to make things simpler.

										std::byte* pThirdResRawDataBegin = (std::byte*)rVAToPtr(pThirdResDataEntry->OffsetToData);
										//Checking RAW Resource data pointer out of bounds.
										if (pThirdResRawDataBegin && isPtrSafe((DWORD_PTR)pThirdResRawDataBegin + (DWORD_PTR)pThirdResDataEntry->Size, true))
										{
											vecThirdResRawData.reserve(pThirdResDataEntry->Size);
											for (unsigned iterResRawData = 0; iterResRawData < pThirdResDataEntry->Size; iterResRawData++)
												vecThirdResRawData.push_back(*(pThirdResRawDataBegin + iterResRawData));
										}
									}

									vecResLvL3.emplace_back(*pThirdResDirEntry, std::move(strThirdResName),
										isPtrSafe(pThirdResDataEntry) ? *pThirdResDataEntry : IMAGE_RESOURCE_DATA_ENTRY { },
										std::move(vecThirdResRawData));

									if (!isPtrSafe(++pThirdResDirEntry))
										break;
								}
								tupResLvL3 = { *pThirdResDir, std::move(vecResLvL3) };
							}
						}
						else
						{	//////Resource LvL2 RAW Data.
							pSecondResDataEntry = (PIMAGE_RESOURCE_DATA_ENTRY)((DWORD_PTR)pRootResDir + (DWORD_PTR)pSecondResDirEntry->OffsetToData);
							if (isPtrSafe(pSecondResDataEntry))
							{
								std::byte* pSecondResRawDataBegin = (std::byte*)rVAToPtr(pSecondResDataEntry->OffsetToData);
								//Checking RAW Resource data pointer out of bounds.
								if (pSecondResRawDataBegin && isPtrSafe((DWORD_PTR)pSecondResRawDataBegin + (DWORD_PTR)pSecondResDataEntry->Size, true))
								{
									vecSecondResRawData.reserve(pSecondResDataEntry->Size);
									for (unsigned iterResRawData = 0; iterResRawData < pSecondResDataEntry->Size; iterResRawData++)
										vecSecondResRawData.push_back(*(pSecondResRawDataBegin + iterResRawData));
								}
							}
						}
						vecResLvL2.emplace_back(*pSecondResDirEntry, std::move(strSecondResName),
							isPtrSafe(pSecondResDataEntry) ? *pSecondResDataEntry : IMAGE_RESOURCE_DATA_ENTRY { },
							std::move(vecSecondResRawData), tupResLvL3);

						if (!isPtrSafe(++pSecondResDirEntry))
							break;
					}
					tupResLvL2 = { *pSecondResDir, std::move(vecResLvL2) };
				}
			}
			else
			{	//////Resource LvL Root RAW Data.
				pRootResDataEntry = (PIMAGE_RESOURCE_DATA_ENTRY)((DWORD_PTR)pRootResDir + (DWORD_PTR)pRootResDirEntry->OffsetToData);
				if (isPtrSafe(pRootResDataEntry))
				{
					std::byte* pRootResRawDataBegin = (std::byte*)rVAToPtr(pRootResDataEntry->OffsetToData);
					//Checking RAW Resource data pointer out of bounds.
					if (pRootResRawDataBegin && isPtrSafe((DWORD_PTR)pRootResRawDataBegin + (DWORD_PTR)pRootResDataEntry->Size, true))
					{
						vecRootResRawData.reserve(pRootResDataEntry->Size);
						for (unsigned iterResRawData = 0; iterResRawData < pRootResDataEntry->Size; iterResRawData++)
							vecRootResRawData.push_back(*(pRootResRawDataBegin + iterResRawData));
					}
				}
			}
			vecResLvLRoot.emplace_back(*pRootResDirEntry, std::move(strRootResName),
				isPtrSafe(pRootResDataEntry) ? *pRootResDataEntry : IMAGE_RESOURCE_DATA_ENTRY { },
				std::move(vecRootResRawData), tupResLvL2);

			if (!isPtrSafe(++pRootResDirEntry))
				break;
		}
		m_tupResourceTable = { *pRootResDir, std::move(vecResLvLRoot) };
	}
	catch (const std::bad_alloc&)
	{
		m_pEmergencyMemory.reset();
		MessageBox(nullptr, L"E_OUTOFMEMORY error while trying to get Resource table.\nFile seems to be corrupted.",
			L"Error", MB_ICONERROR);

		m_pEmergencyMemory = std::make_unique<char []>(0x8FFF);
	}
	catch (...)
	{
		MessageBox(nullptr, L"Unknown exception raised while trying to get Resource table.\r\n\nFile seems to be corrupted.",
			L"Error", MB_ICONERROR);
	}

	m_dwFileSummary |= IMAGE_FLAG_RESOURCE;

	return S_OK;
}

HRESULT Clibpe::getExceptionTable()
{
	//IMAGE_RUNTIME_FUNCTION_ENTRY (without leading underscore) 
	//might have different typedef depending on defined platform, see winnt.h
	_PIMAGE_RUNTIME_FUNCTION_ENTRY pRuntimeFuncsEntry = (_PIMAGE_RUNTIME_FUNCTION_ENTRY)rVAToPtr(getDirEntryRVA(IMAGE_DIRECTORY_ENTRY_EXCEPTION));
	if (!pRuntimeFuncsEntry)
		return E_IMAGE_HAS_NO_EXCEPTION;

	const DWORD dwEntries = getDirEntrySize(IMAGE_DIRECTORY_ENTRY_EXCEPTION) / (DWORD)sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY);
	if (!dwEntries || !isPtrSafe((DWORD_PTR)pRuntimeFuncsEntry + dwEntries))
		return E_IMAGE_HAS_NO_EXCEPTION;

	m_vecExceptionTable.reserve(dwEntries);
	for (unsigned i = 0; i < dwEntries; i++, pRuntimeFuncsEntry++)
		m_vecExceptionTable.push_back(*pRuntimeFuncsEntry);

	m_dwFileSummary |= IMAGE_FLAG_EXCEPTION;

	return S_OK;
}

HRESULT Clibpe::getSecurityTable()
{
	const DWORD dwSecurityDirOffset = getDirEntryRVA(IMAGE_DIRECTORY_ENTRY_SECURITY);
	const DWORD dwSecurityDirSize = getDirEntrySize(IMAGE_DIRECTORY_ENTRY_SECURITY);

	if (!dwSecurityDirOffset || !dwSecurityDirSize)
		return E_IMAGE_HAS_NO_SECURITY;

	DWORD_PTR dwSecurityDirStartVA;

	//Checks for bogus file offsets that can cause DWORD_PTR overflow.
	if (m_fMapViewOfFileWhole)
	{
	#if INTPTR_MAX == INT32_MAX
		if (dwSecurityDirOffset >= (UINT_MAX - (DWORD_PTR)m_lpBase))
			return E_IMAGE_HAS_NO_SECURITY;
	#elif INTPTR_MAX == INT64_MAX
		if (dwSecurityDirOffset >= (MAXDWORD64 - (DWORD_PTR)m_lpBase))
			return E_IMAGE_HAS_NO_SECURITY;
	#endif

		dwSecurityDirStartVA = (DWORD_PTR)m_lpBase + (DWORD_PTR)dwSecurityDirOffset;
	}
	else
	{
	#if INTPTR_MAX == INT32_MAX
		if (dwSecurityDirOffset >= (UINT_MAX - (DWORD_PTR)m_lpSectionBase))
			return E_IMAGE_HAS_NO_SECURITY;
	#elif INTPTR_MAX == INT64_MAX
		if (dwSecurityDirOffset >= (MAXDWORD64 - (DWORD_PTR)m_lpSectionBase))
			return E_IMAGE_HAS_NO_SECURITY;
	#endif

		dwSecurityDirStartVA = (DWORD_PTR)m_lpSectionBase + (DWORD_PTR)m_dwDeltaFileOffsetToMap;
	}

#if INTPTR_MAX == INT32_MAX
	if (dwSecurityDirStartVA > ((DWORD_PTR)UINT_MAX - (DWORD_PTR)dwSecurityDirSize))
		return E_IMAGE_HAS_NO_SECURITY;
#elif INTPTR_MAX == INT64_MAX
	if (dwSecurityDirStartVA > (MAXDWORD64 - (DWORD_PTR)dwSecurityDirSize))
		return E_IMAGE_HAS_NO_SECURITY;
#endif

	const DWORD_PTR dwSecurityDirEndVA = dwSecurityDirStartVA + (DWORD_PTR)dwSecurityDirSize;

	if (!isPtrSafe(dwSecurityDirStartVA) || !isPtrSafe(dwSecurityDirEndVA, true))
		return E_IMAGE_HAS_NO_SECURITY;

	while (dwSecurityDirStartVA < dwSecurityDirEndVA)
	{
		LPWIN_CERTIFICATE pCertificate = (LPWIN_CERTIFICATE)dwSecurityDirStartVA;
		DWORD_PTR dwCertByteEnd = (DWORD_PTR)pCertificate->dwLength - offsetof(WIN_CERTIFICATE, bCertificate);
		if (!isPtrSafe(dwSecurityDirStartVA + dwCertByteEnd))
			break;

		std::vector<std::byte> vecCertBytes { };

		for (DWORD_PTR iterCertData = 0; iterCertData < dwCertByteEnd; iterCertData++)
			vecCertBytes.push_back((std::byte)pCertificate->bCertificate[iterCertData]);

		m_vecSecurity.emplace_back(*pCertificate, std::move(vecCertBytes));

		//Get next certificate entry, all entries start at 8 aligned address.
		DWORD_PTR dwLength = (DWORD_PTR)pCertificate->dwLength;
		dwLength += (8 - (dwLength & 7)) & 7;
		dwSecurityDirStartVA = dwSecurityDirStartVA + dwLength;
		if (!isPtrSafe(dwSecurityDirStartVA))
			break;
	}
	m_dwFileSummary |= IMAGE_FLAG_SECURITY;

	return S_OK;
}

HRESULT Clibpe::getRelocationTable()
{
	PIMAGE_BASE_RELOCATION pBaseRelocDesc = (PIMAGE_BASE_RELOCATION)rVAToPtr(getDirEntryRVA(IMAGE_DIRECTORY_ENTRY_BASERELOC));

	if (!pBaseRelocDesc)
		return E_IMAGE_HAS_NO_BASERELOC;

	try
	{
		while ((pBaseRelocDesc->SizeOfBlock) && (pBaseRelocDesc->VirtualAddress))
		{
			if (pBaseRelocDesc->SizeOfBlock < sizeof(IMAGE_BASE_RELOCATION))
				return E_IMAGE_HAS_NO_BASERELOC;

			//Amount of Reloc entries.
			DWORD dwRelocEntries = (pBaseRelocDesc->SizeOfBlock - (DWORD)sizeof(IMAGE_BASE_RELOCATION)) / (DWORD)sizeof(WORD);
			PWORD pRelocEntry = PWORD((DWORD_PTR)pBaseRelocDesc + sizeof(IMAGE_BASE_RELOCATION));
			WORD wRelocType { };
			std::vector<std::tuple<WORD/*type*/, WORD/*offset*/>> vecRelocs { };

			//In case of bogus SizeOfBlock just getting descriptor, empty vector and breaking out.
			if (!isPtrSafe((DWORD_PTR)pBaseRelocDesc + sizeof(IMAGE_BASE_RELOCATION) + pBaseRelocDesc->SizeOfBlock))
			{
				m_vecRelocationTable.emplace_back(*pBaseRelocDesc, std::move(vecRelocs));
				break;
			}

			vecRelocs.reserve(dwRelocEntries);
			for (DWORD i = 0; i < dwRelocEntries; i++, pRelocEntry++)
			{
				if (!isPtrSafe(pRelocEntry))
					break;
				//Getting HIGH 4 bits of reloc's entry WORD —> reloc type.
				wRelocType = (*pRelocEntry & 0xF000) >> 12;
				vecRelocs.emplace_back(wRelocType, ((*pRelocEntry) & 0x0fff)/*Low 12 bits —> Offset*/);
				if (wRelocType == IMAGE_REL_BASED_HIGHADJ)
				{	//The base relocation adds the high 16 bits of the difference to the 16-bit field at offset.
					//The 16-bit field represents the high value of a 32-bit word. 
					//The low 16 bits of the 32-bit value are stored in the 16-bit word that follows this base relocation.
					//This means that this base relocation occupies two slots. (MSDN)
					if (!isPtrSafe(++pRelocEntry))
					{
						vecRelocs.clear();
						break;
					}
					vecRelocs.emplace_back(wRelocType, *pRelocEntry/*The low 16-bit field*/);
					dwRelocEntries--; //to compensate pRelocEntry++
				}
			}
			m_vecRelocationTable.emplace_back(*pBaseRelocDesc, std::move(vecRelocs));

			//Too big (bogus) SizeOfBlock may cause DWORD_PTR overflow.
			//Checking to prevent.
		#if INTPTR_MAX == INT32_MAX
			if ((DWORD_PTR)pBaseRelocDesc >= ((DWORD_PTR)UINT_MAX - (DWORD_PTR)pBaseRelocDesc->SizeOfBlock))
				break;
		#elif INTPTR_MAX == INT64_MAX
			if ((DWORD_PTR)pBaseRelocDesc >= (MAXDWORD64 - (DWORD_PTR)pBaseRelocDesc->SizeOfBlock))
				break;
		#endif
			pBaseRelocDesc = PIMAGE_BASE_RELOCATION((DWORD_PTR)pBaseRelocDesc + (DWORD_PTR)pBaseRelocDesc->SizeOfBlock);
			if (!isPtrSafe(pBaseRelocDesc))
				break;
		}
	}
	catch (const std::bad_alloc&)
	{
		m_pEmergencyMemory.reset();
		MessageBox(nullptr, L"E_OUTOFMEMORY error while trying to get Relocation table.\nFile seems to be corrupted.",
			L"Error", MB_ICONERROR);

		m_pEmergencyMemory = std::make_unique<char []>(0x8FFF);
	}
	catch (...)
	{
		MessageBox(nullptr, L"Unknown exception raised while trying to get Relocation table.\nFile seems to be corrupted.",
			L"Error", MB_ICONERROR);
	}

	m_dwFileSummary |= IMAGE_FLAG_BASERELOC;

	return S_OK;
}

HRESULT Clibpe::getDebugTable()
{
	const DWORD dwDebugDirRVA = getDirEntryRVA(IMAGE_DIRECTORY_ENTRY_DEBUG);

	if (!dwDebugDirRVA)
		return E_IMAGE_HAS_NO_DEBUG;

	PIMAGE_DEBUG_DIRECTORY pDebugDir;
	DWORD dwDebugDirSize;
	PIMAGE_SECTION_HEADER pDebugSecHdr = getSecHdrFromName(".debug");
	if (pDebugSecHdr && (pDebugSecHdr->VirtualAddress == dwDebugDirRVA))
	{
		if (m_fMapViewOfFileWhole)
			pDebugDir = (PIMAGE_DEBUG_DIRECTORY)((DWORD_PTR)pDebugSecHdr->PointerToRawData + (DWORD_PTR)m_lpBase);
		else
			pDebugDir = (PIMAGE_DEBUG_DIRECTORY)((DWORD_PTR)m_lpSectionBase + (DWORD_PTR)m_dwDeltaFileOffsetToMap);

		dwDebugDirSize = getDirEntrySize(IMAGE_DIRECTORY_ENTRY_DEBUG) * (DWORD)sizeof(IMAGE_DEBUG_DIRECTORY);
	}
	else //Looking for the debug directory.
	{
		if (!(pDebugSecHdr = getSecHdrFromRVA(dwDebugDirRVA)))
			return E_IMAGE_HAS_NO_DEBUG;

		if (!(pDebugDir = (PIMAGE_DEBUG_DIRECTORY)rVAToPtr(dwDebugDirRVA)))
			return E_IMAGE_HAS_NO_DEBUG;

		dwDebugDirSize = getDirEntrySize(IMAGE_DIRECTORY_ENTRY_DEBUG);
	}

	const DWORD dwDebugEntries = dwDebugDirSize / (DWORD)sizeof(IMAGE_DEBUG_DIRECTORY);

	if (!dwDebugEntries || !isPtrSafe((DWORD_PTR)pDebugDir + dwDebugDirSize))
		return E_IMAGE_HAS_NO_DEBUG;

	try {
		m_vecDebugTable.reserve(dwDebugEntries);
		for (unsigned i = 0; i < dwDebugEntries; i++)
		{
			std::vector<std::byte> vecDebugRawData { };
			std::byte* pDebugRawData { };

			if (m_fMapViewOfFileWhole)
				pDebugRawData = (std::byte*)((DWORD_PTR)m_lpBase + pDebugDir->PointerToRawData);
			else
				pDebugRawData = (std::byte*)((DWORD_PTR)m_lpSectionBase + (pDebugDir->PointerToRawData - pDebugSecHdr->PointerToRawData));

			if (isPtrSafe(pDebugRawData) && isPtrSafe(pDebugRawData + pDebugDir->SizeOfData))
			{
				vecDebugRawData.reserve(pDebugDir->SizeOfData);
				for (size_t iterRawData = 0; iterRawData < pDebugDir->SizeOfData; iterRawData++)
					vecDebugRawData.push_back(*(pDebugRawData + iterRawData));
			}

			m_vecDebugTable.emplace_back(*pDebugDir, std::move(vecDebugRawData));
			if (!isPtrSafe(++pDebugDir))
				break;
		}

		m_dwFileSummary |= IMAGE_FLAG_DEBUG;
	}
	catch (const std::bad_alloc&)
	{
		m_pEmergencyMemory;
		MessageBox(nullptr, L"E_OUTOFMEMORY error while trying to get Debug info.\r\n"
			L"File seems to be corrupted.", L"Error", MB_ICONERROR);

		m_pEmergencyMemory = std::make_unique<char []>(0x8FFF);
	}
	return S_OK;
}

HRESULT Clibpe::getArchitectureTable()
{
	const DWORD dwArchDirRVA = getDirEntryRVA(IMAGE_DIRECTORY_ENTRY_ARCHITECTURE);
	if (!dwArchDirRVA)
		return E_IMAGE_HAS_NO_ARCHITECTURE;

	const PIMAGE_ARCHITECTURE_ENTRY pArchEntry = (PIMAGE_ARCHITECTURE_ENTRY)rVAToPtr(dwArchDirRVA);
	if (!pArchEntry)
		return E_IMAGE_HAS_NO_ARCHITECTURE;

	m_dwFileSummary |= IMAGE_FLAG_ARCHITECTURE;

	return S_OK;
}

HRESULT Clibpe::getGlobalPtrTable()
{
	const DWORD_PTR dwGlobalPTRDirRVA = (DWORD_PTR)rVAToPtr(getDirEntryRVA(IMAGE_DIRECTORY_ENTRY_GLOBALPTR));
	if (!dwGlobalPTRDirRVA)
		return E_IMAGE_HAS_NO_GLOBALPTR;

	m_dwFileSummary |= IMAGE_FLAG_GLOBALPTR;

	return S_OK;
}

HRESULT Clibpe::getTLSTable()
{
	const DWORD dwTLSDirRVA = getDirEntryRVA(IMAGE_DIRECTORY_ENTRY_TLS);
	if (!dwTLSDirRVA)
		return E_IMAGE_HAS_NO_TLS;

	try {
		std::vector<std::byte> vecTLSRawData { };
		std::vector<DWORD> vecTLSCallbacks { };
		ULONGLONG ulStartAddressOfRawData { }, ulEndAddressOfRawData { }, ulAddressOfCallBacks { };
		std::variant<IMAGE_TLS_DIRECTORY32, IMAGE_TLS_DIRECTORY64> varTLSDir { };

		if (ImageHasFlag(m_dwFileSummary, IMAGE_FLAG_PE32))
		{
			const PIMAGE_TLS_DIRECTORY32 pTLSDir32 = (PIMAGE_TLS_DIRECTORY32)rVAToPtr(dwTLSDirRVA);
			if (!pTLSDir32)
				return E_IMAGE_HAS_NO_TLS;

			varTLSDir = *pTLSDir32;
			ulStartAddressOfRawData = pTLSDir32->StartAddressOfRawData;
			ulEndAddressOfRawData = pTLSDir32->EndAddressOfRawData;
			ulAddressOfCallBacks = pTLSDir32->AddressOfCallBacks;
		}
		else if (ImageHasFlag(m_dwFileSummary, IMAGE_FLAG_PE64))
		{
			const PIMAGE_TLS_DIRECTORY64 pTLSDir64 = (PIMAGE_TLS_DIRECTORY64)rVAToPtr(dwTLSDirRVA);
			if (!pTLSDir64)
				return E_IMAGE_HAS_NO_TLS;

			varTLSDir = *pTLSDir64;
			ulStartAddressOfRawData = pTLSDir64->StartAddressOfRawData;
			ulEndAddressOfRawData = pTLSDir64->EndAddressOfRawData;
			ulAddressOfCallBacks = pTLSDir64->AddressOfCallBacks;
		}
		else
			return E_IMAGE_HAS_NO_TLS;

		//All TLS adresses are not RVA, but actual VA.
		//So we must subtract ImageBase before pass to rVAToPtr().
		std::byte* pTLSRawStart = (std::byte*)rVAToPtr(ulStartAddressOfRawData - m_ulImageBase);
		std::byte* pTLSRawEnd = (std::byte*)rVAToPtr(ulEndAddressOfRawData - m_ulImageBase);
		if (pTLSRawStart && pTLSRawEnd && pTLSRawEnd > pTLSRawStart)
		{
			DWORD_PTR dwTLSRawSize = pTLSRawEnd - pTLSRawStart;
			if (!isPtrSafe((DWORD_PTR)pTLSRawStart + dwTLSRawSize))
				return E_IMAGE_HAS_NO_TLS;

			vecTLSRawData.reserve(dwTLSRawSize);
			for (size_t iterTLS = 0; iterTLS < dwTLSRawSize; iterTLS++)
				vecTLSRawData.push_back(*(pTLSRawStart + iterTLS));

		}
		PDWORD pTLSCallbacks = (PDWORD)rVAToPtr(ulAddressOfCallBacks - m_ulImageBase);
		if (pTLSCallbacks)
		{
			while (*pTLSCallbacks)
			{
				vecTLSCallbacks.push_back(*pTLSCallbacks);
				if (!isPtrSafe(++pTLSCallbacks))
				{
					vecTLSCallbacks.clear();
					break;
				}
			}
		}

		m_tupTLS = { std::move(varTLSDir), std::move(vecTLSRawData), std::move(vecTLSCallbacks) };
		m_dwFileSummary |= IMAGE_FLAG_TLS;
	}
	catch (const std::bad_alloc&)
	{
		m_pEmergencyMemory.reset();
		MessageBox(nullptr, L"E_OUTOFMEMORY error while trying to get TLS table.\r\n"
			L"File seems to be corrupted.", L"Error", MB_ICONERROR);

		m_pEmergencyMemory = std::make_unique<char []>(0x8FFF);
	}
	catch (...)
	{
		MessageBox(nullptr, L"Unknown exception raised while trying to get TLS table.\r\nFile seems to be corrupted.",
			L"Error", MB_ICONERROR);
	}

	return S_OK;
}

HRESULT Clibpe::getLoadConfigTable()
{
	if (ImageHasFlag(m_dwFileSummary, IMAGE_FLAG_PE32))
	{
		const PIMAGE_LOAD_CONFIG_DIRECTORY32 pLoadConfigDir32 = (PIMAGE_LOAD_CONFIG_DIRECTORY32)rVAToPtr(
			getDirEntryRVA(IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG));
		if (!pLoadConfigDir32)
			return E_IMAGE_HAS_NO_LOADCONFIG;

		m_varLoadConfigDir = *pLoadConfigDir32;
	}
	else if (ImageHasFlag(m_dwFileSummary, IMAGE_FLAG_PE64))
	{
		const PIMAGE_LOAD_CONFIG_DIRECTORY64 pLoadConfigDir64 = (PIMAGE_LOAD_CONFIG_DIRECTORY64)rVAToPtr(
			getDirEntryRVA(IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG));
		if (!pLoadConfigDir64)
			return E_IMAGE_HAS_NO_LOADCONFIG;

		m_varLoadConfigDir = *pLoadConfigDir64;
	}
	else
		return E_IMAGE_HAS_NO_LOADCONFIG;

	m_dwFileSummary |= IMAGE_FLAG_LOADCONFIG;

	return S_OK;
}

HRESULT Clibpe::getBoundImportTable()
{
	PIMAGE_BOUND_IMPORT_DESCRIPTOR pBoundImpDesc =
		(PIMAGE_BOUND_IMPORT_DESCRIPTOR)rVAToPtr(getDirEntryRVA(IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT));

	if (!pBoundImpDesc)
		return E_IMAGE_HAS_NO_BOUNDIMPORT;

	while (pBoundImpDesc->TimeDateStamp)
	{
		std::string strModuleName { };
		std::vector<std::tuple<IMAGE_BOUND_FORWARDER_REF, std::string>> vecBoundForwarders { };

		PIMAGE_BOUND_FORWARDER_REF pBoundImpForwarder = (PIMAGE_BOUND_FORWARDER_REF)(pBoundImpDesc + 1);
		if (!isPtrSafe(pBoundImpForwarder))
			break;

		for (unsigned i = 0; i < pBoundImpDesc->NumberOfModuleForwarderRefs; i++)
		{
			std::string strForwarderModuleName { };

			const LPCSTR szName = (LPCSTR)((DWORD_PTR)pBoundImpDesc + pBoundImpForwarder->OffsetModuleName);
			if (isPtrSafe(szName))
				if (szName && (StringCchLengthA(szName, MAX_PATH, nullptr) != STRSAFE_E_INVALID_PARAMETER))
					strForwarderModuleName = szName;

			vecBoundForwarders.emplace_back(*pBoundImpForwarder, std::move(strForwarderModuleName));

			if (!isPtrSafe(++pBoundImpForwarder))
				break;

			pBoundImpDesc = (PIMAGE_BOUND_IMPORT_DESCRIPTOR)((DWORD_PTR)pBoundImpDesc + sizeof(IMAGE_BOUND_FORWARDER_REF));
			if (!isPtrSafe(pBoundImpDesc))
				break;
		}

		const LPCSTR szName = (LPCSTR)((DWORD_PTR)pBoundImpDesc + pBoundImpDesc->OffsetModuleName);
		if (isPtrSafe(szName))
			if (StringCchLengthA(szName, MAX_PATH, nullptr) != STRSAFE_E_INVALID_PARAMETER)
				strModuleName = szName;

		m_vecBoundImportTable.emplace_back(*pBoundImpDesc, std::move(strModuleName), std::move(vecBoundForwarders));

		if (!isPtrSafe(++pBoundImpDesc))
			break;
	}

	m_dwFileSummary |= IMAGE_FLAG_BOUNDIMPORT;

	return S_OK;
}

HRESULT Clibpe::getIATTable()
{
	const DWORD_PTR dwIATDirRVA = (DWORD_PTR)rVAToPtr(getDirEntryRVA(IMAGE_DIRECTORY_ENTRY_IAT));
	if (!dwIATDirRVA)
		return E_IMAGE_HAS_NO_IAT;

	m_dwFileSummary |= IMAGE_FLAG_IAT;

	return S_OK;
}

HRESULT Clibpe::getDelayImportTable()
{
	PIMAGE_DELAYLOAD_DESCRIPTOR pDelayImpDescriptor = (PIMAGE_DELAYLOAD_DESCRIPTOR)rVAToPtr(getDirEntryRVA(IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT));
	if (!pDelayImpDescriptor)
		return E_IMAGE_HAS_NO_DELAYIMPORT;

	if (ImageHasFlag(m_dwFileSummary, IMAGE_FLAG_PE32))
	{
		while (pDelayImpDescriptor->DllNameRVA)
		{
			PIMAGE_THUNK_DATA32 pThunk32Name = (PIMAGE_THUNK_DATA32)(DWORD_PTR)pDelayImpDescriptor->ImportNameTableRVA;

			if (!pThunk32Name) {
				if (!isPtrSafe(++pDelayImpDescriptor))
					break;
			}
			else
			{
				std::string strDllName { };
				std::vector<std::tuple<LONGLONG/*Ordinal/Hint*/, std::string/*Func name*/, LONGLONG/*Thunk table RVA*/,
					LONGLONG/*IAT->u1.AddressOfData*/, LONGLONG/*BoundIAT->u1.AddressOfData*/, LONGLONG/*UnloadInfoIAT->u1.AddressOfData*/>> vecFunc { };

				pThunk32Name = (PIMAGE_THUNK_DATA32)rVAToPtr((DWORD_PTR)pThunk32Name);
				PIMAGE_THUNK_DATA32 pThunk32IAT = (PIMAGE_THUNK_DATA32)rVAToPtr(pDelayImpDescriptor->ImportAddressTableRVA);
				PIMAGE_THUNK_DATA32 pThunk32BoundIAT = (PIMAGE_THUNK_DATA32)rVAToPtr(
					pDelayImpDescriptor->BoundImportAddressTableRVA);
				PIMAGE_THUNK_DATA32 pThunk32UnloadInfoIAT = (PIMAGE_THUNK_DATA32)rVAToPtr(
					pDelayImpDescriptor->UnloadInformationTableRVA);

				if (!pThunk32Name)
					break;

				while (pThunk32Name->u1.AddressOfData)
				{
					if (pThunk32Name->u1.Ordinal & IMAGE_ORDINAL_FLAG32)
						vecFunc.emplace_back(IMAGE_ORDINAL32(pThunk32Name->u1.Ordinal), "",
							pThunk32Name->u1.AddressOfData,
							pThunk32IAT ? pThunk32IAT->u1.AddressOfData : 0,
							pThunk32BoundIAT ? pThunk32BoundIAT->u1.AddressOfData : 0,
							pThunk32UnloadInfoIAT ? pThunk32UnloadInfoIAT->u1.AddressOfData : 0);
					else {
						std::string strFuncName { };
						//Filling Hint, Name and Thunk RVA.
						const PIMAGE_IMPORT_BY_NAME pName = (PIMAGE_IMPORT_BY_NAME)rVAToPtr(pThunk32Name->u1.AddressOfData);
						if (pName && (StringCchLengthA(pName->Name, MAX_PATH, nullptr) != STRSAFE_E_INVALID_PARAMETER))
							strFuncName = pName->Name;

						vecFunc.emplace_back(pName ? pName->Hint : 0, std::move(strFuncName),
							pThunk32Name->u1.AddressOfData,
							pThunk32IAT ? pThunk32IAT->u1.AddressOfData : 0,
							pThunk32BoundIAT ? pThunk32BoundIAT->u1.AddressOfData : 0,
							pThunk32UnloadInfoIAT ? pThunk32UnloadInfoIAT->u1.AddressOfData : 0);
					}

					if (!isPtrSafe(++pThunk32Name))
						break;
					if (pThunk32IAT)
						if (!isPtrSafe(++pThunk32IAT))
							break;
					if (pThunk32BoundIAT)
						if (!isPtrSafe(++pThunk32BoundIAT))
							break;
					if (pThunk32UnloadInfoIAT)
						if (!isPtrSafe(++pThunk32UnloadInfoIAT))
							break;
				}

				const LPCSTR szName = (LPCSTR)rVAToPtr(pDelayImpDescriptor->DllNameRVA);
				if (szName && (StringCchLengthA(szName, MAX_PATH, nullptr) != STRSAFE_E_INVALID_PARAMETER))
					strDllName = szName;

				m_vecDelayImportTable.emplace_back(*pDelayImpDescriptor, std::move(strDllName), std::move(vecFunc));

				if (!isPtrSafe(++pDelayImpDescriptor))
					break;
			}
		}
	}
	else if (ImageHasFlag(m_dwFileSummary, IMAGE_FLAG_PE64))
	{
		while (pDelayImpDescriptor->DllNameRVA)
		{
			PIMAGE_THUNK_DATA64 pThunk64Name = (PIMAGE_THUNK_DATA64)(DWORD_PTR)pDelayImpDescriptor->ImportNameTableRVA;

			if (!pThunk64Name) {
				if (!isPtrSafe(++pDelayImpDescriptor))
					break;
			}
			else
			{
				std::string strDllName { };
				std::vector<std::tuple<LONGLONG/*Ordinal/Hint*/, std::string/*Func name*/, LONGLONG/*Thunk table RVA*/,
					LONGLONG/*IAT->u1.AddressOfData*/, LONGLONG/*BoundIAT->u1.AddressOfData*/, LONGLONG/*UnloadInfoIAT->u1.AddressOfData*/>> vecFunc { };

				pThunk64Name = (PIMAGE_THUNK_DATA64)rVAToPtr((DWORD_PTR)pThunk64Name);
				PIMAGE_THUNK_DATA64 pThunk64IAT = (PIMAGE_THUNK_DATA64)rVAToPtr(pDelayImpDescriptor->ImportAddressTableRVA);
				PIMAGE_THUNK_DATA64 pThunk64BoundIAT = (PIMAGE_THUNK_DATA64)rVAToPtr(
					pDelayImpDescriptor->BoundImportAddressTableRVA);
				PIMAGE_THUNK_DATA64 pThunk64UnloadInfoIAT = (PIMAGE_THUNK_DATA64)rVAToPtr(
					pDelayImpDescriptor->UnloadInformationTableRVA);

				if (!pThunk64Name)
					break;

				while (pThunk64Name->u1.AddressOfData)
				{
					if (pThunk64Name->u1.Ordinal & IMAGE_ORDINAL_FLAG64)
						vecFunc.emplace_back(IMAGE_ORDINAL64(pThunk64Name->u1.Ordinal), "",
							pThunk64Name->u1.AddressOfData,
							pThunk64IAT ? pThunk64IAT->u1.AddressOfData : 0,
							pThunk64BoundIAT ? pThunk64BoundIAT->u1.AddressOfData : 0,
							pThunk64UnloadInfoIAT ? pThunk64UnloadInfoIAT->u1.AddressOfData : 0);
					else
					{
						std::string strFuncName { };

						//Filling Hint, Name and Thunk RVA.
						const PIMAGE_IMPORT_BY_NAME pName = (PIMAGE_IMPORT_BY_NAME)rVAToPtr(pThunk64Name->u1.AddressOfData);
						if (pName && (StringCchLengthA(pName->Name, MAX_PATH, nullptr) != STRSAFE_E_INVALID_PARAMETER))
							strFuncName = pName->Name;

						vecFunc.emplace_back(pName ? pName->Hint : 0, std::move(strFuncName),
							pThunk64Name->u1.AddressOfData,
							pThunk64IAT ? pThunk64IAT->u1.AddressOfData : 0,
							pThunk64BoundIAT ? pThunk64BoundIAT->u1.AddressOfData : 0,
							pThunk64UnloadInfoIAT ? pThunk64UnloadInfoIAT->u1.AddressOfData : 0);
					}

					if (!isPtrSafe(++pThunk64Name))
						break;
					if (pThunk64IAT)
						if (!isPtrSafe(++pThunk64IAT))
							break;
					if (pThunk64BoundIAT)
						if (!isPtrSafe(++pThunk64BoundIAT))
							break;
					if (pThunk64UnloadInfoIAT)
						if (!isPtrSafe(++pThunk64UnloadInfoIAT))
							break;
				}

				const LPCSTR szName = (LPCSTR)rVAToPtr(pDelayImpDescriptor->DllNameRVA);
				if (szName && (StringCchLengthA(szName, MAX_PATH, nullptr) != STRSAFE_E_INVALID_PARAMETER))
					strDllName = szName;

				m_vecDelayImportTable.emplace_back(*pDelayImpDescriptor, std::move(strDllName), std::move(vecFunc));

				if (!isPtrSafe(++pDelayImpDescriptor))
					break;
			}
		}
	}
	m_dwFileSummary |= IMAGE_FLAG_DELAYIMPORT;

	return S_OK;
}

HRESULT Clibpe::getCOMDescriptorTable()
{
	const PIMAGE_COR20_HEADER pCOMDescriptorHeader = (PIMAGE_COR20_HEADER)rVAToPtr(getDirEntryRVA(IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR));
	if (!pCOMDescriptorHeader)
		return E_IMAGE_HAS_NO_COMDESCRIPTOR;

	m_stCOR20Header = *pCOMDescriptorHeader;
	m_dwFileSummary |= IMAGE_FLAG_COMDESCRIPTOR;

	return S_OK;
}