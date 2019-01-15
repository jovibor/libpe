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
			m_ullwMaxPointerBound = (DWORD_PTR)m_lpBase + (DWORD_PTR)m_dwMinBytesToMap;
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
		m_ullwMaxPointerBound = (DWORD_PTR)m_lpBase + m_stFileSize.QuadPart;
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
		getExport();
		getImport();
		getResources();
		getExceptions();
		getSecurity();
		getRelocations();
		getDebug();
		getArchitecture();
		getGlobalPtr();
		getTLS();
		getLCD();
		getBoundImport();
		getIAT();
		getDelayImport();
		getCOMDescriptor();
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

HRESULT Clibpe::GetPESummary(PCDWORD& pFileSummary)
{
	if (!m_fLoaded)
	{
		pFileSummary = nullptr;
		return E_CALL_LOADPE_FIRST;
	}

	pFileSummary = &m_dwFileSummary;

	return S_OK;
}

HRESULT Clibpe::GetMSDOSHeader(PCLIBPE_DOSHEADER& pDosHeader)
{
	if (!m_fLoaded)
	{
		pDosHeader = nullptr;
		return E_CALL_LOADPE_FIRST;
	}
	if (!ImageHasFlag(m_dwFileSummary, IMAGE_FLAG_DOSHEADER))
	{
		pDosHeader = nullptr;
		return E_IMAGE_HAS_NO_DOSHEADER;
	}

	pDosHeader = &m_stMSDOSHeader;

	return S_OK;
}

HRESULT Clibpe::GetRichHeader(PCLIBPE_RICHHEADER_VEC& pVecRich)
{
	if (!m_fLoaded)
	{
		pVecRich = nullptr;
		return E_CALL_LOADPE_FIRST;
	}
	if (!ImageHasFlag(m_dwFileSummary, IMAGE_FLAG_RICHHEADER))
	{
		pVecRich = nullptr;
		return E_IMAGE_HAS_NO_RICHHEADER;
	}

	pVecRich = &m_vecRichHeader;

	return S_OK;
}

HRESULT Clibpe::GetNTHeader(PCLIBPE_NTHEADER_VAR& pVarNTHdr)
{
	if (!m_fLoaded)
	{
		pVarNTHdr = nullptr;
		return E_CALL_LOADPE_FIRST;
	}
	if (!ImageHasFlag(m_dwFileSummary, IMAGE_FLAG_NTHEADER))
	{
		pVarNTHdr = nullptr;
		return E_IMAGE_HAS_NO_NTHEADER;
	}

	pVarNTHdr = &m_varNTHeader;

	return S_OK;
}

HRESULT Clibpe::GetFileHeader(PCLIBPE_FILEHEADER& pFileHeader)
{
	if (!m_fLoaded)
	{
		pFileHeader = nullptr;
		return E_CALL_LOADPE_FIRST;
	}
	if (!ImageHasFlag(m_dwFileSummary, IMAGE_FLAG_FILEHEADER))
	{
		pFileHeader = nullptr;
		return E_IMAGE_HAS_NO_FILEHEADER;
	}

	pFileHeader = &m_stFileHeader;

	return S_OK;
}

HRESULT Clibpe::GetOptionalHeader(PCLIBPE_OPTHEADER_VAR& pVarOptHeader)
{
	if (!m_fLoaded)
	{
		pVarOptHeader = nullptr;
		return E_CALL_LOADPE_FIRST;
	}
	if (!ImageHasFlag(m_dwFileSummary, IMAGE_FLAG_OPTHEADER))
	{
		pVarOptHeader = nullptr;
		return E_IMAGE_HAS_NO_OPTHEADER;
	}

	pVarOptHeader = &m_varOptHeader;

	return S_OK;
}

HRESULT Clibpe::GetDataDirectories(PCLIBPE_DATADIRS_VEC& pVecDataDir)
{
	if (!m_fLoaded)
	{
		pVecDataDir = nullptr;
		return E_CALL_LOADPE_FIRST;
	}
	if (!ImageHasFlag(m_dwFileSummary, IMAGE_FLAG_DATADIRECTORIES))
	{
		pVecDataDir = nullptr;
		return E_IMAGE_HAS_NO_DATADIRECTORIES;
	}

	pVecDataDir = &m_vecDataDirectories;

	return S_OK;
}

HRESULT Clibpe::GetSectionsHeaders(PCLIBPE_SECHEADERS_VEC& pVecSections)
{
	if (!m_fLoaded)
	{
		pVecSections = nullptr;
		return E_CALL_LOADPE_FIRST;
	}
	if (!ImageHasFlag(m_dwFileSummary, IMAGE_FLAG_SECTIONS))
	{
		pVecSections = nullptr;
		return E_IMAGE_HAS_NO_SECTIONS;
	}

	pVecSections = &m_vecSecHeaders;

	return S_OK;
}

HRESULT Clibpe::GetExport(PCLIBPE_EXPORT& pTupExport)
{
	if (!m_fLoaded)
	{
		pTupExport = nullptr;
		return E_CALL_LOADPE_FIRST;
	}
	if (!ImageHasFlag(m_dwFileSummary, IMAGE_FLAG_EXPORT))
	{
		pTupExport = nullptr;
		return E_IMAGE_HAS_NO_EXPORT;
	}

	pTupExport = &m_stExport;

	return S_OK;
}

HRESULT Clibpe::GetImport(PCLIBPE_IMPORT_VEC& pVecImport)
{
	if (!m_fLoaded)
	{
		pVecImport = nullptr;
		return E_CALL_LOADPE_FIRST;
	}
	if (!ImageHasFlag(m_dwFileSummary, IMAGE_FLAG_IMPORT))
	{
		pVecImport = nullptr;
		return E_IMAGE_HAS_NO_IMPORT;
	}

	pVecImport = &m_vecImport;

	return S_OK;
}

HRESULT Clibpe::GetResources(PCLIBPE_RESOURCE_ROOT& pTupRes)
{
	if (!m_fLoaded)
	{
		pTupRes = nullptr;
		return E_CALL_LOADPE_FIRST;
	}
	if (!ImageHasFlag(m_dwFileSummary, IMAGE_FLAG_RESOURCE))
	{
		pTupRes = nullptr;
		return E_IMAGE_HAS_NO_RESOURCE;
	}

	pTupRes = &m_stResource;

	return S_OK;
}

HRESULT Clibpe::GetExceptions(PCLIBPE_EXCEPTION_VEC& pVecException)
{
	if (!m_fLoaded)
	{
		pVecException = nullptr;
		return E_CALL_LOADPE_FIRST;
	}
	if (!ImageHasFlag(m_dwFileSummary, IMAGE_FLAG_EXCEPTION))
	{
		pVecException = nullptr;
		return E_IMAGE_HAS_NO_EXCEPTION;
	}

	pVecException = &m_vecException;

	return S_OK;
}

HRESULT Clibpe::GetSecurity(PCLIBPE_SECURITY_VEC& pVecSecurity)
{
	if (!m_fLoaded)
	{
		pVecSecurity = nullptr;
		return E_CALL_LOADPE_FIRST;
	}
	if (!ImageHasFlag(m_dwFileSummary, IMAGE_FLAG_SECURITY))
	{
		pVecSecurity = nullptr;
		return E_IMAGE_HAS_NO_SECURITY;
	}

	pVecSecurity = &m_vecSecurity;

	return S_OK;
}

HRESULT Clibpe::GetRelocations(PCLIBPE_RELOCATION_VEC& pVecRelocs)
{
	if (!m_fLoaded)
	{
		pVecRelocs = nullptr;
		return E_CALL_LOADPE_FIRST;
	}
	if (!ImageHasFlag(m_dwFileSummary, IMAGE_FLAG_BASERELOC))
	{
		pVecRelocs = nullptr;
		return E_IMAGE_HAS_NO_BASERELOC;
	}

	pVecRelocs = &m_vecRelocs;

	return S_OK;
}

HRESULT Clibpe::GetDebug(PCLIBPE_DEBUG_VEC& pVecDebug)
{
	if (!m_fLoaded)
	{
		pVecDebug = nullptr;
		return E_CALL_LOADPE_FIRST;
	}
	if (!ImageHasFlag(m_dwFileSummary, IMAGE_FLAG_DEBUG))
	{
		pVecDebug = nullptr;
		return E_IMAGE_HAS_NO_DEBUG;
	}

	pVecDebug = &m_vecDebug;

	return S_OK;
}

HRESULT Clibpe::GetTLS(PCLIBPE_TLS& pTupTLS)
{
	if (!m_fLoaded)
	{
		pTupTLS = nullptr;
		return E_CALL_LOADPE_FIRST;
	}
	if (!ImageHasFlag(m_dwFileSummary, IMAGE_FLAG_TLS))
	{
		pTupTLS = nullptr;
		return E_IMAGE_HAS_NO_TLS;
	}

	pTupTLS = &m_stTLS;

	return S_OK;
}

HRESULT Clibpe::GetLoadConfig(PCLIBPE_LOADCONFIG& pVarLCD)
{
	if (!m_fLoaded)
	{
		pVarLCD = nullptr;
		return E_CALL_LOADPE_FIRST;
	}
	if (!ImageHasFlag(m_dwFileSummary, IMAGE_FLAG_LOADCONFIG))
	{
		pVarLCD = nullptr;
		return E_IMAGE_HAS_NO_LOADCONFIG;
	}

	pVarLCD = &m_stLCD;

	return S_OK;
}

HRESULT Clibpe::GetBoundImport(PCLIBPE_BOUNDIMPORT_VEC& pVecBoundImport)
{
	if (!m_fLoaded)
	{
		pVecBoundImport = nullptr;
		return E_CALL_LOADPE_FIRST;
	}
	if (!ImageHasFlag(m_dwFileSummary, IMAGE_FLAG_BOUNDIMPORT))
	{
		pVecBoundImport = nullptr;
		return E_IMAGE_HAS_NO_BOUNDIMPORT;
	}

	pVecBoundImport = &m_vecBoundImport;

	return S_OK;
}

HRESULT Clibpe::GetDelayImport(PCLIBPE_DELAYIMPORT_VEC& pVecDelayImport)
{
	if (!m_fLoaded)
	{
		pVecDelayImport = nullptr;
		return E_CALL_LOADPE_FIRST;
	}
	if (!ImageHasFlag(m_dwFileSummary, IMAGE_FLAG_DELAYIMPORT))
	{
		pVecDelayImport = nullptr;
		return 	E_IMAGE_HAS_NO_DELAYIMPORT;
	}

	pVecDelayImport = &m_vecDelayImport;

	return S_OK;
}

HRESULT Clibpe::GetCOMDescriptor(PCLIBPE_COMDESCRIPTOR& pCOMDesc)
{
	if (!m_fLoaded)
	{
		pCOMDesc = nullptr;
		return E_CALL_LOADPE_FIRST;
	}
	if (!ImageHasFlag(m_dwFileSummary, IMAGE_FLAG_COMDESCRIPTOR))
	{
		pCOMDesc = nullptr;
		return E_IMAGE_HAS_NO_COMDESCRIPTOR;
	}

	pCOMDesc = &m_stCOR20Desc;

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
		if (!isPtrSafe((DWORD_PTR)pSecHdr + sizeof(IMAGE_SECTION_HEADER)))
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
		if (!isPtrSafe((DWORD_PTR)pSecHdr + sizeof(IMAGE_SECTION_HEADER)))
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
		((DWORD_PTR)tPtr <= m_ullwMaxPointerBound && (DWORD_PTR)tPtr >= (DWORD_PTR)m_lpBase) :
		((DWORD_PTR)tPtr < m_ullwMaxPointerBound && (DWORD_PTR)tPtr >= (DWORD_PTR)m_lpBase));
}

//Performs checking of DWORD_PTR overflow at summing of two variables.
bool Clibpe::isSumOverflow(DWORD_PTR dwFirst, DWORD_PTR dwSecond)
{
	return (dwFirst + dwSecond) < dwFirst;
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
					dwAlignedAddressToMap = (m_dwFileOffsetToMap < m_stSysInfo.dwAllocationGranularity) ? 0 :
					(m_dwFileOffsetToMap - (m_dwFileOffsetToMap % m_stSysInfo.dwAllocationGranularity));
				else
					dwAlignedAddressToMap = m_dwFileOffsetToMap;

				m_dwDeltaFileOffsetToMap = m_dwFileOffsetToMap - dwAlignedAddressToMap;

				dwSizeToMap = (DWORD_PTR)getDirEntrySize(IMAGE_DIRECTORY_ENTRY_SECURITY) + (DWORD_PTR)m_dwDeltaFileOffsetToMap;
				//Checking for out of bounds file's size to map.
				if (((LONGLONG)m_dwFileOffsetToMap + (LONGLONG)getDirEntrySize(IMAGE_DIRECTORY_ENTRY_SECURITY)) <= (m_stFileSize.QuadPart))
				{
					if (!(m_lpSectionBase = MapViewOfFile(m_hMapObject, FILE_MAP_READ, 0, dwAlignedAddressToMap, dwSizeToMap)))
						return E_FILE_MAP_VIEW_OF_FILE_FAILED;

					m_ullwMaxPointerBound = (DWORD_PTR)m_lpSectionBase + dwSizeToMap;
					getSecurity();
					UnmapViewOfFile(m_lpSectionBase);
				}
			}
		}
	}
	else if ((pSecHdr = getSecHdrFromRVA(getDirEntryRVA(dwDirectory))))
	{
		m_dwFileOffsetToMap = pSecHdr->PointerToRawData;

		if (m_dwFileOffsetToMap % m_stSysInfo.dwAllocationGranularity > 0)
			dwAlignedAddressToMap = (m_dwFileOffsetToMap < m_stSysInfo.dwAllocationGranularity) ? 0 :
			(m_dwFileOffsetToMap - (m_dwFileOffsetToMap % m_stSysInfo.dwAllocationGranularity));
		else
			dwAlignedAddressToMap = m_dwFileOffsetToMap;

		m_dwDeltaFileOffsetToMap = m_dwFileOffsetToMap - dwAlignedAddressToMap;
		dwSizeToMap = DWORD_PTR(pSecHdr->Misc.VirtualSize + m_dwDeltaFileOffsetToMap);
		if (((LONGLONG)dwAlignedAddressToMap + dwSizeToMap) > m_stFileSize.QuadPart)
			return E_FILE_SECTION_DATA_CORRUPTED;
		if (!(m_lpSectionBase = MapViewOfFile(m_hMapObject, FILE_MAP_READ, 0, dwAlignedAddressToMap, dwSizeToMap)))
			return E_FILE_MAP_VIEW_OF_FILE_FAILED;

		m_ullwMaxPointerBound = (DWORD_PTR)m_lpSectionBase + dwSizeToMap;
		switch (dwDirectory)
		{
		case IMAGE_DIRECTORY_ENTRY_EXPORT:
			getExport();
			break;
		case IMAGE_DIRECTORY_ENTRY_IMPORT:
			getImport();
			break;
		case IMAGE_DIRECTORY_ENTRY_RESOURCE:
			getResources();
			break;
		case IMAGE_DIRECTORY_ENTRY_EXCEPTION:
			getExceptions();
			break;
		case IMAGE_DIRECTORY_ENTRY_BASERELOC:
			getRelocations();
			break;
		case IMAGE_DIRECTORY_ENTRY_DEBUG:
			getDebug();
			break;
		case IMAGE_DIRECTORY_ENTRY_ARCHITECTURE:
			getArchitecture();
			break;
		case IMAGE_DIRECTORY_ENTRY_GLOBALPTR:
			getGlobalPtr();
			break;
		case IMAGE_DIRECTORY_ENTRY_TLS:
			getTLS();
			break;
		case IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG:
			getLCD();
			break;
		case IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT:
			getBoundImport();
			break;
		case IMAGE_DIRECTORY_ENTRY_IAT:
			getIAT();
			break;
		case IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT:
			getDelayImport();
			break;
		case IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR:
			getCOMDescriptor();
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
	m_vecSecHeaders.clear();
	m_stExport.vecFuncs.clear();
	m_stExport.strModuleName.clear();
	m_vecImport.clear();
	m_stResource.vecResRoot.clear();
	m_vecException.clear();
	m_vecSecurity.clear();
	m_vecRelocs.clear();
	m_vecDebug.clear();
	m_stTLS.vecTLSRawData.clear();
	m_stTLS.vecTLSCallbacks.clear();
	m_vecBoundImport.clear();
	m_vecDelayImport.clear();
}

HRESULT Clibpe::getMSDOSHeader()
{
	m_pDosHeader = (PIMAGE_DOS_HEADER)m_lpBase;

	//If file has at least MSDOS header signature then we can assume, 
	//that this is a minimum correct PE file, and process further.
	if (m_pDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
		return E_IMAGE_HAS_NO_DOSHEADER;

	m_stMSDOSHeader = *m_pDosHeader;
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
	if (m_pDosHeader->e_lfanew <= 0x80 || !isPtrSafe((DWORD_PTR)m_pDosHeader + m_pDosHeader->e_lfanew))
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
				m_vecRichHeader.emplace_back(LIBPE_RICH { (DWORD_PTR)pRichIter - (DWORD_PTR)m_lpBase,
					HIWORD(dwRichXORMask ^ *pRichIter),
					LOWORD(dwRichXORMask ^ *pRichIter),
					dwRichXORMask ^ *(pRichIter + 1) });
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
		m_varNTHeader.stNTHdr32 = *m_pNTHeader32;
		m_stFileHeader = m_pNTHeader32->FileHeader;
		m_varOptHeader.stOptHdr32 = m_pNTHeader32->OptionalHeader;
		m_ullImageBase = m_pNTHeader32->OptionalHeader.ImageBase;
		break;
	case IMAGE_NT_OPTIONAL_HDR64_MAGIC:
		m_dwFileSummary |= IMAGE_FLAG_PE64;
		m_pNTHeader64 = (PIMAGE_NT_HEADERS64)pNTHeader;
		m_varNTHeader.stNTHdr64 = *m_pNTHeader64;
		m_stFileHeader = m_pNTHeader64->FileHeader;
		m_varOptHeader.stOptHdr64 = m_pNTHeader64->OptionalHeader;
		m_ullImageBase = m_pNTHeader64->OptionalHeader.ImageBase;
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

		m_vecDataDirectories.emplace_back(LIBPE_DATADIR { *pDataDir, std::move(strSecName) });
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
		dwSymbolTable = m_pNTHeader32->FileHeader.PointerToSymbolTable;
		dwNumberOfSymbols = m_pNTHeader32->FileHeader.NumberOfSymbols;
	}
	else if (ImageHasFlag(m_dwFileSummary, IMAGE_FLAG_PE64) && ImageHasFlag(m_dwFileSummary, IMAGE_FLAG_FILEHEADER))
	{
		pSecHdr = IMAGE_FIRST_SECTION(m_pNTHeader64);
		wNumSections = m_pNTHeader64->FileHeader.NumberOfSections;
		dwSymbolTable = m_pNTHeader64->FileHeader.PointerToSymbolTable;
		dwNumberOfSymbols = m_pNTHeader64->FileHeader.NumberOfSymbols;
	}
	else
		return E_IMAGE_HAS_NO_SECTIONS;

	m_vecSecHeaders.reserve(wNumSections);

	for (unsigned i = 0; i < wNumSections; i++, pSecHdr++)
	{
		if (!isPtrSafe((DWORD_PTR)pSecHdr + sizeof(IMAGE_SECTION_HEADER)))
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
			char* pEndPtr { };
			const long lOffset = strtol((const char*)&pSecHdr->Name[1], &pEndPtr, 10);
			if (!(lOffset == 0 && (pEndPtr == (const char*)&pSecHdr->Name[1] || *pEndPtr != '\0')))
			{
				const char* lpszSecRealName = (const char*)((DWORD_PTR)m_lpBase +
					DWORD_PTR(dwSymbolTable + dwNumberOfSymbols * 18 + lOffset));
				if (isPtrSafe(lpszSecRealName))
					strSecRealName = lpszSecRealName;
			}
		}

		m_vecSecHeaders.emplace_back(
			LIBPE_SECHEADERS { (DWORD_PTR)pSecHdr - (DWORD_PTR)m_lpBase, *pSecHdr, std::move(strSecRealName) });
	}

	if (m_vecSecHeaders.empty())
		return E_IMAGE_HAS_NO_SECTIONS;

	m_dwFileSummary |= IMAGE_FLAG_SECTIONS;

	return S_OK;
}

HRESULT Clibpe::getExport()
{
	const DWORD dwExportStartRVA = getDirEntryRVA(IMAGE_DIRECTORY_ENTRY_EXPORT);
	const DWORD dwExportEndRVA = dwExportStartRVA + getDirEntrySize(IMAGE_DIRECTORY_ENTRY_EXPORT);

	const PIMAGE_EXPORT_DIRECTORY pExportDir = (PIMAGE_EXPORT_DIRECTORY)rVAToPtr(dwExportStartRVA);
	if (!pExportDir)
		return E_IMAGE_HAS_NO_EXPORT;

	const PDWORD pFuncs = (PDWORD)rVAToPtr(pExportDir->AddressOfFunctions);
	if (!pFuncs)
		return E_IMAGE_HAS_NO_EXPORT;

	std::vector<LIBPE_EXPORT_FUNC> vecFuncs { };
	std::string strModuleName { };
	const PWORD pOrdinals = (PWORD)rVAToPtr(pExportDir->AddressOfNameOrdinals);
	LPCSTR* pszNames = (LPCSTR*)rVAToPtr(pExportDir->AddressOfNames);

	try {
		for (size_t iterFuncs = 0; iterFuncs < (size_t)pExportDir->NumberOfFunctions; iterFuncs++)
		{
			//Checking pFuncs array.
			if (!isPtrSafe(pFuncs + iterFuncs))
				break;

			if (pFuncs[iterFuncs]) //if RVA==0 —> going next entry.
			{
				std::string strFuncName, strForwarderName;
				if (pszNames && pOrdinals)
					for (size_t iterFuncNames = 0; iterFuncNames < (size_t)pExportDir->NumberOfNames; iterFuncNames++)
					{
						//Checking pOrdinals array.
						if (!isPtrSafe(pOrdinals + iterFuncNames))
							break;
						//Cycling through ordinals table to get func name.
						if (pOrdinals[iterFuncNames] == iterFuncs)
						{
							const LPCSTR pszFuncName = (LPCSTR)rVAToPtr((DWORD_PTR)pszNames[iterFuncNames]);
							//Checking func name for length correctness.
							if (pszFuncName && (StringCchLengthA(pszFuncName, MAX_PATH, nullptr) != STRSAFE_E_INVALID_PARAMETER))
								strFuncName = pszFuncName;
							break;
						}
					}
				if ((pFuncs[iterFuncs] >= dwExportStartRVA) && (pFuncs[iterFuncs] <= dwExportEndRVA))
				{
					const LPCSTR pszForwarderName = (LPCSTR)rVAToPtr(pFuncs[iterFuncs]);
					//Checking forwarder name for length correctness.
					if (pszForwarderName && (StringCchLengthA(pszForwarderName, MAX_PATH, nullptr) != STRSAFE_E_INVALID_PARAMETER))
						strForwarderName = pszForwarderName;
				}
				vecFuncs.emplace_back(LIBPE_EXPORT_FUNC { pFuncs[iterFuncs], iterFuncs, std::move(strFuncName), std::move(strForwarderName) });
			}
		}
		const LPCSTR szExportName = (LPCSTR)rVAToPtr(pExportDir->Name);
		//Checking Export name for length correctness.
		if (szExportName && (StringCchLengthA(szExportName, MAX_PATH, nullptr) != STRSAFE_E_INVALID_PARAMETER))
			strModuleName = szExportName;

		DWORD dwOffset;
		if (m_fMapViewOfFileWhole)
			dwOffset = (DWORD_PTR)pExportDir - (DWORD_PTR)m_lpBase;
		else
			dwOffset = (DWORD_PTR)pExportDir - (DWORD_PTR)m_lpSectionBase + m_dwFileOffsetToMap - m_dwDeltaFileOffsetToMap;

		m_stExport = { dwOffset, *pExportDir, std::move(strModuleName) /*Actual IMG name*/, std::move(vecFuncs) };
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

HRESULT Clibpe::getImport()
{
	PIMAGE_IMPORT_DESCRIPTOR pImpDesc = (PIMAGE_IMPORT_DESCRIPTOR)rVAToPtr(getDirEntryRVA(IMAGE_DIRECTORY_ENTRY_IMPORT));

	if (!pImpDesc)
		return E_IMAGE_HAS_NO_IMPORT;

	//Counter for import modules. If it exceeds iMaxModules we stop parsing file, it's definitely bogus.
	//Very unlikely PE file has more than 1000 imports.
	constexpr auto iMaxModules = 1000;
	constexpr auto iMaxFuncs = 5000;
	int iModulesCount = 0;

	try {
		if (ImageHasFlag(m_dwFileSummary, IMAGE_FLAG_PE32))
		{
			while (pImpDesc->Name)
			{
				PIMAGE_THUNK_DATA32 pThunk32 = (PIMAGE_THUNK_DATA32)(DWORD_PTR)pImpDesc->OriginalFirstThunk;
				if (!pThunk32)
					pThunk32 = (PIMAGE_THUNK_DATA32)(DWORD_PTR)pImpDesc->FirstThunk;

				if (pThunk32)
				{
					pThunk32 = (PIMAGE_THUNK_DATA32)rVAToPtr((DWORD_PTR)pThunk32);
					if (!pThunk32)
						break;

					std::vector<LIBPE_IMPORT_FUNC> vecFunc { };
					std::string strDllName { };
					//Counter for import module funcs. If it exceeds 5000 we stop parsing import descr, it's definitely bogus.
					int iFuncsCount = 0;

					while (pThunk32->u1.AddressOfData)
					{
						DWORD dwOffsetThunk;
						if (m_fMapViewOfFileWhole)
							dwOffsetThunk = (DWORD_PTR)pThunk32 - (DWORD_PTR)m_lpBase;
						else
							dwOffsetThunk = (DWORD_PTR)pThunk32 - (DWORD_PTR)m_lpSectionBase + m_dwFileOffsetToMap - m_dwDeltaFileOffsetToMap;

						if (pThunk32->u1.Ordinal & IMAGE_ORDINAL_FLAG32)
							//If funcs are imported only by ordinals then filling only ordinal leaving Name as "".
							vecFunc.emplace_back(LIBPE_IMPORT_FUNC { dwOffsetThunk, 0, IMAGE_ORDINAL32(pThunk32->u1.Ordinal), "", pThunk32->u1.AddressOfData });
						else
						{
							std::string strFuncName { };
							//Filling Hint, Name and Thunk RVA.
							const PIMAGE_IMPORT_BY_NAME pName = (PIMAGE_IMPORT_BY_NAME)rVAToPtr(pThunk32->u1.AddressOfData);
							DWORD dwOffsetFuncName { };
							if (pName && (StringCchLengthA(pName->Name, MAX_PATH, nullptr) != STRSAFE_E_INVALID_PARAMETER))
							{
								strFuncName = pName->Name;
								if (m_fMapViewOfFileWhole)
									dwOffsetFuncName = (DWORD_PTR)&pName->Name - (DWORD_PTR)m_lpBase;
								else
									dwOffsetFuncName = (DWORD_PTR)&pName->Name - (DWORD_PTR)m_lpSectionBase + m_dwFileOffsetToMap - m_dwDeltaFileOffsetToMap;
							}
							vecFunc.emplace_back(LIBPE_IMPORT_FUNC { dwOffsetThunk, dwOffsetFuncName,
								pName ? pName->Hint : (ULONGLONG)0, std::move(strFuncName), pThunk32->u1.AddressOfData });
						}
						if (!isPtrSafe(++pThunk32))
							break;
						if (++iFuncsCount == iMaxFuncs)
							break;
					}

					const LPCSTR szName = (LPCSTR)rVAToPtr(pImpDesc->Name);
					DWORD dwOffsetModuleName { };
					if (szName && (StringCchLengthA(szName, MAX_PATH, nullptr) != STRSAFE_E_INVALID_PARAMETER))
					{
						strDllName = szName;
						if (m_fMapViewOfFileWhole)
							dwOffsetModuleName = (DWORD_PTR)szName - (DWORD_PTR)m_lpBase;
						else
							dwOffsetModuleName = (DWORD_PTR)szName - (DWORD_PTR)m_lpSectionBase + m_dwFileOffsetToMap - m_dwDeltaFileOffsetToMap;
					}
					DWORD dwOffsetDescriptor;
					if (m_fMapViewOfFileWhole)
						dwOffsetDescriptor = (DWORD_PTR)pImpDesc - (DWORD_PTR)m_lpBase;
					else
						dwOffsetDescriptor = (DWORD_PTR)pImpDesc - (DWORD_PTR)m_lpSectionBase + m_dwFileOffsetToMap - m_dwDeltaFileOffsetToMap;

					m_vecImport.emplace_back(LIBPE_IMPORT_MODULE { dwOffsetDescriptor, dwOffsetModuleName, *pImpDesc, std::move(strDllName), std::move(vecFunc) });

					if (!isPtrSafe(++pImpDesc))
						break;
				}
				else //No IMPORT pointers for that DLL?...
					if (!isPtrSafe(++pImpDesc))  //Going next dll.
						break;

				if (++iModulesCount == iMaxModules)
					break;
			}
		}
		else if (ImageHasFlag(m_dwFileSummary, IMAGE_FLAG_PE64))
		{
			while (pImpDesc->Name)
			{
				PIMAGE_THUNK_DATA64 pThunk64 = (PIMAGE_THUNK_DATA64)(DWORD_PTR)pImpDesc->OriginalFirstThunk;
				if (!pThunk64)
					pThunk64 = (PIMAGE_THUNK_DATA64)(DWORD_PTR)pImpDesc->FirstThunk;

				if (pThunk64)
				{
					pThunk64 = (PIMAGE_THUNK_DATA64)rVAToPtr((DWORD_PTR)pThunk64);
					if (!pThunk64)
						return E_IMAGE_HAS_NO_IMPORT;

					std::vector<LIBPE_IMPORT_FUNC> vecFunc { };
					std::string strDllName { };
					int iFuncsCount = 0;

					while (pThunk64->u1.AddressOfData)
					{
						DWORD dwOffsetThunk;
						if (m_fMapViewOfFileWhole)
							dwOffsetThunk = (DWORD_PTR)pThunk64 - (DWORD_PTR)m_lpBase;
						else
							dwOffsetThunk = (DWORD_PTR)pThunk64 - (DWORD_PTR)m_lpSectionBase + m_dwFileOffsetToMap - m_dwDeltaFileOffsetToMap;

						if (pThunk64->u1.Ordinal & IMAGE_ORDINAL_FLAG64)
							//If funcs are imported only by ordinals then filling only ordinal leaving Name as "".
							vecFunc.emplace_back(LIBPE_IMPORT_FUNC { dwOffsetThunk, 0, IMAGE_ORDINAL64(pThunk64->u1.Ordinal), "", pThunk64->u1.AddressOfData });
						else
						{
							std::string strFuncName { };

							//Filling Hint, Name and Thunk RVA.
							const PIMAGE_IMPORT_BY_NAME pName = (PIMAGE_IMPORT_BY_NAME)rVAToPtr(pThunk64->u1.AddressOfData);
							DWORD dwOffsetFuncName { };
							if (pName && (StringCchLengthA(pName->Name, MAX_PATH, nullptr) != STRSAFE_E_INVALID_PARAMETER))
							{
								strFuncName = pName->Name;
								if (m_fMapViewOfFileWhole)
									dwOffsetFuncName = (DWORD_PTR)&pName->Name - (DWORD_PTR)m_lpBase;
								else
									dwOffsetFuncName = (DWORD_PTR)&pName->Name - (DWORD_PTR)m_lpSectionBase + m_dwFileOffsetToMap - m_dwDeltaFileOffsetToMap;
							}
							vecFunc.emplace_back(LIBPE_IMPORT_FUNC { dwOffsetThunk, dwOffsetFuncName,
								pName ? pName->Hint : (ULONGLONG)0, std::move(strFuncName), pThunk64->u1.AddressOfData });
						}
						pThunk64++;
						if (++iFuncsCount == iMaxFuncs)
							break;
					}

					const LPCSTR szName = (LPCSTR)rVAToPtr(pImpDesc->Name);
					DWORD dwOffsetModuleName { };
					if (szName && (StringCchLengthA(szName, MAX_PATH, nullptr) != STRSAFE_E_INVALID_PARAMETER))
					{
						strDllName = szName;
						if (m_fMapViewOfFileWhole)
							dwOffsetModuleName = (DWORD_PTR)szName - (DWORD_PTR)m_lpBase;
						else
							dwOffsetModuleName = (DWORD_PTR)szName - (DWORD_PTR)m_lpSectionBase + m_dwFileOffsetToMap - m_dwDeltaFileOffsetToMap;
					}
					DWORD dwOffsetDescriptor;
					if (m_fMapViewOfFileWhole)
						dwOffsetDescriptor = (DWORD_PTR)pImpDesc - (DWORD_PTR)m_lpBase;
					else
						dwOffsetDescriptor = (DWORD_PTR)pImpDesc - (DWORD_PTR)m_lpSectionBase + m_dwFileOffsetToMap - m_dwDeltaFileOffsetToMap;

					m_vecImport.emplace_back(LIBPE_IMPORT_MODULE { dwOffsetDescriptor, dwOffsetModuleName, *pImpDesc, std::move(strDllName), std::move(vecFunc) });

					if (!isPtrSafe(++pImpDesc))
						break;
				}
				else
					if (!isPtrSafe(++pImpDesc))
						break;

				if (++iModulesCount == iMaxModules)
					break;
			}
		}
	}
	catch (const std::bad_alloc&)
	{
		m_pEmergencyMemory.reset();
		MessageBox(nullptr, L"E_OUTOFMEMORY error while trying to get Import table.\r\n"
			L"Too many import entries!\nFile seems to be corrupted.", L"Error", MB_ICONERROR);

		m_vecImport.clear();
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

HRESULT Clibpe::getResources()
{
	PIMAGE_RESOURCE_DIRECTORY pRootResDir = (PIMAGE_RESOURCE_DIRECTORY)rVAToPtr(getDirEntryRVA(IMAGE_DIRECTORY_ENTRY_RESOURCE));
	if (!pRootResDir)
		return E_IMAGE_HAS_NO_RESOURCE;

	PIMAGE_RESOURCE_DIRECTORY_ENTRY pRootResDirEntry = (PIMAGE_RESOURCE_DIRECTORY_ENTRY)(pRootResDir + 1);
	if (!isPtrSafe(pRootResDirEntry))
		return E_IMAGE_HAS_NO_RESOURCE;

	PIMAGE_RESOURCE_DIR_STRING_U pResDirStr;

	try {
		std::vector<LIBPE_RESOURCE_ROOT_DATA> vecResRoot;
		DWORD dwNumOfEntriesLvL1 = pRootResDir->NumberOfNamedEntries + pRootResDir->NumberOfIdEntries;
		if (!isPtrSafe(pRootResDirEntry + dwNumOfEntriesLvL1))
			return E_IMAGE_HAS_NO_RESOURCE;

		vecResRoot.reserve(dwNumOfEntriesLvL1);
		for (unsigned iLvL1 = 0; iLvL1 < dwNumOfEntriesLvL1; iLvL1++)
		{
			PIMAGE_RESOURCE_DATA_ENTRY pRootResDataEntry { };
			std::wstring wstrResNameRoot { };
			std::vector<std::byte> vecResRawDataRoot { };
			LIBPE_RESOURCE_LVL2 stResLvL2 { };

			//Name of Resource Type (ICON, BITMAP, MENU, etc...).
			if (pRootResDirEntry->NameIsString)
			{
				if (isSumOverflow((DWORD_PTR)pRootResDir, (DWORD_PTR)pRootResDirEntry->NameOffset))
					break;
				pResDirStr = PIMAGE_RESOURCE_DIR_STRING_U((DWORD_PTR)pRootResDir + (DWORD_PTR)pRootResDirEntry->NameOffset);
				if (isPtrSafe(pResDirStr))
					//Copy not more then MAX_PATH chars into wstrResNameRoot, avoiding overflow.
					wstrResNameRoot.assign(pResDirStr->NameString, pResDirStr->Length < MAX_PATH ? pResDirStr->Length : MAX_PATH);
			}
			if (pRootResDirEntry->DataIsDirectory)
			{
				const PIMAGE_RESOURCE_DIRECTORY pSecondResDir = (PIMAGE_RESOURCE_DIRECTORY)((DWORD_PTR)pRootResDir + (DWORD_PTR)pRootResDirEntry->OffsetToDirectory);
				std::vector<LIBPE_RESOURCE_LVL2_DATA> vecResLvL2;

				if (!isPtrSafe(pSecondResDir))
					break;
				if (pSecondResDir == pRootResDir /*Resource loop hack*/)
					stResLvL2 = { *pSecondResDir, vecResLvL2 };
				else
				{
					PIMAGE_RESOURCE_DIRECTORY_ENTRY pSecondResDirEntry = (PIMAGE_RESOURCE_DIRECTORY_ENTRY)(pSecondResDir + 1);
					DWORD dwNumOfEntriesLvL2 = pSecondResDir->NumberOfNamedEntries + pSecondResDir->NumberOfIdEntries;
					if (!isPtrSafe(pSecondResDirEntry + dwNumOfEntriesLvL2))
						break;

					vecResLvL2.reserve(dwNumOfEntriesLvL2);
					for (unsigned iLvL2 = 0; iLvL2 < dwNumOfEntriesLvL2; iLvL2++)
					{
						PIMAGE_RESOURCE_DATA_ENTRY pSecondResDataEntry { };
						std::wstring wstrResNameLvL2 { };
						std::vector<std::byte> vecResRawDataLvL2 { };
						LIBPE_RESOURCE_LVL3 stResLvL3 { };

						//Name of resource itself if not presented by ID ("AFX_MY_SUPER_DIALOG"...).
						if (pSecondResDirEntry->NameIsString)
						{
							if (isSumOverflow((DWORD_PTR)pRootResDir, (DWORD_PTR)pSecondResDirEntry->NameOffset))
								break;
							pResDirStr = PIMAGE_RESOURCE_DIR_STRING_U((DWORD_PTR)pRootResDir + (DWORD_PTR)pSecondResDirEntry->NameOffset);
							if (isPtrSafe(pResDirStr))
								//Copy not more then MAX_PATH chars into wstrResNameLvL2, avoiding overflow.
								wstrResNameLvL2.assign(pResDirStr->NameString, pResDirStr->Length < MAX_PATH ? pResDirStr->Length : MAX_PATH);
						}

						if (pSecondResDirEntry->DataIsDirectory)
						{
							const PIMAGE_RESOURCE_DIRECTORY pThirdResDir = (PIMAGE_RESOURCE_DIRECTORY)((DWORD_PTR)pRootResDir + (DWORD_PTR)pSecondResDirEntry->OffsetToDirectory);
							std::vector<LIBPE_RESOURCE_LVL3_DATA> vecResLvL3;

							if (!isPtrSafe(pThirdResDir))
								break;
							if (pThirdResDir == pSecondResDir || pThirdResDir == pRootResDir)
								stResLvL3 = { *pThirdResDir, vecResLvL3 };
							else
							{
								PIMAGE_RESOURCE_DIRECTORY_ENTRY pThirdResDirEntry = (PIMAGE_RESOURCE_DIRECTORY_ENTRY)(pThirdResDir + 1);
								DWORD dwNumOfEntriesLvL3 = pThirdResDir->NumberOfNamedEntries + pThirdResDir->NumberOfIdEntries;
								if (!isPtrSafe(pThirdResDirEntry + dwNumOfEntriesLvL3))
									break;

								vecResLvL3.reserve(dwNumOfEntriesLvL3);
								for (unsigned iLvL3 = 0; iLvL3 < dwNumOfEntriesLvL3; iLvL3++)
								{
									std::wstring wstrResNameLvL3 { };
									std::vector<std::byte> vecResRawDataLvL3 { };

									if (pThirdResDirEntry->NameIsString)
									{
										if (isSumOverflow((DWORD_PTR)pRootResDir, (DWORD_PTR)pThirdResDirEntry->NameOffset))
											break;
										pResDirStr = PIMAGE_RESOURCE_DIR_STRING_U((DWORD_PTR)pRootResDir + (DWORD_PTR)pThirdResDirEntry->NameOffset);
										if (isPtrSafe(pResDirStr))
											//Copy not more then MAX_PATH chars into wstrResNameLvL2, avoiding overflow.
											wstrResNameLvL3.assign(pResDirStr->NameString, pResDirStr->Length < MAX_PATH ? pResDirStr->Length : MAX_PATH);
									}

									const PIMAGE_RESOURCE_DATA_ENTRY pThirdResDataEntry = (PIMAGE_RESOURCE_DATA_ENTRY)((DWORD_PTR)pRootResDir +
										(DWORD_PTR)pThirdResDirEntry->OffsetToData);
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
											vecResRawDataLvL3.reserve(pThirdResDataEntry->Size);
											for (size_t iterResRawData = 0; iterResRawData < (size_t)pThirdResDataEntry->Size; iterResRawData++)
												vecResRawDataLvL3.push_back(*(pThirdResRawDataBegin + iterResRawData));
										}
									}

									vecResLvL3.emplace_back(LIBPE_RESOURCE_LVL3_DATA { *pThirdResDirEntry, std::move(wstrResNameLvL3),
										isPtrSafe(pThirdResDataEntry) ? *pThirdResDataEntry : IMAGE_RESOURCE_DATA_ENTRY { },
										std::move(vecResRawDataLvL3) });

									if (!isPtrSafe(++pThirdResDirEntry))
										break;
								}
								stResLvL3 = { *pThirdResDir, std::move(vecResLvL3) };
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
									vecResRawDataLvL2.reserve(pSecondResDataEntry->Size);
									for (size_t iterResRawData = 0; iterResRawData < (size_t)pSecondResDataEntry->Size; iterResRawData++)
										vecResRawDataLvL2.push_back(*(pSecondResRawDataBegin + iterResRawData));
								}
							}
						}
						vecResLvL2.emplace_back(LIBPE_RESOURCE_LVL2_DATA { *pSecondResDirEntry, std::move(wstrResNameLvL2),
							isPtrSafe(pSecondResDataEntry) ? *pSecondResDataEntry : IMAGE_RESOURCE_DATA_ENTRY { },
							std::move(vecResRawDataLvL2), stResLvL3 });

						if (!isPtrSafe(++pSecondResDirEntry))
							break;
					}
					stResLvL2 = { *pSecondResDir, std::move(vecResLvL2) };
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
						vecResRawDataRoot.reserve(pRootResDataEntry->Size);
						for (size_t iterResRawData = 0; iterResRawData < (size_t)pRootResDataEntry->Size; iterResRawData++)
							vecResRawDataRoot.push_back(*(pRootResRawDataBegin + iterResRawData));
					}
				}
			}
			vecResRoot.emplace_back(LIBPE_RESOURCE_ROOT_DATA { *pRootResDirEntry, std::move(wstrResNameRoot),
				isPtrSafe(pRootResDataEntry) ? *pRootResDataEntry : IMAGE_RESOURCE_DATA_ENTRY { },
				std::move(vecResRawDataRoot), stResLvL2 });

			if (!isPtrSafe(++pRootResDirEntry))
				break;
		}
		m_stResource = { *pRootResDir, std::move(vecResRoot) };
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

HRESULT Clibpe::getExceptions()
{
	//IMAGE_RUNTIME_FUNCTION_ENTRY (without leading underscore) 
	//might have different typedef depending on defined platform, see winnt.h
	_PIMAGE_RUNTIME_FUNCTION_ENTRY pRuntimeFuncsEntry = (_PIMAGE_RUNTIME_FUNCTION_ENTRY)rVAToPtr(getDirEntryRVA(IMAGE_DIRECTORY_ENTRY_EXCEPTION));
	if (!pRuntimeFuncsEntry)
		return E_IMAGE_HAS_NO_EXCEPTION;

	const DWORD dwEntries = getDirEntrySize(IMAGE_DIRECTORY_ENTRY_EXCEPTION) / (DWORD)sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY);
	if (!dwEntries || !isPtrSafe((DWORD_PTR)pRuntimeFuncsEntry + (DWORD_PTR)dwEntries))
		return E_IMAGE_HAS_NO_EXCEPTION;

	for (unsigned i = 0; i < dwEntries; i++, pRuntimeFuncsEntry++)
	{
		if (!isPtrSafe(pRuntimeFuncsEntry))
			break;

		DWORD dwOffset;
		if (m_fMapViewOfFileWhole)
			dwOffset = (DWORD_PTR)pRuntimeFuncsEntry - (DWORD_PTR)m_lpBase;
		else
			dwOffset = (DWORD_PTR)pRuntimeFuncsEntry - (DWORD_PTR)m_lpSectionBase + m_dwFileOffsetToMap - m_dwDeltaFileOffsetToMap;

		m_vecException.emplace_back(LIBPE_EXCEPTION { dwOffset, *pRuntimeFuncsEntry });
	}

	m_dwFileSummary |= IMAGE_FLAG_EXCEPTION;

	return S_OK;
}

HRESULT Clibpe::getSecurity()
{
	const DWORD dwSecurityDirOffset = getDirEntryRVA(IMAGE_DIRECTORY_ENTRY_SECURITY);
	const DWORD dwSecurityDirSize = getDirEntrySize(IMAGE_DIRECTORY_ENTRY_SECURITY);

	if (!dwSecurityDirOffset || !dwSecurityDirSize)
		return E_IMAGE_HAS_NO_SECURITY;

	DWORD_PTR dwSecurityDirStartVA;

	//Checks for bogus file offsets that can cause DWORD_PTR overflow.
	if (m_fMapViewOfFileWhole)
	{
		if (isSumOverflow((DWORD_PTR)dwSecurityDirOffset, (DWORD_PTR)m_lpBase))
			return E_IMAGE_HAS_NO_SECURITY;

		dwSecurityDirStartVA = (DWORD_PTR)m_lpBase + (DWORD_PTR)dwSecurityDirOffset;
	}
	else
	{
		if (isSumOverflow((DWORD_PTR)dwSecurityDirOffset, (DWORD_PTR)m_lpSectionBase))
			return E_IMAGE_HAS_NO_SECURITY;

		dwSecurityDirStartVA = (DWORD_PTR)m_lpSectionBase + (DWORD_PTR)m_dwDeltaFileOffsetToMap;
	}

	if (isSumOverflow((DWORD_PTR)dwSecurityDirStartVA, (DWORD_PTR)dwSecurityDirSize))
		return E_IMAGE_HAS_NO_SECURITY;

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

		DWORD dwOffset;
		if (m_fMapViewOfFileWhole)
			dwOffset = (DWORD_PTR)pCertificate - (DWORD_PTR)m_lpBase;
		else
			dwOffset = (DWORD_PTR)pCertificate - (DWORD_PTR)m_lpSectionBase + m_dwFileOffsetToMap - m_dwDeltaFileOffsetToMap;

		m_vecSecurity.emplace_back(LIBPE_SECURITY { dwOffset, *pCertificate, std::move(vecCertBytes) });

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

HRESULT Clibpe::getRelocations()
{
	PIMAGE_BASE_RELOCATION pBaseRelocDesc = (PIMAGE_BASE_RELOCATION)rVAToPtr(getDirEntryRVA(IMAGE_DIRECTORY_ENTRY_BASERELOC));

	if (!pBaseRelocDesc)
		return E_IMAGE_HAS_NO_BASERELOC;

	DWORD dwOffset;

	try
	{
		if (!pBaseRelocDesc->SizeOfBlock || !pBaseRelocDesc->VirtualAddress)
		{
			if (m_fMapViewOfFileWhole)
				dwOffset = (DWORD_PTR)pBaseRelocDesc - (DWORD_PTR)m_lpBase;
			else
				dwOffset = (DWORD_PTR)pBaseRelocDesc - (DWORD_PTR)m_lpSectionBase + m_dwFileOffsetToMap - m_dwDeltaFileOffsetToMap;

			m_vecRelocs.emplace_back(LIBPE_RELOCATION { dwOffset, *pBaseRelocDesc, { } });
		}
		while ((pBaseRelocDesc->SizeOfBlock) && (pBaseRelocDesc->VirtualAddress))
		{
			if (pBaseRelocDesc->SizeOfBlock < sizeof(IMAGE_BASE_RELOCATION))
			{
				if (m_fMapViewOfFileWhole)
					dwOffset = (DWORD_PTR)pBaseRelocDesc - (DWORD_PTR)m_lpBase;
				else
					dwOffset = (DWORD_PTR)pBaseRelocDesc - (DWORD_PTR)m_lpSectionBase + m_dwFileOffsetToMap - m_dwDeltaFileOffsetToMap;

				m_vecRelocs.emplace_back(LIBPE_RELOCATION { dwOffset, *pBaseRelocDesc, { } });
				break;
			}

			//Amount of Reloc entries.
			DWORD dwNumRelocEntries = (pBaseRelocDesc->SizeOfBlock - (DWORD)sizeof(IMAGE_BASE_RELOCATION)) / (DWORD)sizeof(WORD);
			PWORD pwRelocEntry = PWORD((DWORD_PTR)pBaseRelocDesc + sizeof(IMAGE_BASE_RELOCATION));
			WORD wRelocType { };
			std::vector<LIBPE_RELOC_DATA> vecRelocs;

			for (DWORD i = 0; i < dwNumRelocEntries; i++, pwRelocEntry++)
			{
				if (!isPtrSafe(pwRelocEntry))
					break;
				//Getting HIGH 4 bits of reloc's entry WORD —> reloc type.
				wRelocType = (*pwRelocEntry & 0xF000) >> 12;

				DWORD dwOffsetRelEntry { };
				if (m_fMapViewOfFileWhole)
					dwOffsetRelEntry = (DWORD_PTR)pwRelocEntry - (DWORD_PTR)m_lpBase;
				else
					dwOffsetRelEntry = (DWORD_PTR)pwRelocEntry - (DWORD_PTR)m_lpSectionBase + m_dwFileOffsetToMap - m_dwDeltaFileOffsetToMap;

				vecRelocs.emplace_back(LIBPE_RELOC_DATA { dwOffsetRelEntry, wRelocType, (WORD)((*pwRelocEntry) & 0x0fff)/*Low 12 bits —> Offset*/ });
				if (wRelocType == IMAGE_REL_BASED_HIGHADJ)
				{	//The base relocation adds the high 16 bits of the difference to the 16-bit field at offset.
					//The 16-bit field represents the high value of a 32-bit word. 
					//The low 16 bits of the 32-bit value are stored in the 16-bit word that follows this base relocation.
					//This means that this base relocation occupies two slots. (MSDN)
					if (!isPtrSafe(++pwRelocEntry))
					{
						vecRelocs.clear();
						break;
					}

					DWORD dwOffsetRelEntry { };
					if (m_fMapViewOfFileWhole)
						dwOffsetRelEntry = (DWORD_PTR)pwRelocEntry - (DWORD_PTR)m_lpBase;
					else
						dwOffsetRelEntry = (DWORD_PTR)pwRelocEntry - (DWORD_PTR)m_lpSectionBase + m_dwFileOffsetToMap - m_dwDeltaFileOffsetToMap;

					vecRelocs.emplace_back(LIBPE_RELOC_DATA { dwOffsetRelEntry, wRelocType, *pwRelocEntry /*The low 16-bit field.*/ });
					dwNumRelocEntries--; //to compensate pwRelocEntry++.
				}
			}

			if (m_fMapViewOfFileWhole)
				dwOffset = (DWORD_PTR)pBaseRelocDesc - (DWORD_PTR)m_lpBase;
			else
				dwOffset = (DWORD_PTR)pBaseRelocDesc - (DWORD_PTR)m_lpSectionBase + m_dwFileOffsetToMap - m_dwDeltaFileOffsetToMap;

			m_vecRelocs.emplace_back(LIBPE_RELOCATION { dwOffset, *pBaseRelocDesc, std::move(vecRelocs) });

			//Too big (bogus) SizeOfBlock may cause DWORD_PTR overflow. Checking to prevent.
			if (isSumOverflow((DWORD_PTR)pBaseRelocDesc, (DWORD_PTR)pBaseRelocDesc->SizeOfBlock))
				break;

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

HRESULT Clibpe::getDebug()
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

	if (!dwDebugEntries || isSumOverflow((DWORD_PTR)pDebugDir, (DWORD_PTR)dwDebugDirSize) ||
		!isPtrSafe((DWORD_PTR)pDebugDir + (DWORD_PTR)dwDebugDirSize))
		return E_IMAGE_HAS_NO_DEBUG;

	try {

		for (unsigned i = 0; i < dwDebugEntries; i++)
		{
			std::vector<std::byte> vecDebugRawData { };
			std::byte* pDebugRawData { };

			if (m_fMapViewOfFileWhole)
				pDebugRawData = (std::byte*)((DWORD_PTR)m_lpBase + (DWORD_PTR)pDebugDir->PointerToRawData);
			else
				pDebugRawData = (std::byte*)((DWORD_PTR)m_lpSectionBase +
				(DWORD_PTR)(pDebugDir->PointerToRawData - pDebugSecHdr->PointerToRawData));

			if (isPtrSafe(pDebugRawData) && isPtrSafe((DWORD_PTR)pDebugRawData + (DWORD_PTR)pDebugDir->SizeOfData))
			{
				vecDebugRawData.reserve(pDebugDir->SizeOfData);
				for (size_t iterRawData = 0; iterRawData < (size_t)pDebugDir->SizeOfData; iterRawData++)
					vecDebugRawData.push_back(*(pDebugRawData + iterRawData));
			}

			DWORD dwOffset;
			if (m_fMapViewOfFileWhole)
				dwOffset = (DWORD_PTR)pDebugDir - (DWORD_PTR)m_lpBase;
			else
				dwOffset = (DWORD_PTR)pDebugDir - (DWORD_PTR)m_lpSectionBase + m_dwFileOffsetToMap - m_dwDeltaFileOffsetToMap;

			m_vecDebug.emplace_back(LIBPE_DEBUG { dwOffset, *pDebugDir, std::move(vecDebugRawData) });
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

HRESULT Clibpe::getArchitecture()
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

HRESULT Clibpe::getGlobalPtr()
{
	const DWORD_PTR dwGlobalPTRDirRVA = (DWORD_PTR)rVAToPtr(getDirEntryRVA(IMAGE_DIRECTORY_ENTRY_GLOBALPTR));
	if (!dwGlobalPTRDirRVA)
		return E_IMAGE_HAS_NO_GLOBALPTR;

	m_dwFileSummary |= IMAGE_FLAG_GLOBALPTR;

	return S_OK;
}

HRESULT Clibpe::getTLS()
{
	const DWORD dwTLSDirRVA = getDirEntryRVA(IMAGE_DIRECTORY_ENTRY_TLS);
	if (!dwTLSDirRVA)
		return E_IMAGE_HAS_NO_TLS;

	try {
		std::vector<std::byte> vecTLSRawData;
		std::vector<DWORD> vecTLSCallbacks;
		ULONGLONG ulStartAddressOfRawData { }, ulEndAddressOfRawData { }, ulAddressOfCallBacks { };
		LIBPE_TLS_VAR varTLSDir;
		DWORD_PTR dwTLSPtr;

		if (ImageHasFlag(m_dwFileSummary, IMAGE_FLAG_PE32))
		{
			const PIMAGE_TLS_DIRECTORY32 pTLSDir32 = (PIMAGE_TLS_DIRECTORY32)rVAToPtr(dwTLSDirRVA);
			if (!pTLSDir32)
				return E_IMAGE_HAS_NO_TLS;

			varTLSDir.stTLSDir32 = *pTLSDir32;
			dwTLSPtr = (DWORD_PTR)pTLSDir32;
			ulStartAddressOfRawData = pTLSDir32->StartAddressOfRawData;
			ulEndAddressOfRawData = pTLSDir32->EndAddressOfRawData;
			ulAddressOfCallBacks = pTLSDir32->AddressOfCallBacks;
		}
		else if (ImageHasFlag(m_dwFileSummary, IMAGE_FLAG_PE64))
		{
			const PIMAGE_TLS_DIRECTORY64 pTLSDir64 = (PIMAGE_TLS_DIRECTORY64)rVAToPtr(dwTLSDirRVA);
			if (!pTLSDir64)
				return E_IMAGE_HAS_NO_TLS;

			varTLSDir.stTLSDir64 = *pTLSDir64;
			dwTLSPtr = (DWORD_PTR)pTLSDir64;
			ulStartAddressOfRawData = pTLSDir64->StartAddressOfRawData;
			ulEndAddressOfRawData = pTLSDir64->EndAddressOfRawData;
			ulAddressOfCallBacks = pTLSDir64->AddressOfCallBacks;
		}
		else
			return E_IMAGE_HAS_NO_TLS;

		//All TLS adresses are not RVA, but actual VA.
		//So we must subtract ImageBase before pass to rVAToPtr().
		std::byte* pTLSRawStart = (std::byte*)rVAToPtr(ulStartAddressOfRawData - m_ullImageBase);
		std::byte* pTLSRawEnd = (std::byte*)rVAToPtr(ulEndAddressOfRawData - m_ullImageBase);
		if (pTLSRawStart && pTLSRawEnd && pTLSRawEnd > pTLSRawStart)
		{
			DWORD_PTR dwTLSRawSize = pTLSRawEnd - pTLSRawStart;
			if (!isPtrSafe((DWORD_PTR)pTLSRawStart + dwTLSRawSize))
				return E_IMAGE_HAS_NO_TLS;

			vecTLSRawData.reserve(dwTLSRawSize);
			for (size_t iterTLS = 0; iterTLS < dwTLSRawSize; iterTLS++)
				vecTLSRawData.push_back(*(pTLSRawStart + iterTLS));

		}
		PDWORD pTLSCallbacks = (PDWORD)rVAToPtr(ulAddressOfCallBacks - m_ullImageBase);
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

		DWORD dwOffset;
		if (m_fMapViewOfFileWhole)
			dwOffset = (DWORD_PTR)dwTLSPtr - (DWORD_PTR)m_lpBase;
		else
			dwOffset = (DWORD_PTR)dwTLSPtr - (DWORD_PTR)m_lpSectionBase + m_dwFileOffsetToMap - m_dwDeltaFileOffsetToMap;

		m_stTLS = LIBPE_TLS { dwOffset, varTLSDir, std::move(vecTLSRawData), std::move(vecTLSCallbacks) };
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

HRESULT Clibpe::getLCD()
{
	if (ImageHasFlag(m_dwFileSummary, IMAGE_FLAG_PE32))
	{
		const PIMAGE_LOAD_CONFIG_DIRECTORY32 pLCD32 =
			(PIMAGE_LOAD_CONFIG_DIRECTORY32)rVAToPtr(getDirEntryRVA(IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG));
		if (!pLCD32 || !isPtrSafe((DWORD_PTR)pLCD32 + sizeof(IMAGE_LOAD_CONFIG_DIRECTORY32)))
			return E_IMAGE_HAS_NO_LOADCONFIG;

		DWORD dwOffset;
		if (m_fMapViewOfFileWhole)
			dwOffset = (DWORD_PTR)pLCD32 - (DWORD_PTR)m_lpBase;
		else
			dwOffset = (DWORD_PTR)pLCD32 - (DWORD_PTR)m_lpSectionBase + m_dwFileOffsetToMap - m_dwDeltaFileOffsetToMap;

		m_stLCD.dwOffset = dwOffset;
		m_stLCD.varLCD.stLCD32 = *pLCD32;
	}
	else if (ImageHasFlag(m_dwFileSummary, IMAGE_FLAG_PE64))
	{
		const PIMAGE_LOAD_CONFIG_DIRECTORY64 pLCD64 =
			(PIMAGE_LOAD_CONFIG_DIRECTORY64)rVAToPtr(getDirEntryRVA(IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG));
		if (!pLCD64 || !isPtrSafe((DWORD_PTR)pLCD64 + sizeof(PIMAGE_LOAD_CONFIG_DIRECTORY64)))
			return E_IMAGE_HAS_NO_LOADCONFIG;

		DWORD dwOffset;
		if (m_fMapViewOfFileWhole)
			dwOffset = (DWORD_PTR)pLCD64 - (DWORD_PTR)m_lpBase;
		else
			dwOffset = (DWORD_PTR)pLCD64 - (DWORD_PTR)m_lpSectionBase + m_dwFileOffsetToMap - m_dwDeltaFileOffsetToMap;

		m_stLCD.dwOffset = dwOffset;
		m_stLCD.varLCD.stLCD64 = *pLCD64;
	}
	else
		return E_IMAGE_HAS_NO_LOADCONFIG;

	m_dwFileSummary |= IMAGE_FLAG_LOADCONFIG;

	return S_OK;
}

HRESULT Clibpe::getBoundImport()
{
	PIMAGE_BOUND_IMPORT_DESCRIPTOR pBoundImpDesc =
		(PIMAGE_BOUND_IMPORT_DESCRIPTOR)rVAToPtr(getDirEntryRVA(IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT));

	if (!pBoundImpDesc)
		return E_IMAGE_HAS_NO_BOUNDIMPORT;

	while (pBoundImpDesc->TimeDateStamp)
	{
		std::string strModuleName;
		std::vector<LIBPE_BOUNDFORWARDER> vecBoundForwarders;

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

			DWORD dwOffset;
			if (m_fMapViewOfFileWhole)
				dwOffset = (DWORD_PTR)pBoundImpForwarder - (DWORD_PTR)m_lpBase;
			else
				dwOffset = (DWORD_PTR)pBoundImpForwarder - (DWORD_PTR)m_lpSectionBase + m_dwFileOffsetToMap - m_dwDeltaFileOffsetToMap;

			vecBoundForwarders.emplace_back(LIBPE_BOUNDFORWARDER { dwOffset, *pBoundImpForwarder, std::move(strForwarderModuleName) });

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

		DWORD dwOffset;
		if (m_fMapViewOfFileWhole)
			dwOffset = (DWORD_PTR)pBoundImpDesc - (DWORD_PTR)m_lpBase;
		else
			dwOffset = (DWORD_PTR)pBoundImpDesc - (DWORD_PTR)m_lpSectionBase + m_dwFileOffsetToMap - m_dwDeltaFileOffsetToMap;

		m_vecBoundImport.emplace_back(LIBPE_BOUNDIMPORT { dwOffset, *pBoundImpDesc, std::move(strModuleName), std::move(vecBoundForwarders) });

		if (!isPtrSafe(++pBoundImpDesc))
			break;
	}

	m_dwFileSummary |= IMAGE_FLAG_BOUNDIMPORT;

	return S_OK;
}

HRESULT Clibpe::getIAT()
{
	const DWORD_PTR dwIATDirRVA = (DWORD_PTR)rVAToPtr(getDirEntryRVA(IMAGE_DIRECTORY_ENTRY_IAT));
	if (!dwIATDirRVA)
		return E_IMAGE_HAS_NO_IAT;

	m_dwFileSummary |= IMAGE_FLAG_IAT;

	return S_OK;
}

HRESULT Clibpe::getDelayImport()
{
	PIMAGE_DELAYLOAD_DESCRIPTOR pDelayImpDescr = (PIMAGE_DELAYLOAD_DESCRIPTOR)rVAToPtr(getDirEntryRVA(IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT));
	if (!pDelayImpDescr)
		return E_IMAGE_HAS_NO_DELAYIMPORT;

	if (ImageHasFlag(m_dwFileSummary, IMAGE_FLAG_PE32))
	{
		while (pDelayImpDescr->DllNameRVA)
		{
			PIMAGE_THUNK_DATA32 pThunk32Name = (PIMAGE_THUNK_DATA32)(DWORD_PTR)pDelayImpDescr->ImportNameTableRVA;

			if (!pThunk32Name) {
				if (!isPtrSafe(++pDelayImpDescr))
					break;
			}
			else
			{
				std::string strDllName;
				std::vector<LIBPE_DELAYIMPORT_FUNC> vecFunc;

				pThunk32Name = (PIMAGE_THUNK_DATA32)rVAToPtr((DWORD_PTR)pThunk32Name);
				PIMAGE_THUNK_DATA32 pThunk32IAT = (PIMAGE_THUNK_DATA32)rVAToPtr(pDelayImpDescr->ImportAddressTableRVA);
				PIMAGE_THUNK_DATA32 pThunk32BoundIAT = (PIMAGE_THUNK_DATA32)rVAToPtr(
					pDelayImpDescr->BoundImportAddressTableRVA);
				PIMAGE_THUNK_DATA32 pThunk32UnloadInfoIAT = (PIMAGE_THUNK_DATA32)rVAToPtr(
					pDelayImpDescr->UnloadInformationTableRVA);

				if (!pThunk32Name)
					break;

				while (pThunk32Name->u1.AddressOfData)
				{
					if (pThunk32Name->u1.Ordinal & IMAGE_ORDINAL_FLAG32)
						vecFunc.emplace_back(LIBPE_DELAYIMPORT_FUNC { IMAGE_ORDINAL32(pThunk32Name->u1.Ordinal), "",
							pThunk32Name->u1.AddressOfData,
							pThunk32IAT ? pThunk32IAT->u1.AddressOfData : 0,
							pThunk32BoundIAT ? pThunk32BoundIAT->u1.AddressOfData : 0,
							pThunk32UnloadInfoIAT ? pThunk32UnloadInfoIAT->u1.AddressOfData : 0 });
					else {
						std::string strFuncName { };
						//Filling Hint, Name and Thunk RVA.
						const PIMAGE_IMPORT_BY_NAME pName = (PIMAGE_IMPORT_BY_NAME)rVAToPtr(pThunk32Name->u1.AddressOfData);
						if (pName && (StringCchLengthA(pName->Name, MAX_PATH, nullptr) != STRSAFE_E_INVALID_PARAMETER))
							strFuncName = pName->Name;

						vecFunc.emplace_back(LIBPE_DELAYIMPORT_FUNC { pName ? pName->Hint : (ULONGLONG)0, std::move(strFuncName),
							pThunk32Name->u1.AddressOfData,
							pThunk32IAT ? pThunk32IAT->u1.AddressOfData : (ULONGLONG)0,
							pThunk32BoundIAT ? pThunk32BoundIAT->u1.AddressOfData : (ULONGLONG)0,
							pThunk32UnloadInfoIAT ? pThunk32UnloadInfoIAT->u1.AddressOfData : (ULONGLONG)0 });
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

				const LPCSTR szName = (LPCSTR)rVAToPtr(pDelayImpDescr->DllNameRVA);
				if (szName && (StringCchLengthA(szName, MAX_PATH, nullptr) != STRSAFE_E_INVALID_PARAMETER))
					strDllName = szName;

				DWORD dwOffset;
				if (m_fMapViewOfFileWhole)
					dwOffset = (DWORD_PTR)pDelayImpDescr - (DWORD_PTR)m_lpBase;
				else
					dwOffset = (DWORD_PTR)pDelayImpDescr - (DWORD_PTR)m_lpSectionBase + m_dwFileOffsetToMap - m_dwDeltaFileOffsetToMap;

				m_vecDelayImport.emplace_back(LIBPE_DELAYIMPORT { dwOffset, *pDelayImpDescr, std::move(strDllName), std::move(vecFunc) });

				if (!isPtrSafe(++pDelayImpDescr))
					break;
			}
		}
	}
	else if (ImageHasFlag(m_dwFileSummary, IMAGE_FLAG_PE64))
	{
		while (pDelayImpDescr->DllNameRVA)
		{
			PIMAGE_THUNK_DATA64 pThunk64Name = (PIMAGE_THUNK_DATA64)(DWORD_PTR)pDelayImpDescr->ImportNameTableRVA;

			if (!pThunk64Name) {
				if (!isPtrSafe(++pDelayImpDescr))
					break;
			}
			else
			{
				std::string strDllName;
				std::vector<LIBPE_DELAYIMPORT_FUNC> vecFunc;

				pThunk64Name = (PIMAGE_THUNK_DATA64)rVAToPtr((DWORD_PTR)pThunk64Name);
				PIMAGE_THUNK_DATA64 pThunk64IAT = (PIMAGE_THUNK_DATA64)rVAToPtr(pDelayImpDescr->ImportAddressTableRVA);
				PIMAGE_THUNK_DATA64 pThunk64BoundIAT = (PIMAGE_THUNK_DATA64)rVAToPtr(
					pDelayImpDescr->BoundImportAddressTableRVA);
				PIMAGE_THUNK_DATA64 pThunk64UnloadInfoIAT = (PIMAGE_THUNK_DATA64)rVAToPtr(
					pDelayImpDescr->UnloadInformationTableRVA);

				if (!pThunk64Name)
					break;

				while (pThunk64Name->u1.AddressOfData)
				{
					if (pThunk64Name->u1.Ordinal & IMAGE_ORDINAL_FLAG64)
						vecFunc.emplace_back(LIBPE_DELAYIMPORT_FUNC { IMAGE_ORDINAL64(pThunk64Name->u1.Ordinal), "",
							pThunk64Name->u1.AddressOfData,
							pThunk64IAT ? pThunk64IAT->u1.AddressOfData : 0,
							pThunk64BoundIAT ? pThunk64BoundIAT->u1.AddressOfData : 0,
							pThunk64UnloadInfoIAT ? pThunk64UnloadInfoIAT->u1.AddressOfData : 0 });
					else
					{
						std::string strFuncName { };

						//Filling Hint, Name and Thunk RVA.
						const PIMAGE_IMPORT_BY_NAME pName = (PIMAGE_IMPORT_BY_NAME)rVAToPtr(pThunk64Name->u1.AddressOfData);
						if (pName && (StringCchLengthA(pName->Name, MAX_PATH, nullptr) != STRSAFE_E_INVALID_PARAMETER))
							strFuncName = pName->Name;

						vecFunc.emplace_back(LIBPE_DELAYIMPORT_FUNC { pName ? pName->Hint : (ULONGLONG)0, std::move(strFuncName),
							pThunk64Name->u1.AddressOfData,
							pThunk64IAT ? pThunk64IAT->u1.AddressOfData : (ULONGLONG)0,
							pThunk64BoundIAT ? pThunk64BoundIAT->u1.AddressOfData : (ULONGLONG)0,
							pThunk64UnloadInfoIAT ? pThunk64UnloadInfoIAT->u1.AddressOfData : (ULONGLONG)0 });
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

				const LPCSTR szName = (LPCSTR)rVAToPtr(pDelayImpDescr->DllNameRVA);
				if (szName && (StringCchLengthA(szName, MAX_PATH, nullptr) != STRSAFE_E_INVALID_PARAMETER))
					strDllName = szName;

				DWORD dwOffset;
				if (m_fMapViewOfFileWhole)
					dwOffset = (DWORD_PTR)pDelayImpDescr - (DWORD_PTR)m_lpBase;
				else
					dwOffset = (DWORD_PTR)pDelayImpDescr - (DWORD_PTR)m_lpSectionBase + m_dwFileOffsetToMap - m_dwDeltaFileOffsetToMap;

				m_vecDelayImport.emplace_back(LIBPE_DELAYIMPORT { dwOffset, *pDelayImpDescr, std::move(strDllName), std::move(vecFunc) });

				if (!isPtrSafe(++pDelayImpDescr))
					break;
			}
		}
	}
	m_dwFileSummary |= IMAGE_FLAG_DELAYIMPORT;

	return S_OK;
}

HRESULT Clibpe::getCOMDescriptor()
{
	const PIMAGE_COR20_HEADER pCOMDescHeader = (PIMAGE_COR20_HEADER)rVAToPtr(getDirEntryRVA(IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR));
	if (!pCOMDescHeader)
		return E_IMAGE_HAS_NO_COMDESCRIPTOR;

	DWORD dwOffset;
	if (m_fMapViewOfFileWhole)
		dwOffset = (DWORD_PTR)pCOMDescHeader - (DWORD_PTR)m_lpBase;
	else
		dwOffset = (DWORD_PTR)pCOMDescHeader - (DWORD_PTR)m_lpSectionBase + m_dwFileOffsetToMap - m_dwDeltaFileOffsetToMap;

	m_stCOR20Desc = { dwOffset, *pCOMDescHeader };
	m_dwFileSummary |= IMAGE_FLAG_COMDESCRIPTOR;

	return S_OK;
}