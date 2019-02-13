/****************************************************************************************
* Copyright (C) 2018-2019, Jovibor: https://github.com/jovibor/			 				*
* PE viewer library for x86 (PE32) and x64 (PE32+) binares.			 					*
* This software is available under the MIT License modified with The Commons Clause.	*
* Additional info can be found at https://github.com/jovibor/libpe	 					*
****************************************************************************************/
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

	m_hFile = CreateFileW(lpszFileName, GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
	if (m_hFile == INVALID_HANDLE_VALUE)
		return E_FILE_OPEN_FAILED;

	::GetFileSizeEx(m_hFile, &m_stFileSize);
	if (m_stFileSize.QuadPart < sizeof(IMAGE_DOS_HEADER))
	{
		CloseHandle(m_hFile);
		return E_FILE_SIZE_TOO_SMALL;
	}

	m_hMapObject = CreateFileMappingW(m_hFile, nullptr, PAGE_READONLY, 0, 0, nullptr);
	if (!m_hMapObject)
	{
		CloseHandle(m_hFile);
		return E_FILE_CREATEFILEMAPPING_FAILED;
	}

	m_lpBase = MapViewOfFile(m_hMapObject, FILE_MAP_READ, 0, 0, 0);
	if (m_lpBase)
	{
		m_fMapViewOfFileWhole = true;
		m_ullMaxPointerBound = (DWORD_PTR)m_lpBase + m_stFileSize.QuadPart;
	}
	else //Not enough memory? File is too big?
	{
		if (GetLastError() == ERROR_NOT_ENOUGH_MEMORY)
		{
			//If file is too big to fit process VirtualSize limit
			//we try to allocate at least some memory to map file's beginning, where PE HEADER resides.
			//Then going to MapViewOfFile/Unmap every section individually. 
			if (!(m_lpBase = MapViewOfFile(m_hMapObject, FILE_MAP_READ, 0, 0, (DWORD_PTR)m_dwMinBytesToMap)))
			{
				CloseHandle(m_hMapObject);
				CloseHandle(m_hFile);
				return E_FILE_MAPVIEWOFFILE_FAILED;
			}
			m_fMapViewOfFileWhole = false;
			m_ullMaxPointerBound = (DWORD_PTR)m_lpBase + (DWORD_PTR)m_dwMinBytesToMap;
			::GetNativeSystemInfo(&m_stSysInfo);
		}
		else
		{
			CloseHandle(m_hMapObject);
			CloseHandle(m_hFile);
			return E_FILE_MAPVIEWOFFILE_FAILED;
		}
	}

	if (getMSDOSHeader() != S_OK)
	{
		UnmapViewOfFile(m_lpBase);
		CloseHandle(m_hMapObject);
		CloseHandle(m_hFile);

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
		getDirBySecMapping(IMAGE_DIRECTORY_ENTRY_EXPORT);
		getDirBySecMapping(IMAGE_DIRECTORY_ENTRY_IMPORT);
		getDirBySecMapping(IMAGE_DIRECTORY_ENTRY_RESOURCE);
		getDirBySecMapping(IMAGE_DIRECTORY_ENTRY_EXCEPTION);
		getDirBySecMapping(IMAGE_DIRECTORY_ENTRY_SECURITY);
		getDirBySecMapping(IMAGE_DIRECTORY_ENTRY_BASERELOC);
		getDirBySecMapping(IMAGE_DIRECTORY_ENTRY_DEBUG);
		getDirBySecMapping(IMAGE_DIRECTORY_ENTRY_ARCHITECTURE);
		getDirBySecMapping(IMAGE_DIRECTORY_ENTRY_GLOBALPTR);
		getDirBySecMapping(IMAGE_DIRECTORY_ENTRY_TLS);
		getDirBySecMapping(IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG);
		getDirBySecMapping(IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT);
		getDirBySecMapping(IMAGE_DIRECTORY_ENTRY_IAT);
		getDirBySecMapping(IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT);
		getDirBySecMapping(IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR);
	}
	UnmapViewOfFile(m_lpBase);
	CloseHandle(m_hMapObject);
	CloseHandle(m_hFile);

	return S_OK;
}

HRESULT Clibpe::GetImageFlags(DWORD& dwImageUlong)
{
	if (!m_fLoaded)
		return E_CALL_LOADPE_FIRST;

	dwImageUlong = m_dwImageFlags;

	return S_OK;
}

HRESULT Clibpe::GetOffsetFromRVA(ULONGLONG ullRVA, DWORD& dwOffset)
{
	if (!m_fLoaded)
		return E_CALL_LOADPE_FIRST;

	dwOffset = rVAToOffset(ullRVA);

	return S_OK;
}

HRESULT Clibpe::GetMSDOSHeader(PCLIBPE_DOSHEADER& pDosHeader)
{
	if (!m_fLoaded)
	{
		pDosHeader = nullptr;
		return E_CALL_LOADPE_FIRST;
	}
	if (!ImageHasFlag(m_dwImageFlags, IMAGE_FLAG_DOSHEADER))
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
	if (!ImageHasFlag(m_dwImageFlags, IMAGE_FLAG_RICHHEADER))
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
	if (!ImageHasFlag(m_dwImageFlags, IMAGE_FLAG_NTHEADER))
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
	if (!ImageHasFlag(m_dwImageFlags, IMAGE_FLAG_FILEHEADER))
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
	if (!ImageHasFlag(m_dwImageFlags, IMAGE_FLAG_OPTHEADER))
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
	if (!ImageHasFlag(m_dwImageFlags, IMAGE_FLAG_DATADIRECTORIES))
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
	if (!ImageHasFlag(m_dwImageFlags, IMAGE_FLAG_SECTIONS))
	{
		pVecSections = nullptr;
		return E_IMAGE_HAS_NO_SECTIONS;
	}

	pVecSections = &m_vecSecHeaders;

	return S_OK;
}

HRESULT Clibpe::GetExport(PCLIBPE_EXPORT& pExport)
{
	if (!m_fLoaded)
	{
		pExport = nullptr;
		return E_CALL_LOADPE_FIRST;
	}
	if (!ImageHasFlag(m_dwImageFlags, IMAGE_FLAG_EXPORT))
	{
		pExport = nullptr;
		return E_IMAGE_HAS_NO_EXPORT;
	}

	pExport = &m_stExport;

	return S_OK;
}

HRESULT Clibpe::GetImport(PCLIBPE_IMPORT_VEC& pVecImport)
{
	if (!m_fLoaded)
	{
		pVecImport = nullptr;
		return E_CALL_LOADPE_FIRST;
	}
	if (!ImageHasFlag(m_dwImageFlags, IMAGE_FLAG_IMPORT))
	{
		pVecImport = nullptr;
		return E_IMAGE_HAS_NO_IMPORT;
	}

	pVecImport = &m_vecImport;

	return S_OK;
}

HRESULT Clibpe::GetResources(PCLIBPE_RESOURCE_ROOT& pResRoot)
{
	if (!m_fLoaded)
	{
		pResRoot = nullptr;
		return E_CALL_LOADPE_FIRST;
	}
	if (!ImageHasFlag(m_dwImageFlags, IMAGE_FLAG_RESOURCE))
	{
		pResRoot = nullptr;
		return E_IMAGE_HAS_NO_RESOURCE;
	}

	pResRoot = &m_stResource;

	return S_OK;
}

HRESULT Clibpe::GetExceptions(PCLIBPE_EXCEPTION_VEC& pVecException)
{
	if (!m_fLoaded)
	{
		pVecException = nullptr;
		return E_CALL_LOADPE_FIRST;
	}
	if (!ImageHasFlag(m_dwImageFlags, IMAGE_FLAG_EXCEPTION))
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
	if (!ImageHasFlag(m_dwImageFlags, IMAGE_FLAG_SECURITY))
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
	if (!ImageHasFlag(m_dwImageFlags, IMAGE_FLAG_BASERELOC))
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
	if (!ImageHasFlag(m_dwImageFlags, IMAGE_FLAG_DEBUG))
	{
		pVecDebug = nullptr;
		return E_IMAGE_HAS_NO_DEBUG;
	}

	pVecDebug = &m_vecDebug;

	return S_OK;
}

HRESULT Clibpe::GetTLS(PCLIBPE_TLS& pTLS)
{
	if (!m_fLoaded)
	{
		pTLS = nullptr;
		return E_CALL_LOADPE_FIRST;
	}
	if (!ImageHasFlag(m_dwImageFlags, IMAGE_FLAG_TLS))
	{
		pTLS = nullptr;
		return E_IMAGE_HAS_NO_TLS;
	}

	pTLS = &m_stTLS;

	return S_OK;
}

HRESULT Clibpe::GetLoadConfig(PCLIBPE_LOADCONFIG& pLCD)
{
	if (!m_fLoaded)
	{
		pLCD = nullptr;
		return E_CALL_LOADPE_FIRST;
	}
	if (!ImageHasFlag(m_dwImageFlags, IMAGE_FLAG_LOADCONFIG))
	{
		pLCD = nullptr;
		return E_IMAGE_HAS_NO_LOADCONFIG;
	}

	pLCD = &m_stLCD;

	return S_OK;
}

HRESULT Clibpe::GetBoundImport(PCLIBPE_BOUNDIMPORT_VEC& pVecBoundImport)
{
	if (!m_fLoaded)
	{
		pVecBoundImport = nullptr;
		return E_CALL_LOADPE_FIRST;
	}
	if (!ImageHasFlag(m_dwImageFlags, IMAGE_FLAG_BOUNDIMPORT))
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
	if (!ImageHasFlag(m_dwImageFlags, IMAGE_FLAG_DELAYIMPORT))
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
	if (!ImageHasFlag(m_dwImageFlags, IMAGE_FLAG_COMDESCRIPTOR))
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
	WORD wNumOfSections;

	if (ImageHasFlag(m_dwImageFlags, IMAGE_FLAG_PE32) && ImageHasFlag(m_dwImageFlags, IMAGE_FLAG_FILEHEADER))
	{
		pSecHdr = IMAGE_FIRST_SECTION(m_pNTHeader32);
		wNumOfSections = m_pNTHeader32->FileHeader.NumberOfSections;
	}
	else if (ImageHasFlag(m_dwImageFlags, IMAGE_FLAG_PE64) && ImageHasFlag(m_dwImageFlags, IMAGE_FLAG_FILEHEADER))
	{
		pSecHdr = IMAGE_FIRST_SECTION(m_pNTHeader64);
		wNumOfSections = m_pNTHeader64->FileHeader.NumberOfSections;
	}
	else
		return nullptr;

	for (unsigned i = 0; i < wNumOfSections; i++, pSecHdr++)
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

	if (ImageHasFlag(m_dwImageFlags, IMAGE_FLAG_PE32) && ImageHasFlag(m_dwImageFlags, IMAGE_FLAG_FILEHEADER))
	{
		pSecHdr = IMAGE_FIRST_SECTION(m_pNTHeader32);
		wNumberOfSections = m_pNTHeader32->FileHeader.NumberOfSections;
	}
	else if (ImageHasFlag(m_dwImageFlags, IMAGE_FLAG_PE64) && ImageHasFlag(m_dwImageFlags, IMAGE_FLAG_FILEHEADER))
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
		ptr = (LPVOID)((DWORD_PTR)m_lpSectionBase + (ullRVA - (DWORD_PTR)(pSecHdr->VirtualAddress - pSecHdr->PointerToRawData)
			- m_dwFileOffsetMapped));

	return isPtrSafe(ptr, true) ? ptr : nullptr;
}

DWORD Clibpe::rVAToOffset(ULONGLONG ullRVA)
{
	DWORD dwOffset { };
	for (unsigned i = 0; i < m_vecSecHeaders.size(); i++)
	{
		auto& pSecHdr = m_vecSecHeaders.at(i).stSecHdr;
		//Is RVA within this section?
		if ((ullRVA >= pSecHdr.VirtualAddress) && (ullRVA < (pSecHdr.VirtualAddress + pSecHdr.Misc.VirtualSize)))
		{
			dwOffset = (DWORD)ullRVA - (pSecHdr.VirtualAddress - pSecHdr.PointerToRawData);
			if (dwOffset > (DWORD)m_stFileSize.QuadPart)
				dwOffset = 0;
		}
	}

	return dwOffset;
}

DWORD Clibpe::ptrToOffset(LPCVOID lp) const
{
	if (!lp)
		return 0;
	if (m_fMapViewOfFileWhole)
		return (DWORD_PTR)lp - (DWORD_PTR)m_lpBase;
	else
		return (DWORD_PTR)lp - (DWORD_PTR)m_lpSectionBase + m_dwFileOffsetMapped;
}

DWORD Clibpe::getDirEntryRVA(UINT uiDirEntry) const
{
	if (ImageHasFlag(m_dwImageFlags, IMAGE_FLAG_PE32) && ImageHasFlag(m_dwImageFlags, IMAGE_FLAG_OPTHEADER))
		return m_pNTHeader32->OptionalHeader.DataDirectory[uiDirEntry].VirtualAddress;
	else if (ImageHasFlag(m_dwImageFlags, IMAGE_FLAG_PE64) && ImageHasFlag(m_dwImageFlags, IMAGE_FLAG_OPTHEADER))
		return m_pNTHeader64->OptionalHeader.DataDirectory[uiDirEntry].VirtualAddress;

	return 0;
}

DWORD Clibpe::getDirEntrySize(UINT uiDirEntry) const
{
	if (ImageHasFlag(m_dwImageFlags, IMAGE_FLAG_PE32) && ImageHasFlag(m_dwImageFlags, IMAGE_FLAG_OPTHEADER))
		return m_pNTHeader32->OptionalHeader.DataDirectory[uiDirEntry].Size;
	else if (ImageHasFlag(m_dwImageFlags, IMAGE_FLAG_PE64) && ImageHasFlag(m_dwImageFlags, IMAGE_FLAG_OPTHEADER))
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
		((DWORD_PTR)tPtr <= m_ullMaxPointerBound && (DWORD_PTR)tPtr >= (DWORD_PTR)m_lpBase) :
		((DWORD_PTR)tPtr < m_ullMaxPointerBound && (DWORD_PTR)tPtr >= (DWORD_PTR)m_lpBase));
}

//Performs checking of DWORD_PTR overflow at summing of two variables.
bool Clibpe::isSumOverflow(DWORD_PTR dwFirst, DWORD_PTR dwSecond)
{
	return (dwFirst + dwSecond) < dwFirst;
}

bool Clibpe::mapDirSection(DWORD dwDirectory)
{
	DWORD_PTR dwSizeToMap;
	PIMAGE_SECTION_HEADER pSecHdr;

	if (dwDirectory == IMAGE_DIRECTORY_ENTRY_SECURITY)
	{
		//This is an actual file RAW offset on disk.
		m_dwFileOffsetMapped = getDirEntryRVA(IMAGE_DIRECTORY_ENTRY_SECURITY);
		//Checking for out of bounds file's size to map.
		if (((LONGLONG)m_dwFileOffsetMapped + (LONGLONG)getDirEntrySize(IMAGE_DIRECTORY_ENTRY_SECURITY)) > (m_stFileSize.QuadPart))
			return false;
	}
	else if ((pSecHdr = getSecHdrFromRVA(getDirEntryRVA(dwDirectory))))
		m_dwFileOffsetMapped = pSecHdr->PointerToRawData;
	else
		return false;

	if (m_dwFileOffsetMapped > m_stFileSize.QuadPart)
		return E_FILE_SECTION_DATA_CORRUPTED;

	m_dwDeltaFileOffsetMapped = m_dwFileOffsetMapped % m_stSysInfo.dwAllocationGranularity;
	if (m_dwDeltaFileOffsetMapped > 0)
		m_dwFileOffsetMapped = m_dwFileOffsetMapped < m_stSysInfo.dwAllocationGranularity ? 0 :
		(m_dwFileOffsetMapped - m_dwDeltaFileOffsetMapped);

	if (dwDirectory == IMAGE_DIRECTORY_ENTRY_SECURITY)
		dwSizeToMap = (DWORD_PTR)getDirEntrySize(IMAGE_DIRECTORY_ENTRY_SECURITY) + (DWORD_PTR)m_dwDeltaFileOffsetMapped;
	else
		dwSizeToMap = DWORD_PTR(pSecHdr->Misc.VirtualSize + m_dwDeltaFileOffsetMapped);

	if (((LONGLONG)m_dwFileOffsetMapped + dwSizeToMap) > m_stFileSize.QuadPart)
		return false;
	if (!(m_lpSectionBase = MapViewOfFile(m_hMapObject, FILE_MAP_READ, 0, m_dwFileOffsetMapped, dwSizeToMap)))
		return false;

	m_ullMaxPointerBound = (DWORD_PTR)m_lpSectionBase + dwSizeToMap;

	return true;
}

void Clibpe::unmapDirSection() const
{
	UnmapViewOfFile(m_lpSectionBase);
}

HRESULT Clibpe::getDirBySecMapping(DWORD dwDirectory)
{
	if (!mapDirSection(dwDirectory))
		return E_FILE_MAPVIEWOFFILE_SECTION_FAILED;

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
	case IMAGE_DIRECTORY_ENTRY_SECURITY:
		getSecurity();
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

	unmapDirSection();

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
	m_dwImageFlags = 0;
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
	m_dwImageFlags |= IMAGE_FLAG_DOSHEADER;
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

			m_dwImageFlags |= IMAGE_FLAG_RICHHEADER;

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
		m_dwImageFlags |= IMAGE_FLAG_PE32;
		m_pNTHeader32 = pNTHeader;
		m_varNTHeader.stNTHdr32 = *m_pNTHeader32;
		m_stFileHeader = m_pNTHeader32->FileHeader;
		m_varOptHeader.stOptHdr32 = m_pNTHeader32->OptionalHeader;
		m_ullImageBase = m_pNTHeader32->OptionalHeader.ImageBase;
		break;
	case IMAGE_NT_OPTIONAL_HDR64_MAGIC:
		m_dwImageFlags |= IMAGE_FLAG_PE64;
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

	m_dwImageFlags |= IMAGE_FLAG_NTHEADER | IMAGE_FLAG_FILEHEADER | IMAGE_FLAG_OPTHEADER;

	return S_OK;
}

HRESULT Clibpe::getDataDirectories()
{
	PIMAGE_DATA_DIRECTORY pDataDir;
	PIMAGE_SECTION_HEADER pSecHdr;
	DWORD dwRVAAndSizes;

	if (ImageHasFlag(m_dwImageFlags, IMAGE_FLAG_PE32) && ImageHasFlag(m_dwImageFlags, IMAGE_FLAG_OPTHEADER))
	{
		pDataDir = (PIMAGE_DATA_DIRECTORY)m_pNTHeader32->OptionalHeader.DataDirectory;
		dwRVAAndSizes = m_pNTHeader32->OptionalHeader.NumberOfRvaAndSizes;
	}
	else if (ImageHasFlag(m_dwImageFlags, IMAGE_FLAG_PE64) && ImageHasFlag(m_dwImageFlags, IMAGE_FLAG_OPTHEADER))
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

	m_dwImageFlags |= IMAGE_FLAG_DATADIRECTORIES;

	return S_OK;
}

HRESULT Clibpe::getSectionsHeaders()
{
	PIMAGE_SECTION_HEADER pSecHdr;
	WORD wNumSections;
	DWORD dwSymbolTable, dwNumberOfSymbols;

	if (ImageHasFlag(m_dwImageFlags, IMAGE_FLAG_PE32) && ImageHasFlag(m_dwImageFlags, IMAGE_FLAG_FILEHEADER))
	{
		pSecHdr = IMAGE_FIRST_SECTION(m_pNTHeader32);
		wNumSections = m_pNTHeader32->FileHeader.NumberOfSections;
		dwSymbolTable = m_pNTHeader32->FileHeader.PointerToSymbolTable;
		dwNumberOfSymbols = m_pNTHeader32->FileHeader.NumberOfSymbols;
	}
	else if (ImageHasFlag(m_dwImageFlags, IMAGE_FLAG_PE64) && ImageHasFlag(m_dwImageFlags, IMAGE_FLAG_FILEHEADER))
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
			LIBPE_SECHEADERS { ptrToOffset(pSecHdr), *pSecHdr, std::move(strSecRealName) });
	}

	if (m_vecSecHeaders.empty())
		return E_IMAGE_HAS_NO_SECTIONS;

	m_dwImageFlags |= IMAGE_FLAG_SECTIONS;

	return S_OK;
}

HRESULT Clibpe::getExport()
{
	const DWORD dwExportStartRVA = getDirEntryRVA(IMAGE_DIRECTORY_ENTRY_EXPORT);
	const DWORD dwExportEndRVA = dwExportStartRVA + getDirEntrySize(IMAGE_DIRECTORY_ENTRY_EXPORT);

	const PIMAGE_EXPORT_DIRECTORY pExportDir = (PIMAGE_EXPORT_DIRECTORY)rVAToPtr(dwExportStartRVA);
	if (!pExportDir)
		return E_IMAGE_HAS_NO_EXPORT;

	const PDWORD pdwFuncs = (PDWORD)rVAToPtr(pExportDir->AddressOfFunctions);
	if (!pdwFuncs)
		return E_IMAGE_HAS_NO_EXPORT;

	std::vector<LIBPE_EXPORT_FUNC> vecFuncs;
	std::string strModuleName;
	const PWORD pwOrdinals = (PWORD)rVAToPtr(pExportDir->AddressOfNameOrdinals);
	LPCSTR* ppszNames = (LPCSTR*)rVAToPtr(pExportDir->AddressOfNames);

	try {
		for (size_t iterFuncs = 0; iterFuncs < (size_t)pExportDir->NumberOfFunctions; iterFuncs++)
		{
			//Checking pdwFuncs array.
			if (!isPtrSafe(pdwFuncs + iterFuncs))
				break;

			if (pdwFuncs[iterFuncs]) //if RVA==0 —> going next entry.
			{
				std::string strFuncName, strForwarderName;
				if (ppszNames && pwOrdinals)
					for (size_t iterFuncNames = 0; iterFuncNames < (size_t)pExportDir->NumberOfNames; iterFuncNames++)
					{
						//Checking pwOrdinals array.
						if (!isPtrSafe(pwOrdinals + iterFuncNames))
							break;
						//Cycling through ordinals table to get func name.
						if (pwOrdinals[iterFuncNames] == iterFuncs)
						{
							const LPCSTR pszFuncName = (LPCSTR)rVAToPtr((DWORD_PTR)ppszNames[iterFuncNames]);
							//Checking func name for length correctness.
							if (pszFuncName && (StringCchLengthA(pszFuncName, MAX_PATH, nullptr) != STRSAFE_E_INVALID_PARAMETER))
								strFuncName = pszFuncName;
							break;
						}
					}
				if ((pdwFuncs[iterFuncs] >= dwExportStartRVA) && (pdwFuncs[iterFuncs] <= dwExportEndRVA))
				{
					const LPCSTR pszForwarderName = (LPCSTR)rVAToPtr(pdwFuncs[iterFuncs]);
					//Checking forwarder name for length correctness.
					if (pszForwarderName && (StringCchLengthA(pszForwarderName, MAX_PATH, nullptr) != STRSAFE_E_INVALID_PARAMETER))
						strForwarderName = pszForwarderName;
				}
				vecFuncs.emplace_back(LIBPE_EXPORT_FUNC { pdwFuncs[iterFuncs], iterFuncs/*Ordinal*/, std::move(strFuncName), std::move(strForwarderName) });
			}
		}
		const LPCSTR szExportName = (LPCSTR)rVAToPtr(pExportDir->Name);
		//Checking Export name for length correctness.
		if (szExportName && (StringCchLengthA(szExportName, MAX_PATH, nullptr) != STRSAFE_E_INVALID_PARAMETER))
			strModuleName = szExportName;

		m_stExport = { ptrToOffset(pExportDir), *pExportDir, std::move(strModuleName) /*Actual IMG name*/, std::move(vecFuncs) };
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

	m_dwImageFlags |= IMAGE_FLAG_EXPORT;

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
	LIBPE_IMPORT_FUNC::LIBPE_IMPORT_THUNK_VAR varImpThunk;

	try {
		if (ImageHasFlag(m_dwImageFlags, IMAGE_FLAG_PE32))
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
						varImpThunk.stThunk32 = *pThunk32;
						IMAGE_IMPORT_BY_NAME stImpByName { };
						std::string strFuncName { };
						if (!(pThunk32->u1.Ordinal & IMAGE_ORDINAL_FLAG32))
						{
							const PIMAGE_IMPORT_BY_NAME pName = (PIMAGE_IMPORT_BY_NAME)rVAToPtr(pThunk32->u1.AddressOfData);
							if (pName && (StringCchLengthA(pName->Name, MAX_PATH, nullptr) != STRSAFE_E_INVALID_PARAMETER)) {
								stImpByName = *pName;
								strFuncName = pName->Name;
							}
						}
						vecFunc.emplace_back(LIBPE_IMPORT_FUNC { varImpThunk, stImpByName, std::move(strFuncName) });

						if (!isPtrSafe(++pThunk32))
							break;
						if (++iFuncsCount == iMaxFuncs)
							break;
					}

					const LPCSTR szName = (LPCSTR)rVAToPtr(pImpDesc->Name);
					if (szName && (StringCchLengthA(szName, MAX_PATH, nullptr) != STRSAFE_E_INVALID_PARAMETER))
						strDllName = szName;

					m_vecImport.emplace_back(LIBPE_IMPORT_MODULE { ptrToOffset(pImpDesc), *pImpDesc, std::move(strDllName), std::move(vecFunc) });

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
		else if (ImageHasFlag(m_dwImageFlags, IMAGE_FLAG_PE64))
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
						varImpThunk.stThunk64 = *pThunk64;
						IMAGE_IMPORT_BY_NAME stImpByName { };
						std::string strFuncName { };
						if (!(pThunk64->u1.Ordinal & IMAGE_ORDINAL_FLAG32))
						{
							const PIMAGE_IMPORT_BY_NAME pName = (PIMAGE_IMPORT_BY_NAME)rVAToPtr(pThunk64->u1.AddressOfData);
							if (pName && (StringCchLengthA(pName->Name, MAX_PATH, nullptr) != STRSAFE_E_INVALID_PARAMETER)) {
								stImpByName = *pName;
								strFuncName = pName->Name;
							}
						}
						vecFunc.emplace_back(LIBPE_IMPORT_FUNC { varImpThunk, stImpByName, std::move(strFuncName) });

						pThunk64++;
						if (++iFuncsCount == iMaxFuncs)
							break;
						if (++iFuncsCount == iMaxFuncs)
							break;
					}

					const LPCSTR szName = (LPCSTR)rVAToPtr(pImpDesc->Name);
					if (szName && (StringCchLengthA(szName, MAX_PATH, nullptr) != STRSAFE_E_INVALID_PARAMETER))
						strDllName = szName;

					m_vecImport.emplace_back(LIBPE_IMPORT_MODULE { ptrToOffset(pImpDesc), *pImpDesc, std::move(strDllName), std::move(vecFunc) });

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

	m_dwImageFlags |= IMAGE_FLAG_IMPORT;

	return S_OK;
}

HRESULT Clibpe::getResources()
{
	PIMAGE_RESOURCE_DIRECTORY pResDirRoot = (PIMAGE_RESOURCE_DIRECTORY)rVAToPtr(getDirEntryRVA(IMAGE_DIRECTORY_ENTRY_RESOURCE));
	if (!pResDirRoot)
		return E_IMAGE_HAS_NO_RESOURCE;

	PIMAGE_RESOURCE_DIRECTORY_ENTRY pResDirEntryRoot = (PIMAGE_RESOURCE_DIRECTORY_ENTRY)(pResDirRoot + 1);
	if (!isPtrSafe(pResDirEntryRoot))
		return E_IMAGE_HAS_NO_RESOURCE;

	PIMAGE_RESOURCE_DIR_STRING_U pResDirStr;

	try {
		std::vector<LIBPE_RESOURCE_ROOT_DATA> vecResRoot;
		DWORD dwNumOfEntriesLvL1 = pResDirRoot->NumberOfNamedEntries + pResDirRoot->NumberOfIdEntries;
		if (!isPtrSafe(pResDirEntryRoot + dwNumOfEntriesLvL1))
			return E_IMAGE_HAS_NO_RESOURCE;

		vecResRoot.reserve(dwNumOfEntriesLvL1);
		for (unsigned iLvL1 = 0; iLvL1 < dwNumOfEntriesLvL1; iLvL1++)
		{
			PIMAGE_RESOURCE_DATA_ENTRY pResDataEntryRoot { };
			std::wstring wstrResNameRoot { };
			std::vector<std::byte> vecResRawDataRoot { };
			LIBPE_RESOURCE_LVL2 stResLvL2 { };

			//Name of Resource Type (ICON, BITMAP, MENU, etc...).
			if (pResDirEntryRoot->NameIsString)
			{
				if (isSumOverflow((DWORD_PTR)pResDirRoot, (DWORD_PTR)pResDirEntryRoot->NameOffset))
					break;
				pResDirStr = PIMAGE_RESOURCE_DIR_STRING_U((DWORD_PTR)pResDirRoot + (DWORD_PTR)pResDirEntryRoot->NameOffset);
				if (isPtrSafe(pResDirStr))
					//Copy not more then MAX_PATH chars into wstrResNameRoot, avoiding overflow.
					wstrResNameRoot.assign(pResDirStr->NameString, pResDirStr->Length < MAX_PATH ? pResDirStr->Length : MAX_PATH);
			}
			if (pResDirEntryRoot->DataIsDirectory)
			{
				const PIMAGE_RESOURCE_DIRECTORY pResDirLvL2 = (PIMAGE_RESOURCE_DIRECTORY)((DWORD_PTR)pResDirRoot + (DWORD_PTR)pResDirEntryRoot->OffsetToDirectory);
				std::vector<LIBPE_RESOURCE_LVL2_DATA> vecResLvL2;

				if (!isPtrSafe(pResDirLvL2))
					break;
				if (pResDirLvL2 == pResDirRoot /*Resource loop hack*/)
					stResLvL2 = { *pResDirLvL2, vecResLvL2 };
				else
				{
					PIMAGE_RESOURCE_DIRECTORY_ENTRY pResDirEntryLvL2 = (PIMAGE_RESOURCE_DIRECTORY_ENTRY)(pResDirLvL2 + 1);
					DWORD dwNumOfEntriesLvL2 = pResDirLvL2->NumberOfNamedEntries + pResDirLvL2->NumberOfIdEntries;
					if (!isPtrSafe(pResDirEntryLvL2 + dwNumOfEntriesLvL2))
						break;

					vecResLvL2.reserve(dwNumOfEntriesLvL2);
					for (unsigned iLvL2 = 0; iLvL2 < dwNumOfEntriesLvL2; iLvL2++)
					{
						PIMAGE_RESOURCE_DATA_ENTRY pResDataEntryLvL2 { };
						std::wstring wstrResNameLvL2 { };
						std::vector<std::byte> vecResRawDataLvL2 { };
						LIBPE_RESOURCE_LVL3 stResLvL3 { };

						//Name of resource itself if not presented by ID ("AFX_MY_SUPER_DIALOG"...).
						if (pResDirEntryLvL2->NameIsString)
						{
							if (isSumOverflow((DWORD_PTR)pResDirRoot, (DWORD_PTR)pResDirEntryLvL2->NameOffset))
								break;
							pResDirStr = PIMAGE_RESOURCE_DIR_STRING_U((DWORD_PTR)pResDirRoot + (DWORD_PTR)pResDirEntryLvL2->NameOffset);
							if (isPtrSafe(pResDirStr))
								//Copy no more then MAX_PATH chars into wstrResNameLvL2, avoiding overflow.
								wstrResNameLvL2.assign(pResDirStr->NameString, pResDirStr->Length < MAX_PATH ? pResDirStr->Length : MAX_PATH);
						}

						if (pResDirEntryLvL2->DataIsDirectory)
						{
							const PIMAGE_RESOURCE_DIRECTORY pResDirLvL3 =
								(PIMAGE_RESOURCE_DIRECTORY)((DWORD_PTR)pResDirRoot + (DWORD_PTR)pResDirEntryLvL2->OffsetToDirectory);
							std::vector<LIBPE_RESOURCE_LVL3_DATA> vecResLvL3;

							if (!isPtrSafe(pResDirLvL3))
								break;
							if (pResDirLvL3 == pResDirLvL2 || pResDirLvL3 == pResDirRoot)
								stResLvL3 = { *pResDirLvL3, vecResLvL3 };
							else
							{
								PIMAGE_RESOURCE_DIRECTORY_ENTRY pResDirEntryLvL3 = (PIMAGE_RESOURCE_DIRECTORY_ENTRY)(pResDirLvL3 + 1);
								DWORD dwNumOfEntriesLvL3 = pResDirLvL3->NumberOfNamedEntries + pResDirLvL3->NumberOfIdEntries;
								if (!isPtrSafe(pResDirEntryLvL3 + dwNumOfEntriesLvL3))
									break;

								vecResLvL3.reserve(dwNumOfEntriesLvL3);
								for (unsigned iLvL3 = 0; iLvL3 < dwNumOfEntriesLvL3; iLvL3++)
								{
									std::wstring wstrResNameLvL3 { };
									std::vector<std::byte> vecResRawDataLvL3 { };

									if (pResDirEntryLvL3->NameIsString)
									{
										if (isSumOverflow((DWORD_PTR)pResDirRoot, (DWORD_PTR)pResDirEntryLvL3->NameOffset))
											break;
										pResDirStr = PIMAGE_RESOURCE_DIR_STRING_U((DWORD_PTR)pResDirRoot + (DWORD_PTR)pResDirEntryLvL3->NameOffset);
										if (isPtrSafe(pResDirStr))
											//Copy not more then MAX_PATH chars into wstrResNameLvL2, avoiding overflow.
											wstrResNameLvL3.assign(pResDirStr->NameString, pResDirStr->Length < MAX_PATH ? pResDirStr->Length : MAX_PATH);
									}

									const PIMAGE_RESOURCE_DATA_ENTRY pResDataEntryLvL3 =
										(PIMAGE_RESOURCE_DATA_ENTRY)((DWORD_PTR)pResDirRoot + (DWORD_PTR)pResDirEntryLvL3->OffsetToData);
									if (isPtrSafe(pResDataEntryLvL3))
									{	//Resource LvL 3 RAW Data.
										//IMAGE_RESOURCE_DATA_ENTRY::OffsetToData is actually a general RVA,
										//not an offset from root IMAGE_RESOURCE_DIRECTORY,
										//like IMAGE_RESOURCE_DIRECTORY_ENTRY::OffsetToData.
										//MS doesn't tend to make things simpler.

										std::byte* pThirdResRawDataBegin = (std::byte*)rVAToPtr(pResDataEntryLvL3->OffsetToData);
										//Checking RAW Resource data pointer out of bounds.
										if (pThirdResRawDataBegin && isPtrSafe((DWORD_PTR)pThirdResRawDataBegin + (DWORD_PTR)pResDataEntryLvL3->Size, true))
										{
											vecResRawDataLvL3.reserve(pResDataEntryLvL3->Size);
											for (size_t iterResRawData = 0; iterResRawData < (size_t)pResDataEntryLvL3->Size; iterResRawData++)
												vecResRawDataLvL3.push_back(*(pThirdResRawDataBegin + iterResRawData));
										}
									}

									vecResLvL3.emplace_back(LIBPE_RESOURCE_LVL3_DATA { *pResDirEntryLvL3, std::move(wstrResNameLvL3),
										isPtrSafe(pResDataEntryLvL3) ? *pResDataEntryLvL3 : IMAGE_RESOURCE_DATA_ENTRY { },
										std::move(vecResRawDataLvL3) });

									if (!isPtrSafe(++pResDirEntryLvL3))
										break;
								}
								stResLvL3 = { *pResDirLvL3, std::move(vecResLvL3) };
							}
						}
						else
						{	//////Resource LvL2 RAW Data.
							pResDataEntryLvL2 = (PIMAGE_RESOURCE_DATA_ENTRY)((DWORD_PTR)pResDirRoot + (DWORD_PTR)pResDirEntryLvL2->OffsetToData);
							if (isPtrSafe(pResDataEntryLvL2))
							{
								std::byte* pSecondResRawDataBegin = (std::byte*)rVAToPtr(pResDataEntryLvL2->OffsetToData);
								//Checking RAW Resource data pointer out of bounds.
								if (pSecondResRawDataBegin && isPtrSafe((DWORD_PTR)pSecondResRawDataBegin + (DWORD_PTR)pResDataEntryLvL2->Size, true))
								{
									vecResRawDataLvL2.reserve(pResDataEntryLvL2->Size);
									for (size_t iterResRawData = 0; iterResRawData < (size_t)pResDataEntryLvL2->Size; iterResRawData++)
										vecResRawDataLvL2.push_back(*(pSecondResRawDataBegin + iterResRawData));
								}
							}
						}
						vecResLvL2.emplace_back(LIBPE_RESOURCE_LVL2_DATA { *pResDirEntryLvL2, std::move(wstrResNameLvL2),
							isPtrSafe(pResDataEntryLvL2) ? *pResDataEntryLvL2 : IMAGE_RESOURCE_DATA_ENTRY { },
							std::move(vecResRawDataLvL2), stResLvL3 });

						if (!isPtrSafe(++pResDirEntryLvL2))
							break;
					}
					stResLvL2 = { *pResDirLvL2, std::move(vecResLvL2) };
				}
			}
			else
			{	//////Resource LvL Root RAW Data.
				pResDataEntryRoot = (PIMAGE_RESOURCE_DATA_ENTRY)((DWORD_PTR)pResDirRoot + (DWORD_PTR)pResDirEntryRoot->OffsetToData);
				if (isPtrSafe(pResDataEntryRoot))
				{
					std::byte* pRootResRawDataBegin = (std::byte*)rVAToPtr(pResDataEntryRoot->OffsetToData);
					//Checking RAW Resource data pointer out of bounds.
					if (pRootResRawDataBegin && isPtrSafe((DWORD_PTR)pRootResRawDataBegin + (DWORD_PTR)pResDataEntryRoot->Size, true))
					{
						vecResRawDataRoot.reserve(pResDataEntryRoot->Size);
						for (size_t iterResRawData = 0; iterResRawData < (size_t)pResDataEntryRoot->Size; iterResRawData++)
							vecResRawDataRoot.push_back(*(pRootResRawDataBegin + iterResRawData));
					}
				}
			}
			vecResRoot.emplace_back(LIBPE_RESOURCE_ROOT_DATA { *pResDirEntryRoot, std::move(wstrResNameRoot),
				isPtrSafe(pResDataEntryRoot) ? *pResDataEntryRoot : IMAGE_RESOURCE_DATA_ENTRY { },
				std::move(vecResRawDataRoot), stResLvL2 });

			if (!isPtrSafe(++pResDirEntryRoot))
				break;
		}
		m_stResource = { ptrToOffset(pResDirRoot), *pResDirRoot, std::move(vecResRoot) };
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

	m_dwImageFlags |= IMAGE_FLAG_RESOURCE;

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

		m_vecException.emplace_back(LIBPE_EXCEPTION { ptrToOffset(pRuntimeFuncsEntry), *pRuntimeFuncsEntry });
	}

	m_dwImageFlags |= IMAGE_FLAG_EXCEPTION;

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

		dwSecurityDirStartVA = (DWORD_PTR)m_lpSectionBase + (DWORD_PTR)m_dwDeltaFileOffsetMapped;
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

		m_vecSecurity.emplace_back(LIBPE_SECURITY { ptrToOffset(pCertificate), *pCertificate, std::move(vecCertBytes) });

		//Get next certificate entry, all entries start at 8 aligned address.
		DWORD_PTR dwLength = (DWORD_PTR)pCertificate->dwLength;
		dwLength += (8 - (dwLength & 7)) & 7;
		dwSecurityDirStartVA = dwSecurityDirStartVA + dwLength;
		if (!isPtrSafe(dwSecurityDirStartVA))
			break;
	}
	m_dwImageFlags |= IMAGE_FLAG_SECURITY;

	return S_OK;
}

HRESULT Clibpe::getRelocations()
{
	PIMAGE_BASE_RELOCATION pBaseRelocDesc = (PIMAGE_BASE_RELOCATION)rVAToPtr(getDirEntryRVA(IMAGE_DIRECTORY_ENTRY_BASERELOC));

	if (!pBaseRelocDesc)
		return E_IMAGE_HAS_NO_BASERELOC;

	try
	{
		if (!pBaseRelocDesc->SizeOfBlock || !pBaseRelocDesc->VirtualAddress)
			m_vecRelocs.emplace_back(LIBPE_RELOCATION { ptrToOffset(pBaseRelocDesc), *pBaseRelocDesc, { } });

		while ((pBaseRelocDesc->SizeOfBlock) && (pBaseRelocDesc->VirtualAddress))
		{
			if (pBaseRelocDesc->SizeOfBlock < sizeof(IMAGE_BASE_RELOCATION))
			{
				m_vecRelocs.emplace_back(LIBPE_RELOCATION { ptrToOffset(pBaseRelocDesc), *pBaseRelocDesc, { } });
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

				vecRelocs.emplace_back(LIBPE_RELOC_DATA { ptrToOffset(pwRelocEntry), wRelocType, (WORD)((*pwRelocEntry) & 0x0fff)/*Low 12 bits —> Offset*/ });
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

					vecRelocs.emplace_back(LIBPE_RELOC_DATA { ptrToOffset(pwRelocEntry), wRelocType, *pwRelocEntry /*The low 16-bit field.*/ });
					dwNumRelocEntries--; //to compensate pwRelocEntry++.
				}
			}

			m_vecRelocs.emplace_back(LIBPE_RELOCATION { ptrToOffset(pBaseRelocDesc), *pBaseRelocDesc, std::move(vecRelocs) });

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

	m_dwImageFlags |= IMAGE_FLAG_BASERELOC;

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
			pDebugDir = (PIMAGE_DEBUG_DIRECTORY)((DWORD_PTR)m_lpBase + pDebugSecHdr->PointerToRawData);
		else
			pDebugDir = (PIMAGE_DEBUG_DIRECTORY)((DWORD_PTR)m_lpSectionBase + m_dwDeltaFileOffsetMapped);

		dwDebugDirSize = getDirEntrySize(IMAGE_DIRECTORY_ENTRY_DEBUG) * sizeof(IMAGE_DEBUG_DIRECTORY);
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
			LPVOID lpDebugRaw { }; //In case of Big file.

			if (m_fMapViewOfFileWhole)
				pDebugRawData = (std::byte*)((DWORD_PTR)m_lpBase + (DWORD_PTR)pDebugDir->PointerToRawData);
			else
			{	//Map Debug raw data file's part.
				DWORD dwOffsetMapped = pDebugDir->PointerToRawData;
				DWORD dwDelta = pDebugDir->PointerToRawData % m_stSysInfo.dwAllocationGranularity;
				if (dwDelta > 0)
					dwOffsetMapped = dwOffsetMapped < m_stSysInfo.dwAllocationGranularity ? 0 :
					(dwOffsetMapped - dwDelta);

				DWORD dwSizeToMap = pDebugDir->SizeOfData + dwDelta;

				if (((LONGLONG)dwOffsetMapped + dwSizeToMap) > m_stFileSize.QuadPart)
					break;
				lpDebugRaw = MapViewOfFile(m_hMapObject, FILE_MAP_READ, 0, dwOffsetMapped, dwSizeToMap);
				if (!lpDebugRaw)
					break;

				pDebugRawData = (std::byte*)((DWORD_PTR)lpDebugRaw + dwDelta);
			}

			if (isPtrSafe(pDebugRawData) && isPtrSafe((DWORD_PTR)pDebugRawData + (DWORD_PTR)pDebugDir->SizeOfData))
			{
				vecDebugRawData.reserve(pDebugDir->SizeOfData);
				for (size_t iterRawData = 0; iterRawData < (size_t)pDebugDir->SizeOfData; iterRawData++)
					vecDebugRawData.push_back(*(pDebugRawData + iterRawData));
			}
			if (!m_fMapViewOfFileWhole)
				UnmapViewOfFile(lpDebugRaw);

			m_vecDebug.emplace_back(LIBPE_DEBUG { ptrToOffset(pDebugDir), *pDebugDir, std::move(vecDebugRawData) });
			if (!isPtrSafe(++pDebugDir))
				break;
		}

		m_dwImageFlags |= IMAGE_FLAG_DEBUG;
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

	m_dwImageFlags |= IMAGE_FLAG_ARCHITECTURE;

	return S_OK;
}

HRESULT Clibpe::getGlobalPtr()
{
	const DWORD_PTR dwGlobalPTRDirRVA = (DWORD_PTR)rVAToPtr(getDirEntryRVA(IMAGE_DIRECTORY_ENTRY_GLOBALPTR));
	if (!dwGlobalPTRDirRVA)
		return E_IMAGE_HAS_NO_GLOBALPTR;

	m_dwImageFlags |= IMAGE_FLAG_GLOBALPTR;

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
		LIBPE_TLS::LIBPE_TLS_VAR varTLSDir;
		PDWORD pdwTLSPtr;

		if (ImageHasFlag(m_dwImageFlags, IMAGE_FLAG_PE32))
		{
			const PIMAGE_TLS_DIRECTORY32 pTLSDir32 = (PIMAGE_TLS_DIRECTORY32)rVAToPtr(dwTLSDirRVA);
			if (!pTLSDir32)
				return E_IMAGE_HAS_NO_TLS;

			varTLSDir.stTLSDir32 = *pTLSDir32;
			pdwTLSPtr = (PDWORD)pTLSDir32;
			ulStartAddressOfRawData = pTLSDir32->StartAddressOfRawData;
			ulEndAddressOfRawData = pTLSDir32->EndAddressOfRawData;
			ulAddressOfCallBacks = pTLSDir32->AddressOfCallBacks;
		}
		else if (ImageHasFlag(m_dwImageFlags, IMAGE_FLAG_PE64))
		{
			const PIMAGE_TLS_DIRECTORY64 pTLSDir64 = (PIMAGE_TLS_DIRECTORY64)rVAToPtr(dwTLSDirRVA);
			if (!pTLSDir64)
				return E_IMAGE_HAS_NO_TLS;

			varTLSDir.stTLSDir64 = *pTLSDir64;
			pdwTLSPtr = (PDWORD)pTLSDir64;
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

		m_stTLS = LIBPE_TLS { ptrToOffset(pdwTLSPtr), varTLSDir, std::move(vecTLSRawData), std::move(vecTLSCallbacks) };
		m_dwImageFlags |= IMAGE_FLAG_TLS;
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
	if (ImageHasFlag(m_dwImageFlags, IMAGE_FLAG_PE32))
	{
		const PIMAGE_LOAD_CONFIG_DIRECTORY32 pLCD32 =
			(PIMAGE_LOAD_CONFIG_DIRECTORY32)rVAToPtr(getDirEntryRVA(IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG));
		if (!pLCD32 || !isPtrSafe((DWORD_PTR)pLCD32 + sizeof(IMAGE_LOAD_CONFIG_DIRECTORY32)))
			return E_IMAGE_HAS_NO_LOADCONFIG;

		m_stLCD.dwOffsetLCD = ptrToOffset(pLCD32);
		m_stLCD.varLCD.stLCD32 = *pLCD32;
	}
	else if (ImageHasFlag(m_dwImageFlags, IMAGE_FLAG_PE64))
	{
		const PIMAGE_LOAD_CONFIG_DIRECTORY64 pLCD64 =
			(PIMAGE_LOAD_CONFIG_DIRECTORY64)rVAToPtr(getDirEntryRVA(IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG));
		if (!pLCD64 || !isPtrSafe((DWORD_PTR)pLCD64 + sizeof(PIMAGE_LOAD_CONFIG_DIRECTORY64)))
			return E_IMAGE_HAS_NO_LOADCONFIG;

		m_stLCD.dwOffsetLCD = ptrToOffset(pLCD64);
		m_stLCD.varLCD.stLCD64 = *pLCD64;
	}
	else
		return E_IMAGE_HAS_NO_LOADCONFIG;

	m_dwImageFlags |= IMAGE_FLAG_LOADCONFIG;

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

			vecBoundForwarders.emplace_back(LIBPE_BOUNDFORWARDER { ptrToOffset(pBoundImpForwarder), *pBoundImpForwarder, std::move(strForwarderModuleName) });

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

		m_vecBoundImport.emplace_back(LIBPE_BOUNDIMPORT { ptrToOffset(pBoundImpDesc), *pBoundImpDesc, std::move(strModuleName), std::move(vecBoundForwarders) });

		if (!isPtrSafe(++pBoundImpDesc))
			break;
	}

	m_dwImageFlags |= IMAGE_FLAG_BOUNDIMPORT;

	return S_OK;
}

HRESULT Clibpe::getIAT()
{
	const DWORD_PTR dwIATDirRVA = (DWORD_PTR)rVAToPtr(getDirEntryRVA(IMAGE_DIRECTORY_ENTRY_IAT));
	if (!dwIATDirRVA)
		return E_IMAGE_HAS_NO_IAT;

	m_dwImageFlags |= IMAGE_FLAG_IAT;

	return S_OK;
}

HRESULT Clibpe::getDelayImport()
{
	PIMAGE_DELAYLOAD_DESCRIPTOR pDelayImpDescr = (PIMAGE_DELAYLOAD_DESCRIPTOR)rVAToPtr(getDirEntryRVA(IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT));
	if (!pDelayImpDescr)
		return E_IMAGE_HAS_NO_DELAYIMPORT;

	LIBPE_DELAYIMPORT_FUNC::LIBPE_DELAYIMPORT_THUNK_VAR varDelayImpThunk { };

	if (ImageHasFlag(m_dwImageFlags, IMAGE_FLAG_PE32))
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
				PIMAGE_THUNK_DATA32 pThunk32UnloadInfoTable = (PIMAGE_THUNK_DATA32)rVAToPtr(
					pDelayImpDescr->UnloadInformationTableRVA);

				if (!pThunk32Name)
					break;

				while (pThunk32Name->u1.AddressOfData)
				{
					varDelayImpThunk.st32.stImportAddressTable = *pThunk32Name;
					varDelayImpThunk.st32.stImportNameTable = pThunk32IAT ? *pThunk32IAT : IMAGE_THUNK_DATA32 { };
					varDelayImpThunk.st32.stBoundImportAddressTable = pThunk32BoundIAT ? *pThunk32BoundIAT : IMAGE_THUNK_DATA32 { };
					varDelayImpThunk.st32.stUnloadInformationTable = pThunk32UnloadInfoTable ? *pThunk32UnloadInfoTable : IMAGE_THUNK_DATA32 { };

					std::string strFuncName { };
					IMAGE_IMPORT_BY_NAME stImpByName { };
					if (!(pThunk32Name->u1.Ordinal & IMAGE_ORDINAL_FLAG32))
					{
						const PIMAGE_IMPORT_BY_NAME pName = (PIMAGE_IMPORT_BY_NAME)rVAToPtr(pThunk32Name->u1.AddressOfData);
						if (pName && (StringCchLengthA(pName->Name, MAX_PATH, nullptr) != STRSAFE_E_INVALID_PARAMETER))
						{
							stImpByName = *pName;
							strFuncName = pName->Name;
						}
					}
					vecFunc.emplace_back(LIBPE_DELAYIMPORT_FUNC { varDelayImpThunk, stImpByName, std::move(strFuncName) });

					if (!isPtrSafe(++pThunk32Name))
						break;
					if (pThunk32IAT)
						if (!isPtrSafe(++pThunk32IAT))
							break;
					if (pThunk32BoundIAT)
						if (!isPtrSafe(++pThunk32BoundIAT))
							break;
					if (pThunk32UnloadInfoTable)
						if (!isPtrSafe(++pThunk32UnloadInfoTable))
							break;
				}

				const LPCSTR szName = (LPCSTR)rVAToPtr(pDelayImpDescr->DllNameRVA);
				if (szName && (StringCchLengthA(szName, MAX_PATH, nullptr) != STRSAFE_E_INVALID_PARAMETER))
					strDllName = szName;

				m_vecDelayImport.emplace_back(LIBPE_DELAYIMPORT { ptrToOffset(pDelayImpDescr), *pDelayImpDescr, std::move(strDllName), std::move(vecFunc) });

				if (!isPtrSafe(++pDelayImpDescr))
					break;
			}
		}
	}
	else if (ImageHasFlag(m_dwImageFlags, IMAGE_FLAG_PE64))
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
				PIMAGE_THUNK_DATA64 pThunk64UnloadInfoTable = (PIMAGE_THUNK_DATA64)rVAToPtr(
					pDelayImpDescr->UnloadInformationTableRVA);

				if (!pThunk64Name)
					break;

				while (pThunk64Name->u1.AddressOfData)
				{
					varDelayImpThunk.st64.stImportAddressTable = *pThunk64Name;
					varDelayImpThunk.st64.stImportNameTable = pThunk64IAT ? *pThunk64IAT : IMAGE_THUNK_DATA64 { };
					varDelayImpThunk.st64.stBoundImportAddressTable = pThunk64BoundIAT ? *pThunk64BoundIAT : IMAGE_THUNK_DATA64 { };
					varDelayImpThunk.st64.stUnloadInformationTable = pThunk64UnloadInfoTable ? *pThunk64UnloadInfoTable : IMAGE_THUNK_DATA64 { };

					std::string strFuncName { };
					IMAGE_IMPORT_BY_NAME stImpByName { };
					if (!(pThunk64Name->u1.Ordinal & IMAGE_ORDINAL_FLAG64))
					{
						const PIMAGE_IMPORT_BY_NAME pName = (PIMAGE_IMPORT_BY_NAME)rVAToPtr(pThunk64Name->u1.AddressOfData);
						if (pName && (StringCchLengthA(pName->Name, MAX_PATH, nullptr) != STRSAFE_E_INVALID_PARAMETER))
						{
							stImpByName = *pName;
							strFuncName = pName->Name;
						}
					}
					vecFunc.emplace_back(LIBPE_DELAYIMPORT_FUNC { varDelayImpThunk, stImpByName, std::move(strFuncName) });

					if (!isPtrSafe(++pThunk64Name))
						break;
					if (pThunk64IAT)
						if (!isPtrSafe(++pThunk64IAT))
							break;
					if (pThunk64BoundIAT)
						if (!isPtrSafe(++pThunk64BoundIAT))
							break;
					if (pThunk64UnloadInfoTable)
						if (!isPtrSafe(++pThunk64UnloadInfoTable))
							break;
				}

				const LPCSTR szName = (LPCSTR)rVAToPtr(pDelayImpDescr->DllNameRVA);
				if (szName && (StringCchLengthA(szName, MAX_PATH, nullptr) != STRSAFE_E_INVALID_PARAMETER))
					strDllName = szName;

				m_vecDelayImport.emplace_back(LIBPE_DELAYIMPORT { ptrToOffset(pDelayImpDescr), *pDelayImpDescr, std::move(strDllName), std::move(vecFunc) });

				if (!isPtrSafe(++pDelayImpDescr))
					break;
			}
		}
	}
	m_dwImageFlags |= IMAGE_FLAG_DELAYIMPORT;

	return S_OK;
}

HRESULT Clibpe::getCOMDescriptor()
{
	const PIMAGE_COR20_HEADER pCOMDescHeader = (PIMAGE_COR20_HEADER)rVAToPtr(getDirEntryRVA(IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR));
	if (!pCOMDescHeader)
		return E_IMAGE_HAS_NO_COMDESCRIPTOR;

	m_stCOR20Desc = { ptrToOffset(pCOMDescHeader), *pCOMDescHeader };
	m_dwImageFlags |= IMAGE_FLAG_COMDESCRIPTOR;

	return S_OK;
}