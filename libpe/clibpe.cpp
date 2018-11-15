/*********************************************************************
* Copyright (C) 2018, Jovibor: https://github.com/jovibor/			 *
* PE viewer library for x86 (PE32) and x64 (PE32+) binares.			 *
* This code is provided «AS IS» without any warranty, and			 *
* can be used without any limitations for non-commercial usage.		 *
* Additional info can be found at https://github.com/jovibor/libpe	 *
*********************************************************************/
#include "stdafx.h"
#include "libpe.h"
#include "clibpe.h"

extern "C" HRESULT ILIBPEAPI Getlibpe(libpe::Ilibpe** pIlibpe)
{
	*pIlibpe = new Clibpe;

	return S_OK;
}

Clibpe::~Clibpe()
{
	delete [] m_lpszEmergencyMemory;
}

HRESULT Clibpe::LoadPe(LPCWSTR lpszFileName)
{
	if (m_fLoaded) //If other PE file was already, previously loaded.
		resetAll();

	const HANDLE hFile = CreateFileW(lpszFileName, GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
	if (hFile == INVALID_HANDLE_VALUE)
		return FILE_OPEN_FAILED;

	::GetFileSizeEx(hFile, &m_stFileSize);
	if (m_stFileSize.QuadPart < sizeof(IMAGE_DOS_HEADER))
	{
		CloseHandle(hFile);
		return FILE_SIZE_TOO_SMALL;
	}

	m_hMapObject = CreateFileMappingW(hFile, nullptr, PAGE_READONLY, 0, 0, nullptr);
	if (!m_hMapObject)
	{
		CloseHandle(hFile);
		return FILE_CREATE_FILE_MAPPING_FAILED;
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
				return FILE_MAP_VIEW_OF_FILE_FAILED;
			}
			m_fMapViewOfFileWhole = false;
			m_dwMaxPointerBound = (DWORD_PTR)m_lpBase + (DWORD_PTR)m_dwMinBytesToMap;
		}
		else
		{
			CloseHandle(m_hMapObject);
			CloseHandle(hFile);
			return FILE_MAP_VIEW_OF_FILE_FAILED;
		}
	}
	else
	{
		m_fMapViewOfFileWhole = true;
		m_dwMaxPointerBound = (DWORD_PTR)m_lpBase + m_stFileSize.QuadPart;
	}

	HRESULT hr = getHeaders();
	if (hr != S_OK)
	{	//If at least IMAGE_DOS_SIGNATURE found then returning S_OK.
		//Some PE files may consist of only DOS stub.
		if (hr != IMAGE_DOS_SIGNATURE_MISMATCH)
			hr = S_OK;

		UnmapViewOfFile(m_lpBase);
		CloseHandle(m_hMapObject);
		CloseHandle(hFile);

		return hr;
	}

	getDataDirectories();
	getSectionsHeaders();

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
		getGlobalPTRTable();
		getTLSTable();
		getLoadConfigTable();
		getBoundImportTable();
		getIATTable();
		getDelayImportTable();
		getCOMDescriptorTable();
	}
	else
	{
		SYSTEM_INFO SysInfo { };
		::GetSystemInfo(&SysInfo);
		DWORD dwAlignedAddressToMap;
		DWORD_PTR dwSizeToMap;
		PIMAGE_SECTION_HEADER pSecHdr;

		if ((pSecHdr = getSecHdrFromRVA(getDirEntryRVA(IMAGE_DIRECTORY_ENTRY_EXPORT))))
		{
			m_dwFileOffsetToMap = pSecHdr->PointerToRawData;

			if (m_dwFileOffsetToMap % SysInfo.dwAllocationGranularity > 0)
			{
				dwAlignedAddressToMap = (m_dwFileOffsetToMap < SysInfo.dwAllocationGranularity) ? 0 :
					(m_dwFileOffsetToMap - (m_dwFileOffsetToMap % SysInfo.dwAllocationGranularity));
			}
			else
				dwAlignedAddressToMap = m_dwFileOffsetToMap;

			m_dwDeltaFileOffsetToMap = m_dwFileOffsetToMap - dwAlignedAddressToMap;
			dwSizeToMap = DWORD_PTR(pSecHdr->Misc.VirtualSize + m_dwDeltaFileOffsetToMap);
			if ((LONGLONG)((DWORD_PTR)dwAlignedAddressToMap + dwSizeToMap) > m_stFileSize.QuadPart)
				return FILE_SECTION_DATA_CORRUPTED;
			if (!(m_lpSectionBase = MapViewOfFile(m_hMapObject, FILE_MAP_READ, 0, dwAlignedAddressToMap, dwSizeToMap)))
				return FILE_MAP_VIEW_OF_FILE_FAILED;

			m_dwMaxPointerBound = (DWORD_PTR)m_lpSectionBase + dwSizeToMap;
			getExportTable();
			UnmapViewOfFile(m_lpSectionBase);
		}

		if ((pSecHdr = getSecHdrFromRVA(getDirEntryRVA(IMAGE_DIRECTORY_ENTRY_IMPORT))))
		{
			m_dwFileOffsetToMap = pSecHdr->PointerToRawData;

			if (m_dwFileOffsetToMap % SysInfo.dwAllocationGranularity > 0)
			{
				dwAlignedAddressToMap = (m_dwFileOffsetToMap < SysInfo.dwAllocationGranularity) ? 0 :
					(m_dwFileOffsetToMap - (m_dwFileOffsetToMap % SysInfo.dwAllocationGranularity));
			}
			else
				dwAlignedAddressToMap = m_dwFileOffsetToMap;

			m_dwDeltaFileOffsetToMap = m_dwFileOffsetToMap - dwAlignedAddressToMap;
			dwSizeToMap = DWORD_PTR(pSecHdr->Misc.VirtualSize + m_dwDeltaFileOffsetToMap);
			if ((LONGLONG)((DWORD_PTR)dwAlignedAddressToMap + dwSizeToMap) > m_stFileSize.QuadPart)
				return FILE_SECTION_DATA_CORRUPTED;

			if (!(m_lpSectionBase = MapViewOfFile(m_hMapObject, FILE_MAP_READ, 0, dwAlignedAddressToMap, dwSizeToMap)))
				return FILE_MAP_VIEW_OF_FILE_FAILED;

			m_dwMaxPointerBound = (DWORD_PTR)m_lpSectionBase + dwSizeToMap;
			getImportTable();
			UnmapViewOfFile(m_lpSectionBase);
		}

		if ((pSecHdr = getSecHdrFromRVA(getDirEntryRVA(IMAGE_DIRECTORY_ENTRY_RESOURCE))))
		{
			m_dwFileOffsetToMap = pSecHdr->PointerToRawData;

			if (m_dwFileOffsetToMap % SysInfo.dwAllocationGranularity > 0)
			{
				dwAlignedAddressToMap = (m_dwFileOffsetToMap < SysInfo.dwAllocationGranularity) ? 0 :
					(m_dwFileOffsetToMap - (m_dwFileOffsetToMap % SysInfo.dwAllocationGranularity));
			}
			else
				dwAlignedAddressToMap = m_dwFileOffsetToMap;

			m_dwDeltaFileOffsetToMap = m_dwFileOffsetToMap - dwAlignedAddressToMap;
			dwSizeToMap = DWORD_PTR(pSecHdr->Misc.VirtualSize + m_dwDeltaFileOffsetToMap);
			if ((LONGLONG)((DWORD_PTR)dwAlignedAddressToMap + dwSizeToMap) > m_stFileSize.QuadPart)
				return FILE_SECTION_DATA_CORRUPTED;

			if (!(m_lpSectionBase = MapViewOfFile(m_hMapObject, FILE_MAP_READ, 0, dwAlignedAddressToMap, dwSizeToMap)))
				return FILE_MAP_VIEW_OF_FILE_FAILED;

			m_dwMaxPointerBound = (DWORD_PTR)m_lpSectionBase + dwSizeToMap;
			getResourceTable();
			UnmapViewOfFile(m_lpSectionBase);
		}

		if ((pSecHdr = getSecHdrFromRVA(getDirEntryRVA(IMAGE_DIRECTORY_ENTRY_EXCEPTION))))
		{
			m_dwFileOffsetToMap = pSecHdr->PointerToRawData;

			if (m_dwFileOffsetToMap % SysInfo.dwAllocationGranularity > 0)
			{
				dwAlignedAddressToMap = (m_dwFileOffsetToMap < SysInfo.dwAllocationGranularity) ? 0 :
					(m_dwFileOffsetToMap - (m_dwFileOffsetToMap % SysInfo.dwAllocationGranularity));
			}
			else
				dwAlignedAddressToMap = m_dwFileOffsetToMap;

			m_dwDeltaFileOffsetToMap = m_dwFileOffsetToMap - dwAlignedAddressToMap;
			dwSizeToMap = DWORD_PTR(pSecHdr->Misc.VirtualSize + m_dwDeltaFileOffsetToMap);
			if ((LONGLONG)((DWORD_PTR)dwAlignedAddressToMap + dwSizeToMap) > m_stFileSize.QuadPart)
				return FILE_SECTION_DATA_CORRUPTED;

			if (!(m_lpSectionBase = MapViewOfFile(m_hMapObject, FILE_MAP_READ, 0, dwAlignedAddressToMap, dwSizeToMap)))
				return FILE_MAP_VIEW_OF_FILE_FAILED;

			m_dwMaxPointerBound = (DWORD_PTR)m_lpSectionBase + dwSizeToMap;
			getExceptionTable();
			UnmapViewOfFile(m_lpSectionBase);
		}

		if (getDirEntryRVA(IMAGE_DIRECTORY_ENTRY_SECURITY))
		{
			//This is an actual file RAW offset.
			m_dwFileOffsetToMap = getDirEntryRVA(IMAGE_DIRECTORY_ENTRY_SECURITY);

			//Checking for exceeding file size bound.
			if (m_dwFileOffsetToMap < m_stFileSize.QuadPart)
			{
				if (m_dwFileOffsetToMap % SysInfo.dwAllocationGranularity > 0)
				{
					dwAlignedAddressToMap = (m_dwFileOffsetToMap < SysInfo.dwAllocationGranularity) ? 0 :
						(m_dwFileOffsetToMap - (m_dwFileOffsetToMap % SysInfo.dwAllocationGranularity));
				}
				else
					dwAlignedAddressToMap = m_dwFileOffsetToMap;

				m_dwDeltaFileOffsetToMap = m_dwFileOffsetToMap - dwAlignedAddressToMap;

				dwSizeToMap = (DWORD_PTR)getDirEntrySize(IMAGE_DIRECTORY_ENTRY_SECURITY) + (DWORD_PTR)m_dwDeltaFileOffsetToMap;
				//Checking for out of bounds file's size to map.
				if (((LONGLONG)m_dwFileOffsetToMap + (LONGLONG)getDirEntrySize(IMAGE_DIRECTORY_ENTRY_SECURITY)) <= (m_stFileSize.QuadPart))
				{
					if (!(m_lpSectionBase = MapViewOfFile(m_hMapObject, FILE_MAP_READ, 0, dwAlignedAddressToMap, dwSizeToMap)))
						return FILE_MAP_VIEW_OF_FILE_FAILED;

					m_dwMaxPointerBound = (DWORD_PTR)m_lpSectionBase + dwSizeToMap;
					getSecurityTable();
					UnmapViewOfFile(m_lpSectionBase);
				}
			}
		}

		if ((pSecHdr = getSecHdrFromRVA(getDirEntryRVA(IMAGE_DIRECTORY_ENTRY_BASERELOC))))
		{
			m_dwFileOffsetToMap = pSecHdr->PointerToRawData;

			if (m_dwFileOffsetToMap % SysInfo.dwAllocationGranularity > 0)
			{
				dwAlignedAddressToMap = (m_dwFileOffsetToMap < SysInfo.dwAllocationGranularity) ? 0 :
					(m_dwFileOffsetToMap - (m_dwFileOffsetToMap % SysInfo.dwAllocationGranularity));
			}
			else
				dwAlignedAddressToMap = m_dwFileOffsetToMap;

			m_dwDeltaFileOffsetToMap = m_dwFileOffsetToMap - dwAlignedAddressToMap;
			dwSizeToMap = DWORD_PTR(pSecHdr->Misc.VirtualSize + m_dwDeltaFileOffsetToMap);
			if ((LONGLONG)((DWORD_PTR)dwAlignedAddressToMap + dwSizeToMap) > m_stFileSize.QuadPart)
				return FILE_SECTION_DATA_CORRUPTED;

			if (!(m_lpSectionBase = MapViewOfFile(m_hMapObject, FILE_MAP_READ, 0, dwAlignedAddressToMap, dwSizeToMap)))
				return FILE_MAP_VIEW_OF_FILE_FAILED;

			m_dwMaxPointerBound = (DWORD_PTR)m_lpSectionBase + dwSizeToMap;
			getRelocationTable();
			UnmapViewOfFile(m_lpSectionBase);
		}

		if ((pSecHdr = getSecHdrFromRVA(getDirEntryRVA(IMAGE_DIRECTORY_ENTRY_DEBUG))))
		{
			m_dwFileOffsetToMap = pSecHdr->PointerToRawData;

			if (m_dwFileOffsetToMap % SysInfo.dwAllocationGranularity > 0)
			{
				dwAlignedAddressToMap = (m_dwFileOffsetToMap < SysInfo.dwAllocationGranularity) ? 0 :
					(m_dwFileOffsetToMap - (m_dwFileOffsetToMap % SysInfo.dwAllocationGranularity));
			}
			else
				dwAlignedAddressToMap = m_dwFileOffsetToMap;

			m_dwDeltaFileOffsetToMap = m_dwFileOffsetToMap - dwAlignedAddressToMap;
			dwSizeToMap = DWORD_PTR(pSecHdr->Misc.VirtualSize + m_dwDeltaFileOffsetToMap);
			if ((LONGLONG)((DWORD_PTR)dwAlignedAddressToMap + dwSizeToMap) > m_stFileSize.QuadPart)
				return FILE_SECTION_DATA_CORRUPTED;

			if (!(m_lpSectionBase = MapViewOfFile(m_hMapObject, FILE_MAP_READ, 0, dwAlignedAddressToMap, dwSizeToMap)))
				return FILE_MAP_VIEW_OF_FILE_FAILED;

			m_dwMaxPointerBound = (DWORD_PTR)m_lpSectionBase + dwSizeToMap;
			getDebugTable();
			UnmapViewOfFile(m_lpSectionBase);
		}

		if ((pSecHdr = getSecHdrFromRVA(getDirEntryRVA(IMAGE_DIRECTORY_ENTRY_TLS))))
		{
			m_dwFileOffsetToMap = pSecHdr->PointerToRawData;

			if (m_dwFileOffsetToMap % SysInfo.dwAllocationGranularity > 0)
			{
				dwAlignedAddressToMap = (m_dwFileOffsetToMap < SysInfo.dwAllocationGranularity) ? 0 :
					(m_dwFileOffsetToMap - (m_dwFileOffsetToMap % SysInfo.dwAllocationGranularity));
			}
			else
				dwAlignedAddressToMap = m_dwFileOffsetToMap;

			m_dwDeltaFileOffsetToMap = m_dwFileOffsetToMap - dwAlignedAddressToMap;
			dwSizeToMap = DWORD_PTR(pSecHdr->Misc.VirtualSize + m_dwDeltaFileOffsetToMap);
			if ((LONGLONG)((DWORD_PTR)dwAlignedAddressToMap + dwSizeToMap) > m_stFileSize.QuadPart)
				return FILE_SECTION_DATA_CORRUPTED;

			if (!(m_lpSectionBase = MapViewOfFile(m_hMapObject, FILE_MAP_READ, 0, dwAlignedAddressToMap, dwSizeToMap)))
				return FILE_MAP_VIEW_OF_FILE_FAILED;

			m_dwMaxPointerBound = (DWORD_PTR)m_lpSectionBase + dwSizeToMap;
			getTLSTable();
			UnmapViewOfFile(m_lpSectionBase);
		}

		if ((pSecHdr = getSecHdrFromRVA(getDirEntryRVA(IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG))))
		{
			m_dwFileOffsetToMap = pSecHdr->PointerToRawData;

			if (m_dwFileOffsetToMap % SysInfo.dwAllocationGranularity > 0)
			{
				dwAlignedAddressToMap = (m_dwFileOffsetToMap < SysInfo.dwAllocationGranularity) ? 0 :
					(m_dwFileOffsetToMap - (m_dwFileOffsetToMap % SysInfo.dwAllocationGranularity));
			}
			else
				dwAlignedAddressToMap = m_dwFileOffsetToMap;

			m_dwDeltaFileOffsetToMap = m_dwFileOffsetToMap - dwAlignedAddressToMap;
			dwSizeToMap = DWORD_PTR(pSecHdr->Misc.VirtualSize + m_dwDeltaFileOffsetToMap);
			if ((LONGLONG)((DWORD_PTR)dwAlignedAddressToMap + dwSizeToMap) > m_stFileSize.QuadPart)
				return FILE_SECTION_DATA_CORRUPTED;

			if (!(m_lpSectionBase = MapViewOfFile(m_hMapObject, FILE_MAP_READ, 0, dwAlignedAddressToMap, dwSizeToMap)))
				return FILE_MAP_VIEW_OF_FILE_FAILED;

			m_dwMaxPointerBound = (DWORD_PTR)m_lpSectionBase + dwSizeToMap;
			getLoadConfigTable();
			UnmapViewOfFile(m_lpSectionBase);
		}

		if ((pSecHdr = getSecHdrFromRVA(getDirEntryRVA(IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT))))
		{
			m_dwFileOffsetToMap = pSecHdr->PointerToRawData;

			if (m_dwFileOffsetToMap % SysInfo.dwAllocationGranularity > 0)
			{
				dwAlignedAddressToMap = (m_dwFileOffsetToMap < SysInfo.dwAllocationGranularity) ? 0 :
					(m_dwFileOffsetToMap - (m_dwFileOffsetToMap % SysInfo.dwAllocationGranularity));
			}
			else
				dwAlignedAddressToMap = m_dwFileOffsetToMap;

			m_dwDeltaFileOffsetToMap = m_dwFileOffsetToMap - dwAlignedAddressToMap;
			dwSizeToMap = DWORD_PTR(pSecHdr->Misc.VirtualSize + m_dwDeltaFileOffsetToMap);
			if ((LONGLONG)((DWORD_PTR)dwAlignedAddressToMap + dwSizeToMap) > m_stFileSize.QuadPart)
				return FILE_SECTION_DATA_CORRUPTED;

			if (!(m_lpSectionBase = MapViewOfFile(m_hMapObject, FILE_MAP_READ, 0, dwAlignedAddressToMap, dwSizeToMap)))
				return FILE_MAP_VIEW_OF_FILE_FAILED;

			m_dwMaxPointerBound = (DWORD_PTR)m_lpSectionBase + dwSizeToMap;
			getBoundImportTable();
			UnmapViewOfFile(m_lpSectionBase);
		}

		if ((pSecHdr = getSecHdrFromRVA(getDirEntryRVA(IMAGE_DIRECTORY_ENTRY_IAT))))
			getIATTable();

		if ((pSecHdr = getSecHdrFromRVA(getDirEntryRVA(IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT))))
		{
			m_dwFileOffsetToMap = pSecHdr->PointerToRawData;

			if (m_dwFileOffsetToMap % SysInfo.dwAllocationGranularity > 0)
			{
				dwAlignedAddressToMap = (m_dwFileOffsetToMap < SysInfo.dwAllocationGranularity) ? 0 :
					(m_dwFileOffsetToMap - (m_dwFileOffsetToMap % SysInfo.dwAllocationGranularity));
			}
			else
				dwAlignedAddressToMap = m_dwFileOffsetToMap;

			m_dwDeltaFileOffsetToMap = m_dwFileOffsetToMap - dwAlignedAddressToMap;
			dwSizeToMap = DWORD_PTR(pSecHdr->Misc.VirtualSize + m_dwDeltaFileOffsetToMap);
			if ((LONGLONG)((DWORD_PTR)dwAlignedAddressToMap + dwSizeToMap) > m_stFileSize.QuadPart)
				return FILE_SECTION_DATA_CORRUPTED;

			if (!(m_lpSectionBase = MapViewOfFile(m_hMapObject, FILE_MAP_READ, 0, dwAlignedAddressToMap, dwSizeToMap)))
				return FILE_MAP_VIEW_OF_FILE_FAILED;

			m_dwMaxPointerBound = (DWORD_PTR)m_lpSectionBase + dwSizeToMap;
			getDelayImportTable();
			UnmapViewOfFile(m_lpSectionBase);
		}
	}

	UnmapViewOfFile(m_lpBase);
	CloseHandle(m_hMapObject);
	CloseHandle(hFile);

	return S_OK;
}

HRESULT Clibpe::GetFileSummary(PCDWORD* pdwFileSummary)
{
	if (!m_fLoaded)
		return CALL_LOADPE_FIRST;

	*pdwFileSummary = &m_dwFileSummary;

	return S_OK;
}

HRESULT Clibpe::GetMSDOSHeader(PCLIBPE_DOSHEADER* pDosHeader)
{
	if (!m_fLoaded)
		return CALL_LOADPE_FIRST;

	if (!IMAGE_HAS_FLAG(m_dwFileSummary, IMAGE_DOS_HEADER_FLAG))
		return IMAGE_HAS_NO_DOS_HEADER;

	*pDosHeader = &m_stDOSHeader;

	return S_OK;
}

HRESULT Clibpe::GetRichHeader(PCLIBPE_RICHHEADER_VEC* pVecRich)
{
	if (!m_fLoaded)
		return CALL_LOADPE_FIRST;

	if (!IMAGE_HAS_FLAG(m_dwFileSummary, IMAGE_RICH_HEADER_FLAG))
		return IMAGE_HAS_NO_RICH_HEADER;

	*pVecRich = &m_vecRichHeader;

	return S_OK;
}

HRESULT Clibpe::GetNTHeader(PCLIBPE_NTHEADER_TUP *pTupNTHeader)
{
	if (!m_fLoaded)
		return CALL_LOADPE_FIRST;

	if (!IMAGE_HAS_FLAG(m_dwFileSummary, IMAGE_NT_HEADER_FLAG))
		return IMAGE_HAS_NO_NT_HEADER;

	*pTupNTHeader = &m_tupNTHeader;

	return S_OK;
}

HRESULT Clibpe::GetFileHeader(PCLIBPE_FILEHEADER* pFileHeader)
{
	if (!m_fLoaded)
		return CALL_LOADPE_FIRST;

	if (!IMAGE_HAS_FLAG(m_dwFileSummary, IMAGE_FILE_HEADER_FLAG))
		return IMAGE_HAS_NO_FILE_HEADER;

	*pFileHeader = &m_stFileHeader;

	return S_OK;
}

HRESULT Clibpe::GetOptionalHeader(PCLIBPE_OPTHEADER_TUP* pTupOptHeader)
{
	if (!m_fLoaded)
		return CALL_LOADPE_FIRST;

	if (!IMAGE_HAS_FLAG(m_dwFileSummary, IMAGE_OPTIONAL_HEADER_FLAG))
		return IMAGE_HAS_NO_OPTIONAL_HEADER;

	*pTupOptHeader = &m_tupOptionalHeader;

	return S_OK;
}

HRESULT Clibpe::GetDataDirectories(PCLIBPE_DATADIRS_VEC* pVecDataDir)
{
	if (!m_fLoaded)
		return CALL_LOADPE_FIRST;

	if (!IMAGE_HAS_FLAG(m_dwFileSummary, IMAGE_DATA_DIRECTORIES_FLAG))
		return IMAGE_HAS_NO_DATA_DIRECTORIES;

	*pVecDataDir = &m_vecDataDirectories;

	return S_OK;
}

HRESULT Clibpe::GetSectionsHeaders(PCLIBPE_SECHEADERS_VEC* pVecSections)
{
	if (!m_fLoaded)
		return CALL_LOADPE_FIRST;

	if (!IMAGE_HAS_FLAG(m_dwFileSummary, IMAGE_SECTION_HEADERS_FLAG))
		return IMAGE_HAS_NO_SECTIONS;

	*pVecSections = &m_vecSectionHeaders;

	return S_OK;
}

HRESULT Clibpe::GetExportTable(PCLIBPE_EXPORT_TUP* pTupExport)
{
	if (!m_fLoaded)
		return CALL_LOADPE_FIRST;

	if (!IMAGE_HAS_FLAG(m_dwFileSummary, IMAGE_EXPORT_DIRECTORY_FLAG))
		return IMAGE_HAS_NO_EXPORT_DIR;

	*pTupExport = &m_tupExport;

	return S_OK;
}

HRESULT Clibpe::GetImportTable(PCLIBPE_IMPORT_VEC* pVecImport)
{
	if (!m_fLoaded)
		return CALL_LOADPE_FIRST;

	if (!IMAGE_HAS_FLAG(m_dwFileSummary, IMAGE_IMPORT_DIRECTORY_FLAG))
		return IMAGE_HAS_NO_IMPORT_DIR;

	*pVecImport = &m_vecImportTable;

	return S_OK;
}

HRESULT Clibpe::GetResourceTable(PCLIBPE_RESOURCE_ROOT_TUP* pTupRes)
{
	if (!m_fLoaded)
		return CALL_LOADPE_FIRST;

	if (!IMAGE_HAS_FLAG(m_dwFileSummary, IMAGE_RESOURCE_DIRECTORY_FLAG))
		return IMAGE_HAS_NO_RESOURCE_DIR;

	*pTupRes = &m_tupResourceTable;

	return S_OK;
}

HRESULT Clibpe::GetExceptionTable(PCLIBPE_EXCEPTION_VEC* pVecException)
{
	if (!m_fLoaded)
		return CALL_LOADPE_FIRST;

	if (!IMAGE_HAS_FLAG(m_dwFileSummary, IMAGE_EXCEPTION_DIRECTORY_FLAG))
		return IMAGE_HAS_NO_EXCEPTION_DIR;

	*pVecException = &m_vecExceptionTable;

	return S_OK;

}

HRESULT Clibpe::GetSecurityTable(PCLIBPE_SECURITY_VEC* pVecSecurity)
{
	if (!m_fLoaded)
		return CALL_LOADPE_FIRST;

	if (!IMAGE_HAS_FLAG(m_dwFileSummary, IMAGE_SECURITY_DIRECTORY_FLAG))
		return IMAGE_HAS_NO_ARCHITECTURE_DIR;

	*pVecSecurity = &m_vecSecurity;

	return S_OK;
}

HRESULT Clibpe::GetRelocationTable(PCLIBPE_RELOCATION_VEC* pVecRelocs)
{
	if (!m_fLoaded)
		return CALL_LOADPE_FIRST;

	if (!IMAGE_HAS_FLAG(m_dwFileSummary, IMAGE_BASERELOC_DIRECTORY_FLAG))
		return IMAGE_HAS_NO_GLOBALPTR_DIR;

	*pVecRelocs = &m_vecRelocationTable;

	return S_OK;
}

HRESULT Clibpe::GetDebugTable(PCLIBPE_DEBUG_VEC* pVecDebug)
{
	if (!m_fLoaded)
		return CALL_LOADPE_FIRST;

	if (!IMAGE_HAS_FLAG(m_dwFileSummary, IMAGE_DEBUG_DIRECTORY_FLAG))
		return IMAGE_HAS_NO_DEBUG_DIR;

	*pVecDebug = &m_vecDebugTable;

	return S_OK;
}

HRESULT Clibpe::GetTLSTable(PCLIBPE_TLS_TUP* pTupTLS)
{
	if (!m_fLoaded)
		return CALL_LOADPE_FIRST;

	if (!IMAGE_HAS_FLAG(m_dwFileSummary, IMAGE_TLS_DIRECTORY_FLAG))
		return IMAGE_HAS_NO_TLS_DIR;

	*pTupTLS = &m_tupTLS;

	return S_OK;
}

HRESULT Clibpe::GetLoadConfigTable(PCLIBPE_LOADCONFIGTABLE_TUP* pTupLCD)
{
	if (!m_fLoaded)
		return CALL_LOADPE_FIRST;

	if (!IMAGE_HAS_FLAG(m_dwFileSummary, IMAGE_LOADCONFIG_DIRECTORY_FLAG))
		return IMAGE_HAS_NO_LOADCONFIG_DIR;

	*pTupLCD = &m_tupLoadConfigDir;

	return S_OK;
}

HRESULT Clibpe::GetBoundImportTable(PCLIBPE_BOUNDIMPORT_VEC* pVecBoundImp)
{
	if (!m_fLoaded)
		return CALL_LOADPE_FIRST;

	if (!IMAGE_HAS_FLAG(m_dwFileSummary, IMAGE_BOUNDIMPORT_DIRECTORY_FLAG))
		return IMAGE_HAS_NO_BOUNDIMPORT_DIR;

	*pVecBoundImp = &m_vecBoundImportTable;

	return S_OK;
}

HRESULT Clibpe::GetDelayImportTable(PCLIBPE_DELAYIMPORT_VEC* pVecDelayImport)
{
	if (!m_fLoaded)
		return CALL_LOADPE_FIRST;

	if (!IMAGE_HAS_FLAG(m_dwFileSummary, IMAGE_DELAYIMPORT_DIRECTORY_FLAG))
		return 	IMAGE_HAS_NO_DELAY_IMPORT_DIR;

	*pVecDelayImport = &m_vecDelayImportTable;

	return S_OK;
}

HRESULT Clibpe::GetCOMDescriptorTable(PCLIBPE_COMDESCRIPTOR* pTupCOMDescriptor)
{
	if (!m_fLoaded)
		return CALL_LOADPE_FIRST;

	if (!IMAGE_HAS_FLAG(m_dwFileSummary, IMAGE_COMDESCRIPTOR_DIRECTORY_FLAG))
		return IMAGE_HAS_NO_COMDESCRIPTOR_DIR;

	*pTupCOMDescriptor = &m_stCOR20Header;

	return S_OK;
}

HRESULT Clibpe::Release()
{
	delete this;

	return S_OK;
}


PIMAGE_SECTION_HEADER Clibpe::getSecHdrFromRVA(ULONGLONG ullRVA) const
{
	PIMAGE_SECTION_HEADER pSecHdr;

	if (IMAGE_HAS_FLAG(m_dwFileSummary, IMAGE_PE32_FLAG))
	{
		pSecHdr = IMAGE_FIRST_SECTION(m_pNTHeader32);
		for (unsigned i = 0; i < m_pNTHeader32->FileHeader.NumberOfSections; i++, pSecHdr++)
		{
			if (!isPtrSafe(pSecHdr))
				return nullptr;
			//Is RVA within this section?
			if ((ullRVA >= pSecHdr->VirtualAddress) && (ullRVA < (pSecHdr->VirtualAddress + pSecHdr->Misc.VirtualSize)))
				return pSecHdr;
		}
	}
	else if (IMAGE_HAS_FLAG(m_dwFileSummary, IMAGE_PE64_FLAG))
	{
		pSecHdr = IMAGE_FIRST_SECTION(m_pNTHeader64);
		for (unsigned i = 0; i < m_pNTHeader64->FileHeader.NumberOfSections; i++, pSecHdr++)
		{
			if (!isPtrSafe(pSecHdr))
				return nullptr;
			if ((ullRVA >= pSecHdr->VirtualAddress) && (ullRVA < (pSecHdr->VirtualAddress + pSecHdr->Misc.VirtualSize)))
				return pSecHdr;
		}
	}

	return nullptr;
}

PIMAGE_SECTION_HEADER Clibpe::getSecHdrFromName(LPCSTR lpszName) const
{
	PIMAGE_SECTION_HEADER pSecHdr;

	if (IMAGE_HAS_FLAG(m_dwFileSummary, IMAGE_PE32_FLAG))
	{
		pSecHdr = IMAGE_FIRST_SECTION(m_pNTHeader32);

		for (unsigned i = 0; i < m_pNTHeader32->FileHeader.NumberOfSections; i++, pSecHdr++)
		{
			if (!isPtrSafe(pSecHdr))
				break;
			if (strncmp((char*)pSecHdr->Name, lpszName, IMAGE_SIZEOF_SHORT_NAME) == 0)
				return pSecHdr;
		}
	}
	else if (IMAGE_HAS_FLAG(m_dwFileSummary, IMAGE_PE64_FLAG))
	{
		pSecHdr = IMAGE_FIRST_SECTION(m_pNTHeader64);

		for (unsigned i = 0; i < m_pNTHeader64->FileHeader.NumberOfSections; i++, pSecHdr++)
		{
			if (!isPtrSafe(pSecHdr))
				break;
			if (strncmp((char*)pSecHdr->Name, lpszName, IMAGE_SIZEOF_SHORT_NAME) == 0)
				return pSecHdr;
		}
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
	{
		ptr = (LPVOID)((DWORD_PTR)m_lpBase + ullRVA - (DWORD_PTR)(pSecHdr->VirtualAddress - pSecHdr->PointerToRawData));
		return isPtrSafe(ptr, true) ? ptr : nullptr;
	}
	else
	{
		ptr = (LPVOID)((DWORD_PTR)m_lpSectionBase + (DWORD_PTR)m_dwDeltaFileOffsetToMap +
			(ullRVA - (DWORD_PTR)(pSecHdr->VirtualAddress - pSecHdr->PointerToRawData) - m_dwFileOffsetToMap));
		return isPtrSafe(ptr, true) ? ptr : nullptr;
	}
}

DWORD Clibpe::getDirEntryRVA(UINT uiDirEntry) const
{
	if (IMAGE_HAS_FLAG(m_dwFileSummary, IMAGE_PE32_FLAG))
		return m_pNTHeader32->OptionalHeader.DataDirectory[uiDirEntry].VirtualAddress;
	else if (IMAGE_HAS_FLAG(m_dwFileSummary, IMAGE_PE64_FLAG))
		return m_pNTHeader64->OptionalHeader.DataDirectory[uiDirEntry].VirtualAddress;

	return 0;
}

DWORD Clibpe::getDirEntrySize(UINT uiDirEntry) const
{
	if (IMAGE_HAS_FLAG(m_dwFileSummary, IMAGE_PE32_FLAG))
		return m_pNTHeader32->OptionalHeader.DataDirectory[uiDirEntry].Size;
	else if (IMAGE_HAS_FLAG(m_dwFileSummary, IMAGE_PE64_FLAG))
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
	std::get<2>(m_tupTLS).clear(); std::get<3>(m_tupTLS).clear();
	m_vecBoundImportTable.clear();
	m_vecDelayImportTable.clear();
}

/********************************************
* Acquiring all standart headers from PE.	*
********************************************/
HRESULT Clibpe::getHeaders()
{
	m_pDosHeader = (PIMAGE_DOS_HEADER)m_lpBase;

	if (m_pDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
		return IMAGE_DOS_SIGNATURE_MISMATCH;

	//If file has at least MSDOS header's signature
	//then we can assume that this is a minimum correct 
	//PE file and process further.
	m_stDOSHeader = *m_pDosHeader;
	m_dwFileSummary |= IMAGE_DOS_HEADER_FLAG;
	m_fLoaded = true;

	getRichHeader();

	if (((PIMAGE_NT_HEADERS32)((DWORD_PTR)m_pDosHeader + (DWORD_PTR)m_pDosHeader->e_lfanew))->Signature != IMAGE_NT_SIGNATURE)
		return IMAGE_NT_SIGNATURE_MISMATCH;

	switch (((PIMAGE_NT_HEADERS32)((DWORD_PTR)m_pDosHeader + (DWORD_PTR)m_pDosHeader->e_lfanew))->OptionalHeader.Magic)
	{
	case IMAGE_NT_OPTIONAL_HDR32_MAGIC:
		m_dwFileSummary |= IMAGE_PE32_FLAG;
		m_pNTHeader32 = (PIMAGE_NT_HEADERS32)((DWORD_PTR)m_pDosHeader + (DWORD_PTR)m_pDosHeader->e_lfanew);
		m_tupNTHeader = { *m_pNTHeader32, IMAGE_NT_HEADERS64 { } };
		m_stFileHeader = m_pNTHeader32->FileHeader;
		m_tupOptionalHeader = { m_pNTHeader32->OptionalHeader, IMAGE_OPTIONAL_HEADER64 { } };
		break;
	case  IMAGE_NT_OPTIONAL_HDR64_MAGIC:
		m_dwFileSummary |= IMAGE_PE64_FLAG;
		m_pNTHeader64 = (PIMAGE_NT_HEADERS64)((DWORD_PTR)m_pDosHeader + (DWORD_PTR)m_pDosHeader->e_lfanew);
		m_tupNTHeader = { IMAGE_NT_HEADERS32 { }, *m_pNTHeader64 };
		m_stFileHeader = m_pNTHeader64->FileHeader;
		m_tupOptionalHeader = { IMAGE_OPTIONAL_HEADER32 { }, m_pNTHeader64->OptionalHeader };
		break;
	case  IMAGE_ROM_OPTIONAL_HDR_MAGIC:
		break;
		//not implemented yet
	default:
		return IMAGE_TYPE_UNSUPPORTED;
	}

	m_dwFileSummary |= IMAGE_NT_HEADER_FLAG | IMAGE_FILE_HEADER_FLAG | IMAGE_OPTIONAL_HEADER_FLAG;

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
	if (m_pDosHeader->e_lfanew <= 0x80)
		return IMAGE_HAS_NO_RICH_HEADER;

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
			const DWORD dwRichXORMask = *(pRichIter + 1);//XOR mask of «Rich» header.
			pRichIter = (PDWORD)((DWORD_PTR)m_pDosHeader + 0x90);//VA of «Rich» DOUBLE_DWORD structs start.

			for (unsigned j = 0; j < dwRichSize; j++)
			{
				//Pushing double DWORD of «Rich» structure.
				//Disassembling first DWORD by two WORDs.
				m_vecRichHeader.emplace_back(HIWORD(dwRichXORMask ^ *pRichIter),
					LOWORD(dwRichXORMask ^ *pRichIter), dwRichXORMask ^ *(pRichIter + 1));
				pRichIter += 2; //Jump to the next DOUBLE_DWORD.
			}

			m_dwFileSummary |= IMAGE_RICH_HEADER_FLAG;

			return S_OK;
		}
	}

	return IMAGE_HAS_NO_RICH_HEADER;
}

HRESULT Clibpe::getDataDirectories()
{
	PIMAGE_DATA_DIRECTORY pDataDir;
	PIMAGE_SECTION_HEADER pSecHdr;
	std::string strSecName { };

	if (IMAGE_HAS_FLAG(m_dwFileSummary, IMAGE_PE32_FLAG))
	{
		pDataDir = (PIMAGE_DATA_DIRECTORY)m_pNTHeader32->OptionalHeader.DataDirectory;

		//Filling DataDirectories vector.
		for (unsigned i = 0; i < (m_pNTHeader32->OptionalHeader.NumberOfRvaAndSizes > 15 ?
			15 : m_pNTHeader32->OptionalHeader.NumberOfRvaAndSizes); i++, pDataDir++)
		{
			pSecHdr = getSecHdrFromRVA(pDataDir->VirtualAddress);
			//RVA of IMAGE_DIRECTORY_ENTRY_SECURITY is file RAW offset.
			if (pSecHdr && (i != IMAGE_DIRECTORY_ENTRY_SECURITY))
				strSecName.assign((char * const)pSecHdr->Name, 8);

			m_vecDataDirectories.emplace_back(*pDataDir, std::move(strSecName));
			strSecName.clear();
		}
	}
	else if (IMAGE_HAS_FLAG(m_dwFileSummary, IMAGE_PE64_FLAG))
	{
		pDataDir = (PIMAGE_DATA_DIRECTORY)m_pNTHeader64->OptionalHeader.DataDirectory;

		for (unsigned i = 0; i < (m_pNTHeader64->OptionalHeader.NumberOfRvaAndSizes > 15 ?
			15 : m_pNTHeader64->OptionalHeader.NumberOfRvaAndSizes); i++, pDataDir++)
		{
			pSecHdr = getSecHdrFromRVA(pDataDir->VirtualAddress);
			if (pSecHdr && (i != IMAGE_DIRECTORY_ENTRY_SECURITY))
				strSecName.assign((char * const)pSecHdr->Name, 8);

			m_vecDataDirectories.emplace_back(*pDataDir, std::move(strSecName));
			strSecName.clear();
		}
	}
	if (m_vecDataDirectories.empty())
		return IMAGE_HAS_NO_DATA_DIRECTORIES;

	m_dwFileSummary |= IMAGE_DATA_DIRECTORIES_FLAG;

	return S_OK;
}

HRESULT Clibpe::getSectionsHeaders()
{
	PIMAGE_SECTION_HEADER pSecHdr;
	std::string strSecRealName { };

	if (IMAGE_HAS_FLAG(m_dwFileSummary, IMAGE_PE32_FLAG))
	{
		pSecHdr = IMAGE_FIRST_SECTION(m_pNTHeader32);
		m_vecSectionHeaders.reserve(m_pNTHeader32->FileHeader.NumberOfSections);

		for (unsigned i = 0; i < m_pNTHeader32->FileHeader.NumberOfSections; i++, pSecHdr++)
		{
			if (!isPtrSafe(pSecHdr))
				break;

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
					const char* lpszSecRealName = (const char*)((DWORD_PTR)m_lpBase + (DWORD_PTR)m_pNTHeader32->FileHeader.PointerToSymbolTable +
						(DWORD_PTR)m_pNTHeader32->FileHeader.NumberOfSymbols * 18 + (DWORD_PTR)lOffset);
					if (isPtrSafe(lpszSecRealName))
						strSecRealName = lpszSecRealName;
				}
			}

			m_vecSectionHeaders.emplace_back(*pSecHdr, std::move(strSecRealName));
			strSecRealName.clear();
		}
	}
	else if (IMAGE_HAS_FLAG(m_dwFileSummary, IMAGE_PE64_FLAG))
	{
		pSecHdr = IMAGE_FIRST_SECTION(m_pNTHeader64);
		m_vecSectionHeaders.reserve(m_pNTHeader64->FileHeader.NumberOfSections);

		for (unsigned i = 0; i < m_pNTHeader64->FileHeader.NumberOfSections; i++, pSecHdr++)
		{
			if (!isPtrSafe(pSecHdr))
				break;

			if (pSecHdr->Name[0] == '/')
			{
				const long lOffset = strtol((const char*)&pSecHdr->Name[1], nullptr, 10);
				if (lOffset != LONG_MAX && lOffset != LONG_MIN && lOffset != 0)
				{
					const char* lpszSecRealName = (const char*)((DWORD_PTR)m_lpBase + (DWORD_PTR)m_pNTHeader64->FileHeader.PointerToSymbolTable +
						(DWORD_PTR)m_pNTHeader64->FileHeader.NumberOfSymbols * 18 + (DWORD_PTR)lOffset);
					if (isPtrSafe(lpszSecRealName))
						strSecRealName = lpszSecRealName;
				}
			}

			m_vecSectionHeaders.emplace_back(*pSecHdr, std::move(strSecRealName));
			strSecRealName.clear();
		}
	}

	if (m_vecSectionHeaders.empty())
		return IMAGE_HAS_NO_SECTIONS;

	m_dwFileSummary |= IMAGE_SECTION_HEADERS_FLAG;

	return S_OK;
}

HRESULT Clibpe::getExportTable()
{
	const DWORD dwExportStartRVA = getDirEntryRVA(IMAGE_DIRECTORY_ENTRY_EXPORT);
	const DWORD dwExportEndRVA = dwExportStartRVA + getDirEntrySize(IMAGE_DIRECTORY_ENTRY_EXPORT);

	const PIMAGE_EXPORT_DIRECTORY pExportDir = (PIMAGE_EXPORT_DIRECTORY)rVAToPtr(dwExportStartRVA);
	if (!pExportDir)
		return IMAGE_HAS_NO_EXPORT_DIR;

	const PDWORD pFuncs = (PDWORD)rVAToPtr(pExportDir->AddressOfFunctions);
	if (!pFuncs)
		return IMAGE_HAS_NO_EXPORT_DIR;

	std::vector<std::tuple<DWORD/*Exported func RVA/Forwarder RVA*/, DWORD/*func Ordinal*/, std::string /*Func Name*/,
		std::string/*Forwarder func name*/>> vecFuncs { };
	std::string strFuncName { }, strFuncNameForwarder { }, strExportName { };
	const PWORD pOrdinals = (PWORD)rVAToPtr(pExportDir->AddressOfNameOrdinals);
	LPCSTR* szNames = (LPCSTR*)rVAToPtr(pExportDir->AddressOfNames);

	try {

		vecFuncs.reserve(pExportDir->NumberOfFunctions);
		for (DWORD iterFuncs = 0; iterFuncs < pExportDir->NumberOfFunctions; iterFuncs++)
		{
			if (pFuncs[iterFuncs]) //if RVA==0 —> going next entry.
			{
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
				strFuncName.clear();
				strFuncNameForwarder.clear();
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
		delete [] m_lpszEmergencyMemory;
		MessageBox(nullptr, L"E_OUTOFMEMORY error while trying to get Export table.\nFile seems to be corrupted.",
			L"Error", MB_ICONERROR);

		vecFuncs.clear();
		m_lpszEmergencyMemory = new char[0x8FFF];
	}
	catch (...)
	{
		MessageBox(nullptr, L"Unknown exception raised while trying to get Export table.\r\nFile seems to be corrupted.",
			L"Error", MB_ICONERROR);
	}

	m_dwFileSummary |= IMAGE_EXPORT_DIRECTORY_FLAG;

	return S_OK;
}

HRESULT Clibpe::getImportTable()
{
	PIMAGE_IMPORT_DESCRIPTOR pImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)rVAToPtr(getDirEntryRVA(IMAGE_DIRECTORY_ENTRY_IMPORT));

	if (!pImportDescriptor)
		return IMAGE_HAS_NO_IMPORT_DIR;

	const DWORD dwTLSDirRVA = getDirEntryRVA(IMAGE_DIRECTORY_ENTRY_TLS);
	std::vector<std::tuple<LONGLONG/*Ordinal/Hint*/, std::string/*Func name*/, LONGLONG/*Thunk table RVA*/>> vecFunc { };
	std::string strDllName { }, strFuncName { };

	try {
		if (IMAGE_HAS_FLAG(m_dwFileSummary, IMAGE_PE32_FLAG))
		{
			const PIMAGE_TLS_DIRECTORY32 pTLSDir32 = (PIMAGE_TLS_DIRECTORY32)rVAToPtr(dwTLSDirRVA);

			while (pImportDescriptor->Name)
			{
				//Checking for TLS Index patching trick, to fade out fake imports.
					//The trick is: OS loader, while loading PE file, patches address in memory 
					//that is pointed at by PIMAGE_TLS_DIRECTORY->AddressOfIndex.
					//If at this address file had, say, Import descriptor with fake imports
					//it will be zeroed, and PE file will be executed just fine.
					//But trying to read this fake Import descriptor from file on disk
					//may lead to many "interesting" things. Import table can be enormous,
					//with absolutely unreadable import names.
				if (pTLSDir32 && pTLSDir32->AddressOfIndex && (((DWORD_PTR)pImportDescriptor + offsetof(IMAGE_IMPORT_DESCRIPTOR, FirstThunk)) ==
					(DWORD_PTR)rVAToPtr(pTLSDir32->AddressOfIndex - m_pNTHeader32->OptionalHeader.ImageBase) ||
					((DWORD_PTR)pImportDescriptor + offsetof(IMAGE_IMPORT_DESCRIPTOR, Name)) ==
					(DWORD_PTR)rVAToPtr(pTLSDir32->AddressOfIndex - m_pNTHeader32->OptionalHeader.ImageBase)))
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
						return IMAGE_HAS_NO_IMPORT_DIR;

					while (pThunk32->u1.AddressOfData)
					{
						if (pThunk32->u1.Ordinal & IMAGE_ORDINAL_FLAG32)
							//If funcs are imported only by ordinals then filling only ordinal leaving Name as "".
							vecFunc.emplace_back(IMAGE_ORDINAL32(pThunk32->u1.Ordinal), "", pThunk32->u1.AddressOfData);
						else
						{	//Filling Hint, Name and Thunk RVA.
							const PIMAGE_IMPORT_BY_NAME pName = (PIMAGE_IMPORT_BY_NAME)rVAToPtr(pThunk32->u1.AddressOfData);
							if (pName && (StringCchLengthA(pName->Name, MAX_PATH, nullptr) != STRSAFE_E_INVALID_PARAMETER))
								strFuncName = pName->Name;

							vecFunc.emplace_back(pName ? pName->Hint : 0, std::move(strFuncName), pThunk32->u1.AddressOfData);
							strFuncName.clear();
						}
						if (!isPtrSafe(++pThunk32)) {
							return IMAGE_HAS_NO_IMPORT_DIR;
						}
					}
					const LPCSTR szName = (LPCSTR)rVAToPtr(pImportDescriptor->Name);
					if (szName && (StringCchLengthA(szName, MAX_PATH, nullptr) != STRSAFE_E_INVALID_PARAMETER))
						strDllName = szName;

					m_vecImportTable.emplace_back(*pImportDescriptor, std::move(strDllName), std::move(vecFunc));
					vecFunc.clear();
					strDllName.clear();

					if (!isPtrSafe(++pImportDescriptor))
						return IMAGE_HAS_NO_IMPORT_DIR;
				}
				else //No IMPORT pointers for that DLL?...
					if (!isPtrSafe(++pImportDescriptor))  //Going next dll.
						return IMAGE_HAS_NO_IMPORT_DIR;
			}
		}
		else if (IMAGE_HAS_FLAG(m_dwFileSummary, IMAGE_PE64_FLAG))
		{
			const PIMAGE_TLS_DIRECTORY64 pTLSDir64 = (PIMAGE_TLS_DIRECTORY64)rVAToPtr(dwTLSDirRVA);

			while (pImportDescriptor->Name)
			{
				if (pTLSDir64 && pTLSDir64->AddressOfIndex && (((DWORD_PTR)pImportDescriptor + offsetof(IMAGE_IMPORT_DESCRIPTOR, FirstThunk)) ==
					(DWORD_PTR)rVAToPtr(pTLSDir64->AddressOfIndex - m_pNTHeader64->OptionalHeader.ImageBase) ||
					((DWORD_PTR)pImportDescriptor + offsetof(IMAGE_IMPORT_DESCRIPTOR, Name)) ==
					(DWORD_PTR)rVAToPtr(pTLSDir64->AddressOfIndex - m_pNTHeader64->OptionalHeader.ImageBase)))
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
					if (pTLSDir64 && ((DWORD_PTR)pThunk64 >= (pTLSDir64->AddressOfIndex - m_pNTHeader64->OptionalHeader.ImageBase)))
					{
						m_vecImportTable.emplace_back(*pImportDescriptor, "(fake import stripped)", std::move(vecFunc));
						break;
					}

					pThunk64 = (PIMAGE_THUNK_DATA64)rVAToPtr((DWORD_PTR)pThunk64);
					if (!pThunk64)
						return IMAGE_HAS_NO_IMPORT_DIR;

					while (pThunk64->u1.AddressOfData)
					{
						if (pThunk64->u1.Ordinal & IMAGE_ORDINAL_FLAG64)
							//If funcs are imported only by ordinals then filling only ordinal leaving Name as "".
							vecFunc.emplace_back(IMAGE_ORDINAL64(pThunk64->u1.Ordinal), "", pThunk64->u1.AddressOfData);
						else
						{	//Filling Hint, Name and Thunk RVA.
							const PIMAGE_IMPORT_BY_NAME pName = (PIMAGE_IMPORT_BY_NAME)rVAToPtr(pThunk64->u1.AddressOfData);
							if (pName && (StringCchLengthA(pName->Name, MAX_PATH, nullptr) != STRSAFE_E_INVALID_PARAMETER))
								strFuncName = pName->Name;

							vecFunc.emplace_back(pName ? pName->Hint : 0, std::move(strFuncName), pThunk64->u1.AddressOfData);
							strFuncName.clear();
						}
						pThunk64++;
					}

					const LPCSTR szName = (LPCSTR)rVAToPtr(pImportDescriptor->Name);
					if (szName && (StringCchLengthA(szName, MAX_PATH, nullptr) != STRSAFE_E_INVALID_PARAMETER))
						strDllName = szName;

					m_vecImportTable.emplace_back(*pImportDescriptor, std::move(strDllName), std::move(vecFunc));
					vecFunc.clear();
					strDllName.clear();

					if (!isPtrSafe(++pImportDescriptor))
						return IMAGE_HAS_NO_IMPORT_DIR;
				}
				else
					if (!isPtrSafe(++pImportDescriptor))
						return IMAGE_HAS_NO_IMPORT_DIR;
			}
		}
	}
	catch (const std::bad_alloc&)
	{
		delete [] m_lpszEmergencyMemory;
		MessageBox(nullptr, L"E_OUTOFMEMORY error while trying to get Import table.\r\n"
			L"Too many import entries!\nFile seems to be corrupted.", L"Error", MB_ICONERROR);

		vecFunc.clear();
		m_vecImportTable.clear();
		m_lpszEmergencyMemory = new char[0x8FFF];
	}
	catch (...)
	{
		MessageBox(nullptr, L"Unknown exception raised while trying to get Import table.\r\nFile seems to be corrupted.",
			L"Error", MB_ICONERROR);
	}

	m_dwFileSummary |= IMAGE_IMPORT_DIRECTORY_FLAG;

	return S_OK;
}

HRESULT Clibpe::getResourceTable()
{
	PIMAGE_RESOURCE_DIRECTORY pRootResDir = (PIMAGE_RESOURCE_DIRECTORY)rVAToPtr(getDirEntryRVA(IMAGE_DIRECTORY_ENTRY_RESOURCE));

	if (!pRootResDir)
		return IMAGE_HAS_NO_RESOURCE_DIR;

	PIMAGE_RESOURCE_DIRECTORY_ENTRY pRootResDirEntry = (PIMAGE_RESOURCE_DIRECTORY_ENTRY)(pRootResDir + 1);
	std::wstring strRootResName { }, strSecondResName { }, strThirdResName { };

	LIBPE_RESOURCE_ROOT_VEC vecResLvLRoot { };
	LIBPE_RESOURCE_LVL2_TUP tupResLvL2 { };
	LIBPE_RESOURCE_LVL2_VEC vecResLvL2 { };
	LIBPE_RESOURCE_LVL3_TUP tupResLvL3 { };
	LIBPE_RESOURCE_LVL3_VEC vecResLvL3 { };
	PIMAGE_RESOURCE_DIR_STRING_U pResDirStr;

	try {
		vecResLvLRoot.reserve(pRootResDir->NumberOfNamedEntries + pRootResDir->NumberOfIdEntries);
		for (int iLvL1 = 0; iLvL1 < pRootResDir->NumberOfNamedEntries + pRootResDir->NumberOfIdEntries; iLvL1++)
		{
			PIMAGE_RESOURCE_DATA_ENTRY pRootResDataEntry { };
			std::vector<std::byte> vecRootResRawData { };

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

				if (!isPtrSafe(pSecondResDir))
					return IMAGE_HAS_NO_RESOURCE_DIR;
				if (pSecondResDir == pRootResDir /*Resource loop hack*/)
					tupResLvL2 = { *pSecondResDir, vecResLvL2 };
				else
				{
					PIMAGE_RESOURCE_DIRECTORY_ENTRY pSecondResDirEntry = (PIMAGE_RESOURCE_DIRECTORY_ENTRY)(pSecondResDir + 1);
					vecResLvL2.reserve(pSecondResDir->NumberOfNamedEntries + pSecondResDir->NumberOfIdEntries);
					for (int iLvL2 = 0; iLvL2 < pSecondResDir->NumberOfNamedEntries + pSecondResDir->NumberOfIdEntries; iLvL2++)
					{
						PIMAGE_RESOURCE_DATA_ENTRY pSecondResDataEntry { };
						std::vector<std::byte> vecSecondResRawData { };

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
							if (!isPtrSafe(pThirdResDir))
								return IMAGE_HAS_NO_RESOURCE_DIR;
							if (pThirdResDir == pSecondResDir || pThirdResDir == pRootResDir)
								tupResLvL3 = { *pThirdResDir, vecResLvL3 };
							else
							{
								PIMAGE_RESOURCE_DIRECTORY_ENTRY pThirdResDirEntry = (PIMAGE_RESOURCE_DIRECTORY_ENTRY)(pThirdResDir + 1);
								vecResLvL3.reserve(pThirdResDir->NumberOfNamedEntries + pThirdResDir->NumberOfIdEntries);
								for (int iLvL3 = 0; iLvL3 < pThirdResDir->NumberOfNamedEntries + pThirdResDir->NumberOfIdEntries; iLvL3++)
								{
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

										PBYTE pThirdResRawDataBegin = (PBYTE)rVAToPtr(pThirdResDataEntry->OffsetToData);
										//Checking RAW Resource data pointer out of bounds.
										if (pThirdResRawDataBegin && isPtrSafe((DWORD_PTR)pThirdResRawDataBegin + (DWORD_PTR)pThirdResDataEntry->Size, true))
										{
											vecThirdResRawData.reserve(pThirdResDataEntry->Size);
											for (unsigned iterResRawData = 0; iterResRawData < pThirdResDataEntry->Size; iterResRawData++)
												vecThirdResRawData.push_back(std::byte(*(pThirdResRawDataBegin + iterResRawData)));
										}
									}

									vecResLvL3.emplace_back(*pThirdResDirEntry, std::move(strThirdResName),
										isPtrSafe(pThirdResDataEntry) ? *pThirdResDataEntry : IMAGE_RESOURCE_DATA_ENTRY { },
										std::move(vecThirdResRawData));
									vecThirdResRawData.clear();
									strThirdResName.clear();

									pThirdResDirEntry++;
								}
								tupResLvL3 = { *pThirdResDir, std::move(vecResLvL3) };
								vecResLvL3.clear();
							}
						}
						else
						{	//////Resource LvL2 RAW Data.
							pSecondResDataEntry = (PIMAGE_RESOURCE_DATA_ENTRY)((DWORD_PTR)pRootResDir + (DWORD_PTR)pSecondResDirEntry->OffsetToData);
							if (isPtrSafe(pSecondResDataEntry))
							{
								PBYTE pSecondResRawDataBegin = (PBYTE)rVAToPtr(pSecondResDataEntry->OffsetToData);
								//Checking RAW Resource data pointer out of bounds.
								if (pSecondResRawDataBegin && isPtrSafe((DWORD_PTR)pSecondResRawDataBegin + (DWORD_PTR)pSecondResDataEntry->Size, true))
								{
									vecSecondResRawData.reserve(pSecondResDataEntry->Size);
									for (unsigned iterResRawData = 0; iterResRawData < pSecondResDataEntry->Size; iterResRawData++)
										vecSecondResRawData.push_back(std::byte(*(pSecondResRawDataBegin + iterResRawData)));
								}
							}
						}
						vecResLvL2.emplace_back(*pSecondResDirEntry, std::move(strSecondResName),
							isPtrSafe(pSecondResDataEntry) ? *pSecondResDataEntry : IMAGE_RESOURCE_DATA_ENTRY { },
							std::move(vecSecondResRawData), tupResLvL3);
						vecSecondResRawData.clear();
						strSecondResName.clear();

						pSecondResDirEntry++;
					}
					tupResLvL2 = { *pSecondResDir, std::move(vecResLvL2) };
					vecResLvL2.clear();
				}
			}
			else
			{	//////Resource LvL Root RAW Data.
				pRootResDataEntry = (PIMAGE_RESOURCE_DATA_ENTRY)((DWORD_PTR)pRootResDir + (DWORD_PTR)pRootResDirEntry->OffsetToData);
				if (isPtrSafe(pRootResDataEntry))
				{
					PBYTE pRootResRawDataBegin = (PBYTE)rVAToPtr(pRootResDataEntry->OffsetToData);
					//Checking RAW Resource data pointer out of bounds.
					if (pRootResRawDataBegin && isPtrSafe((DWORD_PTR)pRootResRawDataBegin + (DWORD_PTR)pRootResDataEntry->Size, true))
					{
						vecRootResRawData.reserve(pRootResDataEntry->Size);
						for (unsigned iterResRawData = 0; iterResRawData < pRootResDataEntry->Size; iterResRawData++)
							vecRootResRawData.push_back(std::byte(*(pRootResRawDataBegin + iterResRawData)));
					}
				}
			}
			vecResLvLRoot.emplace_back(*pRootResDirEntry, std::move(strRootResName),
				isPtrSafe(pRootResDataEntry) ? *pRootResDataEntry : IMAGE_RESOURCE_DATA_ENTRY { },
				std::move(vecRootResRawData), tupResLvL2);
			vecRootResRawData.clear();
			strRootResName.clear();

			pRootResDirEntry++;
		}
		m_tupResourceTable = { *pRootResDir, std::move(vecResLvLRoot) };
		vecResLvLRoot.clear();
	}
	catch (const std::bad_alloc&)
	{
		delete [] m_lpszEmergencyMemory;
		MessageBox(nullptr, L"E_OUTOFMEMORY error while trying to get Resource table.\nFile seems to be corrupted.",
			L"Error", MB_ICONERROR);

		vecResLvLRoot.clear();
		vecResLvL2.clear();
		vecResLvL3.clear();
		m_lpszEmergencyMemory = new char[0x8FFF];
	}
	catch (...)
	{
		MessageBox(nullptr, L"Unknown exception raised while trying to get Resource table.\r\n\nFile seems to be corrupted.",
			L"Error", MB_ICONERROR);
	}

	m_dwFileSummary |= IMAGE_RESOURCE_DIRECTORY_FLAG;

	return S_OK;
}

HRESULT Clibpe::getExceptionTable()
{
	//IMAGE_RUNTIME_FUNCTION_ENTRY (without leading underscore) 
	//might have different typedef depending on defined platform, see winnt.h
	_PIMAGE_RUNTIME_FUNCTION_ENTRY pRuntimeFuncsEntry = (_PIMAGE_RUNTIME_FUNCTION_ENTRY)rVAToPtr(getDirEntryRVA(IMAGE_DIRECTORY_ENTRY_EXCEPTION));
	if (!pRuntimeFuncsEntry)
		return IMAGE_HAS_NO_EXCEPTION_DIR;

	const DWORD nEntries = getDirEntrySize(IMAGE_DIRECTORY_ENTRY_EXCEPTION) / (DWORD)sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY);
	if (!nEntries)
		return IMAGE_HAS_NO_EXCEPTION_DIR;

	m_vecExceptionTable.reserve(nEntries);
	for (unsigned i = 0; i < nEntries; i++, pRuntimeFuncsEntry++)
		m_vecExceptionTable.push_back(*pRuntimeFuncsEntry);

	m_dwFileSummary |= IMAGE_EXCEPTION_DIRECTORY_FLAG;

	return S_OK;
}

HRESULT Clibpe::getSecurityTable()
{
	const DWORD dwSecurityDirOffset = getDirEntryRVA(IMAGE_DIRECTORY_ENTRY_SECURITY);
	const DWORD dwSecurityDirSize = getDirEntrySize(IMAGE_DIRECTORY_ENTRY_SECURITY);

	if (!dwSecurityDirOffset || !dwSecurityDirSize)
		return IMAGE_HAS_NO_SECURITY_DIR;

	DWORD_PTR dwSecurityDirStartVA;

	//Checks for bogus file offsets that can cause DWORD_PTR overflow.
	if (m_fMapViewOfFileWhole)
	{
	#if INTPTR_MAX == INT32_MAX
		if (dwSecurityDirOffset >= (UINT_MAX - (DWORD)m_lpBase))
			return IMAGE_HAS_NO_SECURITY_DIR;
	#elif INTPTR_MAX == INT64_MAX
		if (dwSecurityDirOffset >= (MAXDWORD64 - (DWORD_PTR)m_lpBase))
			return IMAGE_HAS_NO_SECURITY_DIR;
	#endif

		dwSecurityDirStartVA = (DWORD_PTR)m_lpBase + (DWORD_PTR)dwSecurityDirOffset;
	}
	else
	{
	#if INTPTR_MAX == INT32_MAX
		if (dwSecurityDirOffset >= (UINT_MAX - (DWORD)m_lpSectionBase))
			return IMAGE_HAS_NO_SECURITY_DIR;
	#elif INTPTR_MAX == INT64_MAX
		if (dwSecurityDirOffset >= (MAXDWORD64 - (DWORD_PTR)m_lpSectionBase))
			return IMAGE_HAS_NO_SECURITY_DIR;
	#endif

		dwSecurityDirStartVA = (DWORD_PTR)m_lpSectionBase + (DWORD_PTR)m_dwDeltaFileOffsetToMap;
	}

#if INTPTR_MAX == INT32_MAX
	if (dwSecurityDirStartVA > ((DWORD_PTR)UINT_MAX - (DWORD_PTR)dwSecurityDirSize))
		return IMAGE_HAS_NO_SECURITY_DIR;
#elif INTPTR_MAX == INT64_MAX
	if (dwSecurityDirStartVA > (MAXDWORD64 - (DWORD_PTR)dwSecurityDirSize))
		return IMAGE_HAS_NO_SECURITY_DIR;
#endif

	const DWORD_PTR dwSecurityDirEndVA = dwSecurityDirStartVA + (DWORD_PTR)dwSecurityDirSize;

	if (!isPtrSafe(dwSecurityDirStartVA) || !isPtrSafe(dwSecurityDirEndVA, true))
		return IMAGE_HAS_NO_SECURITY_DIR;

	LPWIN_CERTIFICATE pCertificate = (LPWIN_CERTIFICATE)dwSecurityDirStartVA;
	std::vector<std::byte> vecCertBytes { };
	while (dwSecurityDirStartVA < dwSecurityDirEndVA)
	{
		for (DWORD_PTR iterCertData = 0; iterCertData < (DWORD_PTR)pCertificate->dwLength - offsetof(WIN_CERTIFICATE, bCertificate); iterCertData++)
			vecCertBytes.push_back((std::byte)pCertificate->bCertificate[iterCertData]);

		m_vecSecurity.emplace_back(*pCertificate, std::move(vecCertBytes));
		vecCertBytes.clear();

		//Get next certificate entry.
		//All entries start at 8 rounded address.
		dwSecurityDirStartVA = ((DWORD_PTR)pCertificate->dwLength + dwSecurityDirStartVA) % 8 + ((DWORD_PTR)pCertificate->dwLength + dwSecurityDirStartVA);
		pCertificate = (LPWIN_CERTIFICATE)dwSecurityDirStartVA;
	}
	m_dwFileSummary |= IMAGE_SECURITY_DIRECTORY_FLAG;

	return S_OK;
}

HRESULT Clibpe::getRelocationTable()
{
	PIMAGE_BASE_RELOCATION pBaseRelocDescriptor = (PIMAGE_BASE_RELOCATION)rVAToPtr(getDirEntryRVA(IMAGE_DIRECTORY_ENTRY_BASERELOC));

	if (!pBaseRelocDescriptor)
		return IMAGE_HAS_NO_GLOBALPTR_DIR;

	std::vector<std::tuple<WORD/*type*/, WORD/*offset*/>> vecRelocs { };

	try
	{
		while ((pBaseRelocDescriptor->SizeOfBlock) && (pBaseRelocDescriptor->VirtualAddress))
		{
			if (pBaseRelocDescriptor->SizeOfBlock < sizeof(IMAGE_BASE_RELOCATION))
				return -1;

			//Amount of Reloc entries.
			DWORD nRelocEntries = (pBaseRelocDescriptor->SizeOfBlock - (DWORD)sizeof(IMAGE_BASE_RELOCATION)) / (DWORD)sizeof(WORD);
			PWORD pRelocEntry = PWORD((DWORD_PTR)pBaseRelocDescriptor + sizeof(IMAGE_BASE_RELOCATION));
			WORD relocType { };

			vecRelocs.reserve(nRelocEntries);
			for (DWORD i = 0; i < nRelocEntries; i++)
			{
				if (!isPtrSafe(pRelocEntry))
					break;
				//Getting HIGH 4 bits of reloc's entry WORD —> reloc type.
				relocType = (*pRelocEntry & 0xF000) >> 12;
				vecRelocs.emplace_back(relocType, ((*pRelocEntry) & 0x0fff)/*Low 12 bits —> Offset*/);
				if (relocType == IMAGE_REL_BASED_HIGHADJ)
				{	//The base relocation adds the high 16 bits of the difference to the 16-bit field at offset.
					//The 16-bit field represents the high value of a 32-bit word. 
					//The low 16 bits of the 32-bit value are stored in the 16-bit word that follows this base relocation.
					//This means that this base relocation occupies two slots. (MSDN)
					if (!isPtrSafe(++pRelocEntry))
					{
						vecRelocs.clear();
						break;
					}
					vecRelocs.emplace_back(relocType, *pRelocEntry/*The low 16-bit field*/);
					nRelocEntries--; //to compensate pRelocEntry++
				}
				pRelocEntry++;
			}
			m_vecRelocationTable.emplace_back(*pBaseRelocDescriptor, std::move(vecRelocs));
			vecRelocs.clear(); //clear temp vector to fill with next entries.

			//Too big (bogus) SizeOfBlock may cause DWORD_PTR overflow.
			//Checking to prevent.
		#if INTPTR_MAX == INT32_MAX
			if ((DWORD_PTR)pBaseRelocDescriptor >= ((DWORD_PTR)UINT_MAX - (DWORD_PTR)pBaseRelocDescriptor->SizeOfBlock))
				break;
		#elif INTPTR_MAX == INT64_MAX
			if ((DWORD_PTR)pBaseRelocDescriptor >= (MAXDWORD64 - (DWORD_PTR)pBaseRelocDescriptor->SizeOfBlock))
				break;
		#endif
			pBaseRelocDescriptor = PIMAGE_BASE_RELOCATION((DWORD_PTR)pBaseRelocDescriptor + (DWORD_PTR)pBaseRelocDescriptor->SizeOfBlock);
			if (!isPtrSafe(pBaseRelocDescriptor))
				break;
		}
	}
	catch (const std::bad_alloc&)
	{
		delete [] m_lpszEmergencyMemory;
		MessageBox(nullptr, L"E_OUTOFMEMORY error while trying to get Relocation table.\nFile seems to be corrupted.",
			L"Error", MB_ICONERROR);

		vecRelocs.clear();
		m_lpszEmergencyMemory = new char[0x8FFF];
	}
	catch (...)
	{
		MessageBox(nullptr, L"Unknown exception raised while trying to get Relocation table.\nFile seems to be corrupted.",
			L"Error", MB_ICONERROR);
	}

	m_dwFileSummary |= IMAGE_BASERELOC_DIRECTORY_FLAG;

	return S_OK;
}

HRESULT Clibpe::getDebugTable()
{
	const DWORD dwDebugDirRVA = getDirEntryRVA(IMAGE_DIRECTORY_ENTRY_DEBUG);

	if (!dwDebugDirRVA)
		return IMAGE_HAS_NO_DEBUG_DIR;

	PIMAGE_DEBUG_DIRECTORY pDebugDir;
	DWORD dwDebugDirSize;
	PIMAGE_SECTION_HEADER pDebugSecHeader = getSecHdrFromName(".debug");

	if (pDebugSecHeader && (pDebugSecHeader->VirtualAddress == dwDebugDirRVA))
	{
		if (m_fMapViewOfFileWhole)
			pDebugDir = (PIMAGE_DEBUG_DIRECTORY)((DWORD_PTR)pDebugSecHeader->PointerToRawData + (DWORD_PTR)m_lpBase);
		else
			pDebugDir = (PIMAGE_DEBUG_DIRECTORY)((DWORD_PTR)m_lpSectionBase + (DWORD_PTR)m_dwDeltaFileOffsetToMap);

		dwDebugDirSize = getDirEntrySize(IMAGE_DIRECTORY_ENTRY_DEBUG) * (DWORD)sizeof(IMAGE_DEBUG_DIRECTORY);
	}
	else //Looking for the debug directory.
	{
		pDebugSecHeader = getSecHdrFromRVA(dwDebugDirRVA);
		if (!pDebugSecHeader)
			return IMAGE_HAS_NO_DEBUG_DIR;

		if (!(pDebugDir = (PIMAGE_DEBUG_DIRECTORY)rVAToPtr(dwDebugDirRVA)))
			return IMAGE_HAS_NO_DEBUG_DIR;

		dwDebugDirSize = getDirEntrySize(IMAGE_DIRECTORY_ENTRY_DEBUG);
	}

	const DWORD nDebugEntries = dwDebugDirSize / (DWORD)sizeof(IMAGE_DEBUG_DIRECTORY);

	if (!nDebugEntries)
		return -1;

	m_vecDebugTable.reserve(nDebugEntries);
	for (unsigned i = 0; i < nDebugEntries; i++)
	{
		m_vecDebugTable.push_back(*pDebugDir);
		pDebugDir++;
	}
	m_dwFileSummary |= IMAGE_DEBUG_DIRECTORY_FLAG;

	return S_OK;
}

HRESULT Clibpe::getArchitectureTable()
{
	const DWORD dwArchDirRVA = getDirEntryRVA(IMAGE_DIRECTORY_ENTRY_ARCHITECTURE);
	if (!dwArchDirRVA)
		return IMAGE_HAS_NO_ARCHITECTURE_DIR;

	const PIMAGE_ARCHITECTURE_ENTRY pArchEntry = (PIMAGE_ARCHITECTURE_ENTRY)rVAToPtr(dwArchDirRVA);
	if (!pArchEntry)
		return IMAGE_HAS_NO_ARCHITECTURE_DIR;

	m_dwFileSummary |= IMAGE_ARCHITECTURE_DIRECTORY_FLAG;

	return S_OK;
}

HRESULT Clibpe::getGlobalPTRTable()
{
	const DWORD_PTR dwGlobalPTRDirRVA = (DWORD_PTR)rVAToPtr(getDirEntryRVA(IMAGE_DIRECTORY_ENTRY_GLOBALPTR));
	if (!dwGlobalPTRDirRVA)
		return IMAGE_HAS_NO_GLOBALPTR_DIR;

	m_dwFileSummary |= IMAGE_GLOBALPTR_DIRECTORY_FLAG;

	return S_OK;
}

HRESULT Clibpe::getTLSTable()
{
	const DWORD dwTLSDirRVA = getDirEntryRVA(IMAGE_DIRECTORY_ENTRY_TLS);
	if (!dwTLSDirRVA)
		return IMAGE_HAS_NO_TLS_DIR;
	try {
		std::vector<std::byte> vecTLSRawData { };
		std::vector<DWORD> vecTLSCallbacks { };

		if (IMAGE_HAS_FLAG(m_dwFileSummary, IMAGE_PE32_FLAG))
		{
			const PIMAGE_TLS_DIRECTORY32 pTLSDir32 = (PIMAGE_TLS_DIRECTORY32)rVAToPtr(dwTLSDirRVA);
			if (!pTLSDir32)
				return IMAGE_HAS_NO_TLS_DIR;
			//All TLS adresses are not RVA, but actual VA.
			//So we must subtract ImageBase before pass to rVAToPtr().
			PBYTE dwTLSRawStart = (PBYTE)rVAToPtr(pTLSDir32->StartAddressOfRawData - m_pNTHeader32->OptionalHeader.ImageBase);
			PBYTE dwTLSRawEnd = (PBYTE)rVAToPtr(pTLSDir32->EndAddressOfRawData - m_pNTHeader32->OptionalHeader.ImageBase);
			if (dwTLSRawStart && dwTLSRawEnd && dwTLSRawEnd > dwTLSRawStart)
			{
				vecTLSRawData.reserve(dwTLSRawEnd - dwTLSRawStart);
				for (unsigned i = 0; i < dwTLSRawEnd - dwTLSRawStart; i++)
					vecTLSRawData.push_back(std::byte(*(dwTLSRawStart + i)));

			}
			PDWORD pTLSCallbacks = (PDWORD)rVAToPtr(pTLSDir32->AddressOfCallBacks - m_pNTHeader32->OptionalHeader.ImageBase);
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
			
			m_tupTLS = { *pTLSDir32, IMAGE_TLS_DIRECTORY64 { }, std::move(vecTLSRawData), std::move(vecTLSCallbacks) };
		}
		else if (IMAGE_HAS_FLAG(m_dwFileSummary, IMAGE_PE64_FLAG))
		{
			const PIMAGE_TLS_DIRECTORY64 pTLSDir64 = (PIMAGE_TLS_DIRECTORY64)rVAToPtr(dwTLSDirRVA);
			if (!pTLSDir64)
				return IMAGE_HAS_NO_TLS_DIR;

			PBYTE pTLSRawStart = (PBYTE)rVAToPtr(pTLSDir64->StartAddressOfRawData - m_pNTHeader64->OptionalHeader.ImageBase);
			PBYTE pTLSRawEnd = (PBYTE)rVAToPtr(pTLSDir64->EndAddressOfRawData - m_pNTHeader64->OptionalHeader.ImageBase);
			if (pTLSRawStart && pTLSRawEnd && pTLSRawEnd > pTLSRawStart)
			{
				vecTLSRawData.reserve(pTLSRawEnd - pTLSRawStart);
				for (unsigned i = 0; i < pTLSRawEnd - pTLSRawStart; i++)
					vecTLSRawData.push_back(std::byte(*(pTLSRawStart + i)));

			}
			PDWORD pTLSCallbacks = (PDWORD)rVAToPtr(pTLSDir64->AddressOfCallBacks - m_pNTHeader64->OptionalHeader.ImageBase);
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

			m_tupTLS = { IMAGE_TLS_DIRECTORY32 { }, *pTLSDir64, std::move(vecTLSRawData), std::move(vecTLSCallbacks) };
		}
		m_dwFileSummary |= IMAGE_TLS_DIRECTORY_FLAG;
	}
	catch (const std::bad_alloc&)
	{
		delete [] m_lpszEmergencyMemory;
		MessageBox(nullptr, L"E_OUTOFMEMORY error while trying to get TLS table.\r\n"
			L"File seems to be corrupted.", L"Error", MB_ICONERROR);

		m_lpszEmergencyMemory = new char[0x8FFF];
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
	if (IMAGE_HAS_FLAG(m_dwFileSummary, IMAGE_PE32_FLAG))
	{
		const PIMAGE_LOAD_CONFIG_DIRECTORY32 pLoadConfigDir32 = (PIMAGE_LOAD_CONFIG_DIRECTORY32)rVAToPtr(
			getDirEntryRVA(IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG));
		if (!pLoadConfigDir32)
			return IMAGE_HAS_NO_LOADCONFIG_DIR;

		m_tupLoadConfigDir = { *pLoadConfigDir32, IMAGE_LOAD_CONFIG_DIRECTORY64 { } };
	}
	else if (IMAGE_HAS_FLAG(m_dwFileSummary, IMAGE_PE64_FLAG))
	{
		const PIMAGE_LOAD_CONFIG_DIRECTORY64 pLoadConfigDir64 = (PIMAGE_LOAD_CONFIG_DIRECTORY64)rVAToPtr(
			getDirEntryRVA(IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG));
		if (!pLoadConfigDir64)
			return IMAGE_HAS_NO_LOADCONFIG_DIR;

		m_tupLoadConfigDir = { IMAGE_LOAD_CONFIG_DIRECTORY32 { }, *pLoadConfigDir64 };
	}
	m_dwFileSummary |= IMAGE_LOADCONFIG_DIRECTORY_FLAG;

	return S_OK;
}

HRESULT Clibpe::getBoundImportTable()
{
	PIMAGE_BOUND_IMPORT_DESCRIPTOR pBoundImpDesc =
		(PIMAGE_BOUND_IMPORT_DESCRIPTOR)rVAToPtr(getDirEntryRVA(IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT));

	if (!pBoundImpDesc)
		return IMAGE_HAS_NO_BOUNDIMPORT_DIR;

	std::vector<std::tuple<IMAGE_BOUND_FORWARDER_REF, std::string>> vecBoundForwarders { };
	std::string strModuleName { };

	while (pBoundImpDesc->TimeDateStamp)
	{
		PIMAGE_BOUND_FORWARDER_REF pBoundImpForwarder = (PIMAGE_BOUND_FORWARDER_REF)(pBoundImpDesc + 1);
		if (!isPtrSafe(pBoundImpForwarder))
			return IMAGE_HAS_NO_BOUNDIMPORT_DIR;

		for (unsigned i = 0; i < pBoundImpDesc->NumberOfModuleForwarderRefs; i++)
		{
			const LPCSTR szName = (LPCSTR)((DWORD_PTR)pBoundImpDesc + pBoundImpForwarder->OffsetModuleName);
			if (isPtrSafe(szName))
				if (szName && (StringCchLengthA(szName, MAX_PATH, nullptr) != STRSAFE_E_INVALID_PARAMETER))
					strModuleName = szName;

			vecBoundForwarders.emplace_back(*pBoundImpForwarder, std::move(strModuleName));
			strModuleName.clear();

			if (!isPtrSafe(++pBoundImpForwarder))
				return IMAGE_HAS_NO_BOUNDIMPORT_DIR;

			pBoundImpDesc = (PIMAGE_BOUND_IMPORT_DESCRIPTOR)((DWORD_PTR)pBoundImpDesc + sizeof(IMAGE_BOUND_FORWARDER_REF));
			if (!isPtrSafe(pBoundImpDesc))
				return IMAGE_HAS_NO_BOUNDIMPORT_DIR;
		}

		const LPCSTR szName = (LPCSTR)((DWORD_PTR)pBoundImpDesc + pBoundImpDesc->OffsetModuleName);
		if (isPtrSafe(szName))
			if (StringCchLengthA(szName, MAX_PATH, nullptr) != STRSAFE_E_INVALID_PARAMETER)
				strModuleName = szName;

		m_vecBoundImportTable.emplace_back(*pBoundImpDesc, std::move(strModuleName), std::move(vecBoundForwarders));
		vecBoundForwarders.clear();
		strModuleName.clear();

		if (!isPtrSafe(++pBoundImpDesc))
			return IMAGE_HAS_NO_BOUNDIMPORT_DIR;
	}
	m_dwFileSummary |= IMAGE_BOUNDIMPORT_DIRECTORY_FLAG;

	return S_OK;
}

HRESULT Clibpe::getIATTable()
{
	const DWORD_PTR dwIATDirRVA = (DWORD_PTR)rVAToPtr(getDirEntryRVA(IMAGE_DIRECTORY_ENTRY_IAT));
	if (!dwIATDirRVA)
		return IMAGE_HAS_NO_IAT_DIR;

	m_dwFileSummary |= IMAGE_IAT_DIRECTORY_FLAG;

	return S_OK;
}

HRESULT Clibpe::getDelayImportTable()
{
	PIMAGE_DELAYLOAD_DESCRIPTOR pDelayImpDescriptor = (PIMAGE_DELAYLOAD_DESCRIPTOR)rVAToPtr(getDirEntryRVA(IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT));
	if (!pDelayImpDescriptor)
		return IMAGE_HAS_NO_DELAY_IMPORT_DIR;

	std::vector<std::tuple<LONGLONG/*Ordinal/Hint*/, std::string/*Func name*/, LONGLONG/*Thunk table RVA*/,
		LONGLONG/*IAT->u1.AddressOfData*/, LONGLONG/*BoundIAT->u1.AddressOfData*/, LONGLONG/*UnloadInfoIAT->u1.AddressOfData*/>> vecFunc { };
	std::string strDllName { };

	if (IMAGE_HAS_FLAG(m_dwFileSummary, IMAGE_PE32_FLAG))
	{
		while (pDelayImpDescriptor->DllNameRVA)
		{
			PIMAGE_THUNK_DATA32 pThunk32Name = (PIMAGE_THUNK_DATA32)(DWORD_PTR)pDelayImpDescriptor->ImportNameTableRVA;

			if (!pThunk32Name) {
				if (!isPtrSafe(++pDelayImpDescriptor))
					return IMAGE_HAS_NO_DELAY_IMPORT_DIR;
			}
			else
			{
				pThunk32Name = (PIMAGE_THUNK_DATA32)rVAToPtr((DWORD_PTR)pThunk32Name);
				PIMAGE_THUNK_DATA32 pThunk32IAT = (PIMAGE_THUNK_DATA32)rVAToPtr(pDelayImpDescriptor->ImportAddressTableRVA);
				PIMAGE_THUNK_DATA32 pThunk32BoundIAT = (PIMAGE_THUNK_DATA32)rVAToPtr(
					pDelayImpDescriptor->BoundImportAddressTableRVA);
				PIMAGE_THUNK_DATA32 pThunk32UnloadInfoIAT = (PIMAGE_THUNK_DATA32)rVAToPtr(
					pDelayImpDescriptor->UnloadInformationTableRVA);

				if (!pThunk32Name)
					return IMAGE_HAS_NO_DELAY_IMPORT_DIR;

				while (pThunk32Name->u1.AddressOfData)
				{
					if (pThunk32Name->u1.Ordinal & IMAGE_ORDINAL_FLAG32)
						vecFunc.emplace_back(IMAGE_ORDINAL32(pThunk32Name->u1.Ordinal), "",
							pThunk32Name->u1.AddressOfData,
							pThunk32IAT ? pThunk32IAT->u1.AddressOfData : 0,
							pThunk32BoundIAT ? pThunk32BoundIAT->u1.AddressOfData : 0,
							pThunk32UnloadInfoIAT ? pThunk32UnloadInfoIAT->u1.AddressOfData : 0);
					else {//filling Hint, Name and Thunk RVA
						const PIMAGE_IMPORT_BY_NAME pName = (PIMAGE_IMPORT_BY_NAME)rVAToPtr(pThunk32Name->u1.AddressOfData);
						if (pName && (StringCchLengthA(pName->Name, MAX_PATH, nullptr) != STRSAFE_E_INVALID_PARAMETER))
							strDllName = pName->Name;

						vecFunc.emplace_back(pName ? pName->Hint : 0, std::move(strDllName),
							pThunk32Name->u1.AddressOfData,
							pThunk32IAT ? pThunk32IAT->u1.AddressOfData : 0,
							pThunk32BoundIAT ? pThunk32BoundIAT->u1.AddressOfData : 0,
							pThunk32UnloadInfoIAT ? pThunk32UnloadInfoIAT->u1.AddressOfData : 0);
					}

					if (!isPtrSafe(++pThunk32Name))
						return IMAGE_HAS_NO_DELAY_IMPORT_DIR;
					if (pThunk32IAT)
						if (!isPtrSafe(++pThunk32IAT))
							return IMAGE_HAS_NO_DELAY_IMPORT_DIR;
					if (pThunk32BoundIAT)
						if (!isPtrSafe(++pThunk32BoundIAT))
							return IMAGE_HAS_NO_DELAY_IMPORT_DIR;
					if (pThunk32UnloadInfoIAT)
						if (!isPtrSafe(++pThunk32UnloadInfoIAT))
							return IMAGE_HAS_NO_DELAY_IMPORT_DIR;

					strDllName.clear();
				}

				const LPCSTR szName = (LPCSTR)rVAToPtr(pDelayImpDescriptor->DllNameRVA);
				if (szName && (StringCchLengthA(szName, MAX_PATH, nullptr) != STRSAFE_E_INVALID_PARAMETER))
					strDllName = szName;

				m_vecDelayImportTable.emplace_back(*pDelayImpDescriptor, std::move(strDllName), std::move(vecFunc));
				vecFunc.clear();
				strDllName.clear();

				if (!isPtrSafe(++pDelayImpDescriptor))
					return IMAGE_HAS_NO_DELAY_IMPORT_DIR;
			}
		}
	}
	else if (IMAGE_HAS_FLAG(m_dwFileSummary, IMAGE_PE64_FLAG))
	{
		while (pDelayImpDescriptor->DllNameRVA)
		{
			PIMAGE_THUNK_DATA64 pThunk64Name = (PIMAGE_THUNK_DATA64)(DWORD_PTR)pDelayImpDescriptor->ImportNameTableRVA;

			if (!pThunk64Name) {
				if (!isPtrSafe(++pDelayImpDescriptor))
					return IMAGE_HAS_NO_DELAY_IMPORT_DIR;
			}
			else
			{
				pThunk64Name = (PIMAGE_THUNK_DATA64)rVAToPtr((DWORD_PTR)pThunk64Name);
				PIMAGE_THUNK_DATA64 pThunk64IAT = (PIMAGE_THUNK_DATA64)rVAToPtr(pDelayImpDescriptor->ImportAddressTableRVA);
				PIMAGE_THUNK_DATA64 pThunk64BoundIAT = (PIMAGE_THUNK_DATA64)rVAToPtr(
					pDelayImpDescriptor->BoundImportAddressTableRVA);
				PIMAGE_THUNK_DATA64 pThunk64UnloadInfoIAT = (PIMAGE_THUNK_DATA64)rVAToPtr(
					pDelayImpDescriptor->UnloadInformationTableRVA);

				if (!pThunk64Name)
					return IMAGE_HAS_NO_DELAY_IMPORT_DIR;

				while (pThunk64Name->u1.AddressOfData)
				{
					if (pThunk64Name->u1.Ordinal & IMAGE_ORDINAL_FLAG64)
						vecFunc.emplace_back(IMAGE_ORDINAL64(pThunk64Name->u1.Ordinal), "",
							pThunk64Name->u1.AddressOfData,
							pThunk64IAT ? pThunk64IAT->u1.AddressOfData : 0,
							pThunk64BoundIAT ? pThunk64BoundIAT->u1.AddressOfData : 0,
							pThunk64UnloadInfoIAT ? pThunk64UnloadInfoIAT->u1.AddressOfData : 0);
					else
					{	//filling Hint, Name and Thunk RVA.
						const PIMAGE_IMPORT_BY_NAME pName = (PIMAGE_IMPORT_BY_NAME)rVAToPtr(pThunk64Name->u1.AddressOfData);
						if (pName && (StringCchLengthA(pName->Name, MAX_PATH, nullptr) != STRSAFE_E_INVALID_PARAMETER))
							strDllName = pName->Name;

						vecFunc.emplace_back(pName ? pName->Hint : 0, std::move(strDllName),
							pThunk64Name->u1.AddressOfData,
							pThunk64IAT ? pThunk64IAT->u1.AddressOfData : 0,
							pThunk64BoundIAT ? pThunk64BoundIAT->u1.AddressOfData : 0,
							pThunk64UnloadInfoIAT ? pThunk64UnloadInfoIAT->u1.AddressOfData : 0);
					}

					if (!isPtrSafe(++pThunk64Name))
						return IMAGE_HAS_NO_DELAY_IMPORT_DIR;
					if (pThunk64IAT)
						if (!isPtrSafe(++pThunk64IAT))
							return IMAGE_HAS_NO_DELAY_IMPORT_DIR;
					if (pThunk64BoundIAT)
						if (!isPtrSafe(++pThunk64BoundIAT))
							return IMAGE_HAS_NO_DELAY_IMPORT_DIR;
					if (pThunk64UnloadInfoIAT)
						if (!isPtrSafe(++pThunk64UnloadInfoIAT))
							return IMAGE_HAS_NO_DELAY_IMPORT_DIR;

					strDllName.clear();
				}

				const LPCSTR szName = (LPCSTR)rVAToPtr(pDelayImpDescriptor->DllNameRVA);
				if (szName && (StringCchLengthA(szName, MAX_PATH, nullptr) != STRSAFE_E_INVALID_PARAMETER))
					strDllName = szName;

				m_vecDelayImportTable.emplace_back(*pDelayImpDescriptor, std::move(strDllName), std::move(vecFunc));
				vecFunc.clear();
				strDllName.clear();

				if (!isPtrSafe(++pDelayImpDescriptor))
					return IMAGE_HAS_NO_DELAY_IMPORT_DIR;
			}
		}
	}
	m_dwFileSummary |= IMAGE_DELAYIMPORT_DIRECTORY_FLAG;

	return S_OK;
}

HRESULT Clibpe::getCOMDescriptorTable()
{
	const PIMAGE_COR20_HEADER pCOMDescriptorHeader = (PIMAGE_COR20_HEADER)rVAToPtr(getDirEntryRVA(IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR));
	if (!pCOMDescriptorHeader)
		return IMAGE_HAS_NO_COMDESCRIPTOR_DIR;

	m_stCOR20Header = *pCOMDescriptorHeader;

	m_dwFileSummary |= IMAGE_COMDESCRIPTOR_DIRECTORY_FLAG;

	return S_OK;
}