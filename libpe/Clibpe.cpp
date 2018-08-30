#include "stdafx.h"
#include "libpe.h"
#include "Clibpe.h"

Clibpe::~Clibpe()
{
	delete [] m_szEmergencyMemory;
}

HRESULT Clibpe::LoadPe(LPCWSTR lpszFile)
{
	if (m_lpBase)//if it's not the first LoadPe call from the Ilibpe pointer
		PEResetAll();//sets all members to zero and clear() vectors

	HANDLE hFile = CreateFileW(lpszFile, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE)
		return FILE_OPEN_FAILED;

	::GetFileSizeEx(hFile, &m_stFileSize);
	if (m_stFileSize.QuadPart < sizeof(IMAGE_DOS_HEADER))
	{
		CloseHandle(hFile);
		return FILE_SIZE_TOO_SMALL;
	}

	m_hMapObject = CreateFileMappingW(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
	if (!m_hMapObject)
	{
		CloseHandle(hFile);
		return FILE_CREATE_FILE_MAPPING_FAILED;
	}

	m_lpBase = MapViewOfFile(m_hMapObject, FILE_MAP_READ, 0, 0, 0);
	if (!m_lpBase) //Not enough memmory? File is too big?
	{
		if (GetLastError() == ERROR_NOT_ENOUGH_MEMORY)
		{
			//If file is too big to fit process VirtualSize limit
			//we try to allocate at least some memory to map file's beginning, where PE HEADER resides.
			//Then going to MapViewOfFile/Unmap every section individually. 
			if (!(m_lpBase = MapViewOfFile(m_hMapObject, FILE_MAP_READ, 0, 0, 0xFFFF)))
			{
				CloseHandle(m_hMapObject);
				CloseHandle(hFile);
				return FILE_MAP_VIEW_OF_FILE_FAILED;
			}
			m_fMapViewOfFileWhole = false;
			m_dwMaxPointerBound = (DWORD_PTR)m_lpBase + 0xFFFF;
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

	HRESULT hr = PEGetHeaders();
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

	PEGetDataDirs();
	PEGetSectionHeaders();

	if (m_fMapViewOfFileWhole)
	{
		PEGetExportTable();
		PEGetImportTable();
		PEGetResourceTable();
		PEGetExceptionTable();
		PEGetSecurityTable();
		PEGetRelocationTable();
		PEGetDebugTable();
		PEGetArchitectureTable();
		PEGetGlobalPTRTable();
		PEGetTLSTable();
		PEGetLoadConfigTable();
		PEGetBoundImportTable();
		PEGetIATTable();
		PEGetDelayImportTable();
		PEGetCOMDescriptorTable();
	}
	else
	{
		SYSTEM_INFO SysInfo { };
		::GetSystemInfo(&SysInfo);
		DWORD dwAlignedAddressToMap { };
		SIZE_T ulSizeToMap { };
		PIMAGE_SECTION_HEADER pSec { };

		if (pSec = PEGetSecHeaderFromRVA(PEGetDirEntryRVA(IMAGE_DIRECTORY_ENTRY_EXPORT)))
		{
			m_dwFileOffsetToMap = pSec->PointerToRawData;

			if (m_dwFileOffsetToMap % SysInfo.dwAllocationGranularity > 0)
			{
				dwAlignedAddressToMap = (m_dwFileOffsetToMap < SysInfo.dwAllocationGranularity) ? 0 :
					(m_dwFileOffsetToMap - (m_dwFileOffsetToMap % SysInfo.dwAllocationGranularity));
			}
			else
				dwAlignedAddressToMap = m_dwFileOffsetToMap;

			m_dwDeltaFileOffsetToMap = m_dwFileOffsetToMap - dwAlignedAddressToMap;
			ulSizeToMap = (pSec->Misc.VirtualSize + m_dwFileOffsetToMap) > m_stFileSize.QuadPart ?
				SIZE_T(m_stFileSize.QuadPart - m_dwFileOffsetToMap) : SIZE_T(pSec->Misc.VirtualSize + m_dwDeltaFileOffsetToMap);

			if (!(m_lpSectionBase = MapViewOfFile(m_hMapObject, FILE_MAP_READ, 0, dwAlignedAddressToMap, ulSizeToMap)))
				return FILE_MAP_VIEW_OF_FILE_FAILED;

			m_dwMaxPointerBound = (DWORD_PTR)m_lpSectionBase + ulSizeToMap;
			PEGetExportTable();
			UnmapViewOfFile(m_lpSectionBase);
		}

		if (pSec = PEGetSecHeaderFromRVA(PEGetDirEntryRVA(IMAGE_DIRECTORY_ENTRY_IMPORT)))
		{
			m_dwFileOffsetToMap = pSec->PointerToRawData;

			if (m_dwFileOffsetToMap % SysInfo.dwAllocationGranularity > 0)
			{
				dwAlignedAddressToMap = (m_dwFileOffsetToMap < SysInfo.dwAllocationGranularity) ? 0 :
					(m_dwFileOffsetToMap - (m_dwFileOffsetToMap % SysInfo.dwAllocationGranularity));
			}
			else
				dwAlignedAddressToMap = m_dwFileOffsetToMap;

			m_dwDeltaFileOffsetToMap = m_dwFileOffsetToMap - dwAlignedAddressToMap;
			ulSizeToMap = (pSec->Misc.VirtualSize + m_dwFileOffsetToMap) > m_stFileSize.QuadPart ?
				SIZE_T(m_stFileSize.QuadPart - m_dwFileOffsetToMap) : SIZE_T(pSec->Misc.VirtualSize + m_dwDeltaFileOffsetToMap);

			if (!(m_lpSectionBase = MapViewOfFile(m_hMapObject, FILE_MAP_READ, 0, dwAlignedAddressToMap, ulSizeToMap)))
				return GetLastError();

			m_dwMaxPointerBound = (DWORD_PTR)m_lpSectionBase + ulSizeToMap;
			PEGetImportTable();
			UnmapViewOfFile(m_lpSectionBase);
		}

		if (pSec = PEGetSecHeaderFromRVA(PEGetDirEntryRVA(IMAGE_DIRECTORY_ENTRY_RESOURCE)))
		{
			m_dwFileOffsetToMap = pSec->PointerToRawData;

			if (m_dwFileOffsetToMap % SysInfo.dwAllocationGranularity > 0)
			{
				dwAlignedAddressToMap = (m_dwFileOffsetToMap < SysInfo.dwAllocationGranularity) ? 0 :
					(m_dwFileOffsetToMap - (m_dwFileOffsetToMap % SysInfo.dwAllocationGranularity));
			}
			else
				dwAlignedAddressToMap = m_dwFileOffsetToMap;

			m_dwDeltaFileOffsetToMap = m_dwFileOffsetToMap - dwAlignedAddressToMap;
			ulSizeToMap = (pSec->Misc.VirtualSize + m_dwFileOffsetToMap) > m_stFileSize.QuadPart ?
				SIZE_T(m_stFileSize.QuadPart - m_dwFileOffsetToMap) : SIZE_T(pSec->Misc.VirtualSize + m_dwDeltaFileOffsetToMap);

			if (!(m_lpSectionBase = MapViewOfFile(m_hMapObject, FILE_MAP_READ, 0, dwAlignedAddressToMap, ulSizeToMap)))
				return FILE_MAP_VIEW_OF_FILE_FAILED;

			m_dwMaxPointerBound = (DWORD_PTR)m_lpSectionBase + ulSizeToMap;
			PEGetResourceTable();
			UnmapViewOfFile(m_lpSectionBase);
		}

		if (pSec = PEGetSecHeaderFromRVA(PEGetDirEntryRVA(IMAGE_DIRECTORY_ENTRY_EXCEPTION)))
		{
			m_dwFileOffsetToMap = pSec->PointerToRawData;

			if (m_dwFileOffsetToMap % SysInfo.dwAllocationGranularity > 0)
			{
				dwAlignedAddressToMap = (m_dwFileOffsetToMap < SysInfo.dwAllocationGranularity) ? 0 :
					(m_dwFileOffsetToMap - (m_dwFileOffsetToMap % SysInfo.dwAllocationGranularity));
			}
			else
				dwAlignedAddressToMap = m_dwFileOffsetToMap;

			m_dwDeltaFileOffsetToMap = m_dwFileOffsetToMap - dwAlignedAddressToMap;
			ulSizeToMap = (pSec->Misc.VirtualSize + m_dwFileOffsetToMap) > m_stFileSize.QuadPart ?
				SIZE_T(m_stFileSize.QuadPart - m_dwFileOffsetToMap) : SIZE_T(pSec->Misc.VirtualSize + m_dwDeltaFileOffsetToMap);

			if (!(m_lpSectionBase = MapViewOfFile(m_hMapObject, FILE_MAP_READ, 0, dwAlignedAddressToMap, ulSizeToMap)))
				return FILE_MAP_VIEW_OF_FILE_FAILED;

			m_dwMaxPointerBound = (DWORD_PTR)m_lpSectionBase + ulSizeToMap;
			PEGetExceptionTable();
			UnmapViewOfFile(m_lpSectionBase);
		}

		if (PEGetDirEntryRVA(IMAGE_DIRECTORY_ENTRY_SECURITY))
		{/////////////////////This is actual file RAW offset
			m_dwFileOffsetToMap = PEGetDirEntryRVA(IMAGE_DIRECTORY_ENTRY_SECURITY);

			//Checking for exceeding file size bound
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

				ulSizeToMap = SIZE_T(PEGetDirEntrySize(IMAGE_DIRECTORY_ENTRY_SECURITY) + m_dwDeltaFileOffsetToMap);
				//Checking for out of bounds file sizes to map.
				if (((LONGLONG)m_dwFileOffsetToMap + (LONGLONG)ulSizeToMap) <= (m_stFileSize.QuadPart))
				{
					if (!(m_lpSectionBase = MapViewOfFile(m_hMapObject, FILE_MAP_READ, 0, dwAlignedAddressToMap, ulSizeToMap)))
						return FILE_MAP_VIEW_OF_FILE_FAILED;

					m_dwMaxPointerBound = (DWORD_PTR)m_lpSectionBase + ulSizeToMap;
					PEGetSecurityTable();
					UnmapViewOfFile(m_lpSectionBase);
				}
			}
		}

		if (pSec = PEGetSecHeaderFromRVA(PEGetDirEntryRVA(IMAGE_DIRECTORY_ENTRY_BASERELOC)))
		{
			m_dwFileOffsetToMap = pSec->PointerToRawData;

			if (m_dwFileOffsetToMap % SysInfo.dwAllocationGranularity > 0)
			{
				dwAlignedAddressToMap = (m_dwFileOffsetToMap < SysInfo.dwAllocationGranularity) ? 0 :
					(m_dwFileOffsetToMap - (m_dwFileOffsetToMap % SysInfo.dwAllocationGranularity));
			}
			else
				dwAlignedAddressToMap = m_dwFileOffsetToMap;

			m_dwDeltaFileOffsetToMap = m_dwFileOffsetToMap - dwAlignedAddressToMap;
			ulSizeToMap = (pSec->Misc.VirtualSize + m_dwFileOffsetToMap) > m_stFileSize.QuadPart ?
				SIZE_T(m_stFileSize.QuadPart - m_dwFileOffsetToMap) : SIZE_T(pSec->Misc.VirtualSize + m_dwDeltaFileOffsetToMap);

			if (!(m_lpSectionBase = MapViewOfFile(m_hMapObject, FILE_MAP_READ, 0, dwAlignedAddressToMap, ulSizeToMap)))
				return FILE_MAP_VIEW_OF_FILE_FAILED;

			m_dwMaxPointerBound = (DWORD_PTR)m_lpSectionBase + ulSizeToMap;
			PEGetRelocationTable();
			UnmapViewOfFile(m_lpSectionBase);
		}

		if (pSec = PEGetSecHeaderFromRVA(PEGetDirEntryRVA(IMAGE_DIRECTORY_ENTRY_DEBUG)))
		{
			m_dwFileOffsetToMap = pSec->PointerToRawData;

			if (m_dwFileOffsetToMap % SysInfo.dwAllocationGranularity > 0)
			{
				dwAlignedAddressToMap = (m_dwFileOffsetToMap < SysInfo.dwAllocationGranularity) ? 0 :
					(m_dwFileOffsetToMap - (m_dwFileOffsetToMap % SysInfo.dwAllocationGranularity));
			}
			else
				dwAlignedAddressToMap = m_dwFileOffsetToMap;

			m_dwDeltaFileOffsetToMap = m_dwFileOffsetToMap - dwAlignedAddressToMap;
			ulSizeToMap = (pSec->Misc.VirtualSize + m_dwFileOffsetToMap) > m_stFileSize.QuadPart ?
				SIZE_T(m_stFileSize.QuadPart - m_dwFileOffsetToMap) : SIZE_T(pSec->Misc.VirtualSize + m_dwDeltaFileOffsetToMap);

			if (!(m_lpSectionBase = MapViewOfFile(m_hMapObject, FILE_MAP_READ, 0, dwAlignedAddressToMap, ulSizeToMap)))
				return FILE_MAP_VIEW_OF_FILE_FAILED;

			m_dwMaxPointerBound = (DWORD_PTR)m_lpSectionBase + ulSizeToMap;
			PEGetDebugTable();
			UnmapViewOfFile(m_lpSectionBase);
		}

		if (pSec = PEGetSecHeaderFromRVA(PEGetDirEntryRVA(IMAGE_DIRECTORY_ENTRY_TLS)))
		{
			m_dwFileOffsetToMap = pSec->PointerToRawData;

			if (m_dwFileOffsetToMap % SysInfo.dwAllocationGranularity > 0)
			{
				dwAlignedAddressToMap = (m_dwFileOffsetToMap < SysInfo.dwAllocationGranularity) ? 0 :
					(m_dwFileOffsetToMap - (m_dwFileOffsetToMap % SysInfo.dwAllocationGranularity));
			}
			else
				dwAlignedAddressToMap = m_dwFileOffsetToMap;

			m_dwDeltaFileOffsetToMap = m_dwFileOffsetToMap - dwAlignedAddressToMap;
			ulSizeToMap = (pSec->Misc.VirtualSize + m_dwFileOffsetToMap) > m_stFileSize.QuadPart ?
				SIZE_T(m_stFileSize.QuadPart - m_dwFileOffsetToMap) : SIZE_T(pSec->Misc.VirtualSize + m_dwDeltaFileOffsetToMap);

			if (!(m_lpSectionBase = MapViewOfFile(m_hMapObject, FILE_MAP_READ, 0, dwAlignedAddressToMap, ulSizeToMap)))
				return FILE_MAP_VIEW_OF_FILE_FAILED;

			m_dwMaxPointerBound = (DWORD_PTR)m_lpSectionBase + ulSizeToMap;
			PEGetTLSTable();
			UnmapViewOfFile(m_lpSectionBase);
		}

		if (pSec = PEGetSecHeaderFromRVA(PEGetDirEntryRVA(IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG)))
		{
			m_dwFileOffsetToMap = pSec->PointerToRawData;

			if (m_dwFileOffsetToMap % SysInfo.dwAllocationGranularity > 0)
			{
				dwAlignedAddressToMap = (m_dwFileOffsetToMap < SysInfo.dwAllocationGranularity) ? 0 :
					(m_dwFileOffsetToMap - (m_dwFileOffsetToMap % SysInfo.dwAllocationGranularity));
			}
			else
				dwAlignedAddressToMap = m_dwFileOffsetToMap;

			m_dwDeltaFileOffsetToMap = m_dwFileOffsetToMap - dwAlignedAddressToMap;
			ulSizeToMap = (pSec->Misc.VirtualSize + m_dwFileOffsetToMap) > m_stFileSize.QuadPart ?
				SIZE_T(m_stFileSize.QuadPart - m_dwFileOffsetToMap) : SIZE_T(pSec->Misc.VirtualSize + m_dwDeltaFileOffsetToMap);

			if (!(m_lpSectionBase = MapViewOfFile(m_hMapObject, FILE_MAP_READ, 0, dwAlignedAddressToMap, ulSizeToMap)))
				return FILE_MAP_VIEW_OF_FILE_FAILED;

			m_dwMaxPointerBound = (DWORD_PTR)m_lpSectionBase + ulSizeToMap;
			PEGetLoadConfigTable();
			UnmapViewOfFile(m_lpSectionBase);
		}

		if (pSec = PEGetSecHeaderFromRVA(PEGetDirEntryRVA(IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT)))
		{
			m_dwFileOffsetToMap = pSec->PointerToRawData;

			if (m_dwFileOffsetToMap % SysInfo.dwAllocationGranularity > 0)
			{
				dwAlignedAddressToMap = (m_dwFileOffsetToMap < SysInfo.dwAllocationGranularity) ? 0 :
					(m_dwFileOffsetToMap - (m_dwFileOffsetToMap % SysInfo.dwAllocationGranularity));
			}
			else
				dwAlignedAddressToMap = m_dwFileOffsetToMap;

			m_dwDeltaFileOffsetToMap = m_dwFileOffsetToMap - dwAlignedAddressToMap;
			ulSizeToMap = (pSec->Misc.VirtualSize + m_dwFileOffsetToMap) > m_stFileSize.QuadPart ?
				SIZE_T(m_stFileSize.QuadPart - m_dwFileOffsetToMap) : SIZE_T(pSec->Misc.VirtualSize + m_dwDeltaFileOffsetToMap);

			if (!(m_lpSectionBase = MapViewOfFile(m_hMapObject, FILE_MAP_READ, 0, dwAlignedAddressToMap, ulSizeToMap)))
				return FILE_MAP_VIEW_OF_FILE_FAILED;

			m_dwMaxPointerBound = (DWORD_PTR)m_lpSectionBase + ulSizeToMap;
			PEGetBoundImportTable();
			UnmapViewOfFile(m_lpSectionBase);
		}

		if (pSec = PEGetSecHeaderFromRVA(PEGetDirEntryRVA(IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT)))
		{
			m_dwFileOffsetToMap = pSec->PointerToRawData;

			if (m_dwFileOffsetToMap % SysInfo.dwAllocationGranularity > 0)
			{
				dwAlignedAddressToMap = (m_dwFileOffsetToMap < SysInfo.dwAllocationGranularity) ? 0 :
					(m_dwFileOffsetToMap - (m_dwFileOffsetToMap % SysInfo.dwAllocationGranularity));
			}
			else
				dwAlignedAddressToMap = m_dwFileOffsetToMap;

			m_dwDeltaFileOffsetToMap = m_dwFileOffsetToMap - dwAlignedAddressToMap;
			ulSizeToMap = (pSec->Misc.VirtualSize + m_dwFileOffsetToMap) > m_stFileSize.QuadPart ?
				SIZE_T(m_stFileSize.QuadPart - m_dwFileOffsetToMap) : SIZE_T(pSec->Misc.VirtualSize + m_dwDeltaFileOffsetToMap);

			if (!(m_lpSectionBase = MapViewOfFile(m_hMapObject, FILE_MAP_READ, 0, dwAlignedAddressToMap, ulSizeToMap)))
				return FILE_MAP_VIEW_OF_FILE_FAILED;

			m_dwMaxPointerBound = (DWORD_PTR)m_lpSectionBase + ulSizeToMap;
			PEGetDelayImportTable();
			UnmapViewOfFile(m_lpSectionBase);
		}
	}

	UnmapViewOfFile(m_lpBase);
	CloseHandle(m_hMapObject);
	CloseHandle(hFile);

	return S_OK;
}

HRESULT Clibpe::GetFileSummary(PCDWORD* pFileSummary)
{
	if (!m_fLoaded)
		return CALL_LOADPE_FIRST;

	*pFileSummary = &m_dwFileSummary;

	return S_OK;
}

HRESULT Clibpe::GetMSDOSHeader(PLIBPE_DOSHEADER* pp)
{
	if (!m_fLoaded)
		return CALL_LOADPE_FIRST;

	if (!IMAGE_HAS_FLAG(m_dwFileSummary, IMAGE_DOS_HEADER_FLAG))
		return IMAGE_HAS_NO_DOS_HEADER;

	*pp = &m_stDOSHeader;

	return S_OK;
}

HRESULT Clibpe::GetMSDOSRichHeader(PLIBPE_RICH_VEC* vecRich)
{
	if (!m_fLoaded)
		return CALL_LOADPE_FIRST;

	if (!IMAGE_HAS_FLAG(m_dwFileSummary, IMAGE_RICH_HEADER_FLAG))
		return IMAGE_HAS_NO_RICH_HEADER;

	*vecRich = &m_vecRichHeader;

	return S_OK;
}

HRESULT Clibpe::GetNTHeader(PLIBPE_NTHEADER *pTupleNTHeader)
{
	if (!m_fLoaded)
		return CALL_LOADPE_FIRST;

	if (!IMAGE_HAS_FLAG(m_dwFileSummary, IMAGE_NT_HEADER_FLAG))
		return IMAGE_HAS_NO_NT_HEADER;

	*pTupleNTHeader = &m_tupNTHeader;

	return S_OK;
}

HRESULT Clibpe::GetFileHeader(PLIBPE_FILEHEADER* pp)
{
	if (!m_fLoaded)
		return CALL_LOADPE_FIRST;

	if (!IMAGE_HAS_FLAG(m_dwFileSummary, IMAGE_FILE_HEADER_FLAG))
		return IMAGE_HAS_NO_FILE_HEADER;

	*pp = &m_stFileHeader;

	return S_OK;
}

HRESULT Clibpe::GetOptionalHeader(PLIBPE_OPTHEADER* tupleOptHeader)
{
	if (!m_fLoaded)
		return CALL_LOADPE_FIRST;

	if (!IMAGE_HAS_FLAG(m_dwFileSummary, IMAGE_OPTIONAL_HEADER_FLAG))
		return IMAGE_HAS_NO_OPTIONAL_HEADER;

	*tupleOptHeader = &m_tupOptionalHeader;

	return S_OK;
}

HRESULT Clibpe::GetDataDirectories(PLIBPE_DATADIRS_VEC* vecDataDir)
{
	if (!m_fLoaded)
		return CALL_LOADPE_FIRST;

	if (!IMAGE_HAS_FLAG(m_dwFileSummary, IMAGE_DATA_DIRECTORIES_FLAG))
		return IMAGE_HAS_NO_DATA_DIRECTORIES;

	*vecDataDir = &m_vecDataDirectories;

	return S_OK;
}

HRESULT Clibpe::GetSectionHeaders(PLIBPE_SECHEADER_VEC* vecSections)
{
	if (!m_fLoaded)
		return CALL_LOADPE_FIRST;

	if (!IMAGE_HAS_FLAG(m_dwFileSummary, IMAGE_SECTION_HEADERS_FLAG))
		return IMAGE_HAS_NO_SECTIONS;

	*vecSections = &m_vecSectionHeaders;

	return S_OK;
}

HRESULT Clibpe::GetExportTable(PLIBPE_EXPORT* vecExport)
{
	if (!m_fLoaded)
		return CALL_LOADPE_FIRST;

	if (!IMAGE_HAS_FLAG(m_dwFileSummary, IMAGE_EXPORT_DIRECTORY_FLAG))
		return IMAGE_HAS_NO_EXPORT_DIR;

	*vecExport = &m_tupExport;

	return S_OK;
}

HRESULT Clibpe::GetImportTable(PLIBPE_IMPORT_VEC* vecImport)
{
	if (!m_fLoaded)
		return CALL_LOADPE_FIRST;

	if (!IMAGE_HAS_FLAG(m_dwFileSummary, IMAGE_IMPORT_DIRECTORY_FLAG))
		return IMAGE_HAS_NO_IMPORT_DIR;

	*vecImport = &m_vecImportTable;

	return S_OK;
}

HRESULT Clibpe::GetResourceTable(PLIBPE_RESOURCE_ROOT* tupleRes)
{
	if (!m_fLoaded)
		return CALL_LOADPE_FIRST;

	if (!IMAGE_HAS_FLAG(m_dwFileSummary, IMAGE_RESOURCE_DIRECTORY_FLAG))
		return IMAGE_HAS_NO_RESOURCE_DIR;

	*tupleRes = &m_tupResourceTable;

	return S_OK;
}

HRESULT Clibpe::GetExceptionTable(PLIBPE_EXCEPTION_VEC* vecException)
{
	if (!m_fLoaded)
		return CALL_LOADPE_FIRST;

	if (!IMAGE_HAS_FLAG(m_dwFileSummary, IMAGE_EXCEPTION_DIRECTORY_FLAG))
		return IMAGE_HAS_NO_EXCEPTION_DIR;

	*vecException = &m_vecExceptionTable;

	return S_OK;

}

HRESULT Clibpe::GetSecurityTable(PLIBPE_SECURITY_VEC* vecSecurity)
{
	if (!m_fLoaded)
		return CALL_LOADPE_FIRST;

	if (!IMAGE_HAS_FLAG(m_dwFileSummary, IMAGE_SECURITY_DIRECTORY_FLAG))
		return IMAGE_HAS_NO_SECURITY_DIR;

	*vecSecurity = &m_vecSecurity;

	return S_OK;
}

HRESULT Clibpe::GetRelocationTable(PLIBPE_RELOCATION_VEC* vecRelocs)
{
	if (!m_fLoaded)
		return CALL_LOADPE_FIRST;

	if (!IMAGE_HAS_FLAG(m_dwFileSummary, IMAGE_BASERELOC_DIRECTORY_FLAG))
		return IMAGE_HAS_NO_BASERELOC_DIR;

	*vecRelocs = &m_vecRelocationTable;

	return S_OK;
}

HRESULT Clibpe::GetDebugTable(PLIBPE_DEBUG_VEC* vecDebug)
{
	if (!m_fLoaded)
		return CALL_LOADPE_FIRST;

	if (!IMAGE_HAS_FLAG(m_dwFileSummary, IMAGE_DEBUG_DIRECTORY_FLAG))
		return IMAGE_HAS_NO_DEBUG_DIR;

	*vecDebug = &m_vecDebugTable;

	return S_OK;
}

HRESULT Clibpe::GetTLSTable(PLIBPE_TLS* tupleTLS)
{
	if (!m_fLoaded)
		return CALL_LOADPE_FIRST;

	if (!IMAGE_HAS_FLAG(m_dwFileSummary, IMAGE_TLS_DIRECTORY_FLAG))
		return IMAGE_HAS_NO_TLS_DIR;

	*tupleTLS = &m_tupTLS;

	return S_OK;
}

HRESULT Clibpe::GetLoadConfigTable(PLIBPE_LOADCONFIGTABLE* tupleLCD)
{
	if (!m_fLoaded)
		return CALL_LOADPE_FIRST;

	if (!IMAGE_HAS_FLAG(m_dwFileSummary, IMAGE_LOADCONFIG_DIRECTORY_FLAG))
		return IMAGE_HAS_NO_LOADCONFIG_DIR;

	*tupleLCD = &m_tupLoadConfigDir;

	return S_OK;
}

HRESULT Clibpe::GetBoundImportTable(PLIBPE_BOUNDIMPORT_VEC* vecBoundImp)
{
	if (!m_fLoaded)
		return CALL_LOADPE_FIRST;

	if (!IMAGE_HAS_FLAG(m_dwFileSummary, IMAGE_BOUNDIMPORT_DIRECTORY_FLAG))
		return IMAGE_HAS_NO_BOUNDIMPORT_DIR;

	*vecBoundImp = &m_vecBoundImportTable;

	return S_OK;
}

HRESULT Clibpe::GetDelayImportTable(PLIBPE_DELAYIMPORT_VEC* vecDelayImport)
{
	if (!m_fLoaded)
		return CALL_LOADPE_FIRST;

	if (!IMAGE_HAS_FLAG(m_dwFileSummary, IMAGE_DELAYIMPORT_DIRECTORY_FLAG))
		return 	IMAGE_HAS_NO_DELAY_IMPORT_DIR;

	*vecDelayImport = &m_vecDelayImportTable;

	return S_OK;
}

HRESULT Clibpe::GetCOMDescriptorTable(PLIBPE_COM_DESCRIPTOR * pCOMDescriptor)
{
	if (!m_fLoaded)
		return CALL_LOADPE_FIRST;

	if (!IMAGE_HAS_FLAG(m_dwFileSummary, IMAGE_COMDESCRIPTOR_DIRECTORY_FLAG))
		return IMAGE_HAS_NO_COMDESCRIPTOR_DIR;

	*pCOMDescriptor = &m_stCOR20Header;

	return S_OK;
}

HRESULT Clibpe::Release()
{
	delete this;

	return S_OK;
}


PIMAGE_SECTION_HEADER Clibpe::PEGetSecHeaderFromRVA(ULONGLONG RVA)
{
	PIMAGE_SECTION_HEADER pSection { };

	if (IMAGE_HAS_FLAG(m_dwFileSummary, IMAGE_PE32_FLAG))
	{
		pSection = IMAGE_FIRST_SECTION(m_pNTHeader32);
		for (unsigned i = 0; i < m_pNTHeader32->FileHeader.NumberOfSections; i++, pSection++)
		{
			if ((DWORD_PTR)pSection >= m_dwMaxPointerBound)
				return nullptr;
			// is RVA within this section?
			if ((RVA >= pSection->VirtualAddress) && (RVA < (pSection->VirtualAddress + pSection->Misc.VirtualSize)))
				return pSection;
		}
	}
	else if (IMAGE_HAS_FLAG(m_dwFileSummary, IMAGE_PE64_FLAG))
	{
		pSection = IMAGE_FIRST_SECTION(m_pNTHeader64);
		for (unsigned i = 0; i < m_pNTHeader64->FileHeader.NumberOfSections; i++, pSection++)
		{
			if ((DWORD_PTR)pSection >= m_dwMaxPointerBound)
				return nullptr;
			if ((RVA >= pSection->VirtualAddress) && (RVA < (pSection->VirtualAddress + pSection->Misc.VirtualSize)))
				return pSection;
		}
	}

	return nullptr;
}

PIMAGE_SECTION_HEADER Clibpe::PEGetSecHeaderFromName(LPCSTR pName)
{
	PIMAGE_SECTION_HEADER pSection;

	if (IMAGE_HAS_FLAG(m_dwFileSummary, IMAGE_PE32_FLAG))
	{
		pSection = IMAGE_FIRST_SECTION(m_pNTHeader32);

		for (unsigned i = 0; i < m_pNTHeader32->FileHeader.NumberOfSections; i++, pSection++)
		{
			if ((DWORD_PTR)pSection >= m_dwMaxPointerBound)
				break;
			if (strncmp((char*)pSection->Name, pName, IMAGE_SIZEOF_SHORT_NAME) == 0)
				return pSection;
		}
	}
	else if (IMAGE_HAS_FLAG(m_dwFileSummary, IMAGE_PE64_FLAG))
	{
		pSection = IMAGE_FIRST_SECTION(m_pNTHeader64);

		for (unsigned i = 0; i < m_pNTHeader64->FileHeader.NumberOfSections; i++, pSection++)
		{
			if ((DWORD_PTR)pSection >= m_dwMaxPointerBound)
				break;
			if (strncmp((char*)pSection->Name, pName, IMAGE_SIZEOF_SHORT_NAME) == 0)
				return pSection;
		}
	}

	return nullptr;
}

LPVOID Clibpe::PERVAToPTR(ULONGLONG RVA)
{
	PIMAGE_SECTION_HEADER pSection = PEGetSecHeaderFromRVA(RVA);
	if (!pSection)
		return nullptr;

	if (!m_fMapViewOfFileWhole)
		return (LPVOID)((DWORD_PTR)m_lpSectionBase + (SIZE_T)m_dwDeltaFileOffsetToMap +
		(RVA - (DWORD_PTR)(pSection->VirtualAddress - pSection->PointerToRawData) - m_dwFileOffsetToMap));
	else
		return (LPVOID)((DWORD_PTR)m_lpBase + RVA - (DWORD_PTR)(pSection->VirtualAddress - pSection->PointerToRawData));
}

DWORD Clibpe::PEGetDirEntryRVA(UINT dirEntry)
{
	if (IMAGE_HAS_FLAG(m_dwFileSummary, IMAGE_PE32_FLAG))
		return m_pNTHeader32->OptionalHeader.DataDirectory[dirEntry].VirtualAddress;
	else if (IMAGE_HAS_FLAG(m_dwFileSummary, IMAGE_PE64_FLAG))
		return m_pNTHeader64->OptionalHeader.DataDirectory[dirEntry].VirtualAddress;

	return 0;
}

DWORD Clibpe::PEGetDirEntrySize(UINT dirEntry)
{
	if (IMAGE_HAS_FLAG(m_dwFileSummary, IMAGE_PE32_FLAG))
		return m_pNTHeader32->OptionalHeader.DataDirectory[dirEntry].Size;
	else if (IMAGE_HAS_FLAG(m_dwFileSummary, IMAGE_PE64_FLAG))
		return m_pNTHeader64->OptionalHeader.DataDirectory[dirEntry].Size;

	return 0;
}

void Clibpe::PEResetAll()
{
	m_dwFileSummary = 0;
	m_pNTHeader32 = nullptr;
	m_pNTHeader64 = nullptr;
	m_lpBase = nullptr;
	m_fLoaded = false;

	m_vecDataDirectories.clear();
	m_vecSectionHeaders.clear();
	m_vecImportTable.clear();
	m_vecExceptionTable.clear();
	m_vecRelocationTable.clear();
	m_vecDebugTable.clear();
	std::get<2>(m_tupExport).clear();
	m_vecBoundImportTable.clear();
	m_vecDelayImportTable.clear();
}

HRESULT Clibpe::PEGetHeaders()
{
	m_pDosHeader = (PIMAGE_DOS_HEADER)m_lpBase;

	if (m_pDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
		return IMAGE_DOS_SIGNATURE_MISMATCH;

	m_stDOSHeader = *m_pDosHeader;
	m_dwFileSummary |= IMAGE_DOS_HEADER_FLAG;
	m_fLoaded = true;

	PEGetRichHeader();

	if (((PIMAGE_NT_HEADERS32)((DWORD_PTR)m_pDosHeader + m_pDosHeader->e_lfanew))->Signature != IMAGE_NT_SIGNATURE)
		return IMAGE_NT_SIGNATURE_MISMATCH;

	switch (((PIMAGE_NT_HEADERS32)((DWORD_PTR)m_pDosHeader + m_pDosHeader->e_lfanew))->OptionalHeader.Magic)
	{
	case IMAGE_NT_OPTIONAL_HDR32_MAGIC:
		m_dwFileSummary |= IMAGE_PE32_FLAG;
		m_pNTHeader32 = (PIMAGE_NT_HEADERS32)((DWORD_PTR)m_pDosHeader + m_pDosHeader->e_lfanew);
		m_tupNTHeader = { *m_pNTHeader32, IMAGE_NT_HEADERS64 { 0 } };
		m_stFileHeader = m_pNTHeader32->FileHeader;
		m_tupOptionalHeader = { m_pNTHeader32->OptionalHeader, IMAGE_OPTIONAL_HEADER64 { 0 } };
		break;
	case  IMAGE_NT_OPTIONAL_HDR64_MAGIC:
		m_dwFileSummary |= IMAGE_PE64_FLAG;
		m_pNTHeader64 = (PIMAGE_NT_HEADERS64)((DWORD_PTR)m_pDosHeader + m_pDosHeader->e_lfanew);
		m_tupNTHeader = { IMAGE_NT_HEADERS32 { 0 }, *m_pNTHeader64 };
		m_stFileHeader = m_pNTHeader64->FileHeader;
		m_tupOptionalHeader = { IMAGE_OPTIONAL_HEADER32 { 0 }, m_pNTHeader64->OptionalHeader };
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

HRESULT Clibpe::PEGetRichHeader()
{
	//"Rich" stub starts at 0x80 offset,
	//before m_pDosHeader->e_lfanew (PE header start offset)
	//If e_lfanew < 0x80 there is no "Rich"
	if (m_pDosHeader->e_lfanew <= 0x80)
		return IMAGE_HAS_NO_RICH_HEADER;

	PDWORD pRichStartVA = (PDWORD)((DWORD_PTR)m_pDosHeader + 0x80);
	PDWORD pRichIter = pRichStartVA;

	for (int i = 0; i < ((m_pDosHeader->e_lfanew - 0x80) / 4); i++)
	{
		//Check "Rich" (ANSI) sign then XOR pRichStartVA DWORD with the DWORD following "Rich" sign
		//to find out if it is "DanS" (ANSI).
		if ((*pRichIter == 0x68636952/*"Rich"*/) && ((*pRichStartVA xor *(pRichIter + 1)) == 0x536E6144/*"Dans"*/))
		{
			DWORD dwRichSize = (DWORD)(((DWORD_PTR)pRichIter - (DWORD_PTR)m_pDosHeader) - 0x90) / 8;//amount of all "Rich" DOUBLE_DWORD structs 
			DWORD dwRichXORMask = *(pRichIter + 1);//XOR mask of this "Rich" header
			pRichIter = (PDWORD)((DWORD_PTR)m_pDosHeader + 0x90);//VA of "Rich" DOUBLE_DWORD Struct start

			for (unsigned i = 0; i < dwRichSize; i++)
			{
				//Pushing double DWORD of "Rich" structure.
				m_vecRichHeader.push_back({ HIWORD(dwRichXORMask xor *pRichIter), LOWORD(dwRichXORMask xor *pRichIter), dwRichXORMask xor *(pRichIter + 1) });
				pRichIter += 2;//Jump next DOUBLE_DWORD
			}

			m_dwFileSummary |= IMAGE_RICH_HEADER_FLAG;

			return S_OK;
		}
		else
			pRichIter++;
	}

	return IMAGE_HAS_NO_RICH_HEADER;
}

HRESULT Clibpe::PEGetDataDirs()
{
	PIMAGE_DATA_DIRECTORY pDataDir { };
	PIMAGE_SECTION_HEADER pSectionHeader { };
	std::string strSecName { };

	if (IMAGE_HAS_FLAG(m_dwFileSummary, IMAGE_PE32_FLAG))
	{
		pDataDir = (PIMAGE_DATA_DIRECTORY)m_pNTHeader32->OptionalHeader.DataDirectory;

		//Filling DataDirectories vector
		for (unsigned i = 0; i < (m_pNTHeader32->OptionalHeader.NumberOfRvaAndSizes > 15 ?
			15 : m_pNTHeader32->OptionalHeader.NumberOfRvaAndSizes); i++)
		{
			pSectionHeader = PEGetSecHeaderFromRVA(pDataDir->VirtualAddress);
			//RVA of IMAGE_DIRECTORY_ENTRY_SECURITY is file RAW offset
			if (pSectionHeader && (i != IMAGE_DIRECTORY_ENTRY_SECURITY))
				strSecName.assign((char * const)pSectionHeader->Name, 8);

			m_vecDataDirectories.push_back({ *pDataDir, std::move(strSecName) });

			pDataDir++;
			strSecName.clear();
		}
	}
	else if (IMAGE_HAS_FLAG(m_dwFileSummary, IMAGE_PE64_FLAG))
	{
		pDataDir = (PIMAGE_DATA_DIRECTORY)m_pNTHeader64->OptionalHeader.DataDirectory;

		//Filling DataDirectories vector
		for (unsigned i = 0; i < m_pNTHeader64->OptionalHeader.NumberOfRvaAndSizes; i++)
		{
			pSectionHeader = PEGetSecHeaderFromRVA(pDataDir->VirtualAddress);
			//RVA of IMAGE_DIRECTORY_ENTRY_SECURITY is file RAW offset
			if (pSectionHeader && (i != IMAGE_DIRECTORY_ENTRY_SECURITY))
				strSecName.assign((char * const)pSectionHeader->Name, 8);

			m_vecDataDirectories.push_back({ *pDataDir, std::move(strSecName) });

			pDataDir++;
			strSecName.clear();
		}
	}
	if (m_vecDataDirectories.empty())
		return IMAGE_HAS_NO_DATA_DIRECTORIES;

	m_dwFileSummary |= IMAGE_DATA_DIRECTORIES_FLAG;

	return S_OK;
}

HRESULT Clibpe::PEGetSectionHeaders()
{
	PIMAGE_SECTION_HEADER pSectionHeader { };

	if (IMAGE_HAS_FLAG(m_dwFileSummary, IMAGE_PE32_FLAG))
	{
		pSectionHeader = IMAGE_FIRST_SECTION(m_pNTHeader32);

		for (unsigned i = 0; i < m_pNTHeader32->FileHeader.NumberOfSections; i++, pSectionHeader++)
		{
			if ((DWORD_PTR)pSectionHeader >= m_dwMaxPointerBound)
				break;
			m_vecSectionHeaders.push_back(*pSectionHeader);
		}
	}
	else if (IMAGE_HAS_FLAG(m_dwFileSummary, IMAGE_PE64_FLAG))
	{
		pSectionHeader = IMAGE_FIRST_SECTION(m_pNTHeader64);

		for (unsigned i = 0; i < m_pNTHeader64->FileHeader.NumberOfSections; i++, pSectionHeader++)
		{
			if ((DWORD_PTR)pSectionHeader >= m_dwMaxPointerBound)
				break;
			m_vecSectionHeaders.push_back(*pSectionHeader);
		}
	}

	if (m_vecSectionHeaders.empty())
		return IMAGE_HAS_NO_SECTIONS;

	m_vecSectionHeaders.shrink_to_fit();
	m_dwFileSummary |= IMAGE_SECTION_HEADERS_FLAG;

	return S_OK;
}

HRESULT Clibpe::PEGetExportTable()
{
	DWORD dwExportStartRVA = PEGetDirEntryRVA(IMAGE_DIRECTORY_ENTRY_EXPORT);
	DWORD dwExportEndRVA = dwExportStartRVA + PEGetDirEntrySize(IMAGE_DIRECTORY_ENTRY_EXPORT);
	PIMAGE_SECTION_HEADER pExportSecHeader = PEGetSecHeaderFromRVA(dwExportStartRVA);

	std::vector<std::tuple<DWORD/*Exported func RVA/Forwarder RVA*/, DWORD/*func Ordinal*/, std::string /*Func Name*/,
		std::string/*Forwarder func name*/>> vecFuncs { };
	std::string strFuncName { }, strFuncNameForwarder { }, strExportName { };

	if (!pExportSecHeader)
		return IMAGE_HAS_NO_EXPORT_DIR;

	PIMAGE_EXPORT_DIRECTORY pExportDir = (PIMAGE_EXPORT_DIRECTORY)PERVAToPTR(dwExportStartRVA);

	if (!pExportDir)
		return IMAGE_HAS_NO_EXPORT_DIR;

	PDWORD pFuncs = (PDWORD)PERVAToPTR(pExportDir->AddressOfFunctions);
	if (!pFuncs)
		return IMAGE_HAS_NO_EXPORT_DIR;

	PWORD pOrdinals = (PWORD)PERVAToPTR(pExportDir->AddressOfNameOrdinals);
	LPCSTR* szNames = (LPCSTR*)PERVAToPTR(pExportDir->AddressOfNames);

	try {
		for (unsigned i = 0; i < pExportDir->NumberOfFunctions; i++)
		{
			if (pFuncs[i])//if RVA==0 —> going next entry
			{
				LPCSTR szFuncName { }, szFuncNameForwarder { };

				if (szNames && pOrdinals)
					for (unsigned j = 0; j < pExportDir->NumberOfNames; j++)
						if (pOrdinals[j] == i)//cycling through Ordinals table to get func name
						{
							szFuncName = (LPCSTR)PERVAToPTR((DWORD_PTR)szNames[j]);
							//checking func name for length correctness
							if (szFuncName && (StringCchLengthA(szFuncName, MAX_PATH, nullptr) != STRSAFE_E_INVALID_PARAMETER))
								strFuncName = szFuncName;
						}
				if ((pFuncs[i] >= dwExportStartRVA) && (pFuncs[i] <= dwExportEndRVA))
				{
					szFuncNameForwarder = (LPCSTR)PERVAToPTR(pFuncs[i]);
					//checking forwarder name for length correctness
					if (szFuncNameForwarder && (StringCchLengthA(szFuncNameForwarder, MAX_PATH, nullptr) != STRSAFE_E_INVALID_PARAMETER))
						strFuncNameForwarder = szFuncNameForwarder;
				}
				vecFuncs.push_back({ pFuncs[i], i, std::move(strFuncName), std::move(strFuncNameForwarder) });
				strFuncName.clear();
				strFuncNameForwarder.clear();
			}
		}

		LPCSTR szExportName = (LPCSTR)PERVAToPTR(pExportDir->Name);
		//checking Export name for length correctness
		if (szExportName && (StringCchLengthA(szExportName, MAX_PATH, nullptr) != STRSAFE_E_INVALID_PARAMETER))
			strExportName = szExportName;

		m_tupExport = { *pExportDir, std::move(strExportName) /*Actual IMG name*/, std::move(vecFuncs) };
	}
	catch (const std::bad_alloc&)
	{
		delete [] m_szEmergencyMemory;
		MessageBox(0, TEXT("E_OUTOFMEMORY error while trying to get Export Table."), TEXT("Error"), MB_ICONERROR);

		vecFuncs.clear();
		m_szEmergencyMemory = new char[16384];
	}
	m_dwFileSummary |= IMAGE_EXPORT_DIRECTORY_FLAG;

	return S_OK;
}

HRESULT Clibpe::PEGetImportTable()
{
	PIMAGE_IMPORT_DESCRIPTOR pImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)PERVAToPTR(PEGetDirEntryRVA(IMAGE_DIRECTORY_ENTRY_IMPORT));

	if (!pImportDescriptor)
		return IMAGE_HAS_NO_IMPORT_DIR;

	DWORD dwTLSDirRVA = PEGetDirEntryRVA(IMAGE_DIRECTORY_ENTRY_TLS);
	PIMAGE_TLS_DIRECTORY32 pTLSDir32 { };
	PIMAGE_TLS_DIRECTORY64 pTLSDir64 { };
	PIMAGE_THUNK_DATA32 pThunk32 { };
	PIMAGE_THUNK_DATA64 pThunk64 { };
	std::vector<std::tuple<LONGLONG/*Ordinal/Hint*/, std::string/*Func name*/, LONGLONG/*Thunk table RVA*/>> vecFunc { };
	std::string strDllName { }, strFuncName { };

	try {
		if (IMAGE_HAS_FLAG(m_dwFileSummary, IMAGE_PE32_FLAG))
		{
			pTLSDir32 = (PIMAGE_TLS_DIRECTORY32)PERVAToPTR(dwTLSDirRVA);

			while (pImportDescriptor->Name)
			{
				//Checking for TLS Index patching trick, to fade Fake Imports
				if (pTLSDir32 && pTLSDir32->AddressOfIndex && (((DWORD_PTR)pImportDescriptor + offsetof(IMAGE_IMPORT_DESCRIPTOR, FirstThunk)) ==
					(DWORD_PTR)PERVAToPTR(pTLSDir32->AddressOfIndex - m_pNTHeader32->OptionalHeader.ImageBase) ||
					((DWORD_PTR)pImportDescriptor + offsetof(IMAGE_IMPORT_DESCRIPTOR, Name)) ==
					(DWORD_PTR)PERVAToPTR(pTLSDir32->AddressOfIndex - m_pNTHeader32->OptionalHeader.ImageBase)))
				{
					LPCSTR szName = (LPCSTR)PERVAToPTR(pImportDescriptor->Name);
					if (szName && (StringCchLengthA(szName, MAX_PATH, nullptr) != STRSAFE_E_INVALID_PARAMETER))
						strDllName = szName;

					strDllName += " (--> stripped by TLS::AddressOfIndex trick)";

					m_vecImportTable.push_back({ *pImportDescriptor, std::move(strDllName), std::move(vecFunc) });
					break;
				}

				pThunk32 = (PIMAGE_THUNK_DATA32)(DWORD_PTR)pImportDescriptor->OriginalFirstThunk;
				if (!pThunk32)
					pThunk32 = (PIMAGE_THUNK_DATA32)(DWORD_PTR)pImportDescriptor->FirstThunk;

				if (pThunk32)
				{
					pThunk32 = (PIMAGE_THUNK_DATA32)PERVAToPTR((DWORD_PTR)pThunk32);
					if (!pThunk32)
						return IMAGE_HAS_NO_IMPORT_DIR;

					while (pThunk32->u1.AddressOfData)
					{
						if (pThunk32->u1.Ordinal & IMAGE_ORDINAL_FLAG32)
							//If funcs are imported only by ordinals then filling only ordinal leaving Name as ""
							vecFunc.push_back({ IMAGE_ORDINAL32(pThunk32->u1.Ordinal), std::move(strFuncName), pThunk32->u1.AddressOfData });
						else
						{	//filling Hint, Name and Thunk RVA
							PIMAGE_IMPORT_BY_NAME pName = (PIMAGE_IMPORT_BY_NAME)PERVAToPTR(pThunk32->u1.AddressOfData);
							if (pName && (StringCchLengthA(pName->Name, MAX_PATH, nullptr) != STRSAFE_E_INVALID_PARAMETER))
								strFuncName = pName->Name;

							vecFunc.push_back({ pName ? pName->Hint : 0, std::move(strFuncName), pThunk32->u1.AddressOfData });
							strFuncName.clear();
						}
						pThunk32++;
					}

					LPCSTR szName = (LPCSTR)PERVAToPTR(pImportDescriptor->Name);
					if (szName && (StringCchLengthA(szName, MAX_PATH, nullptr) != STRSAFE_E_INVALID_PARAMETER))
						strDllName = szName;

					m_vecImportTable.push_back({ *pImportDescriptor, std::move(strDllName), std::move(vecFunc) });
					vecFunc.clear();
					strDllName.clear();

					pImportDescriptor++;
				}
				else// No IMPORT pointers for that DLL?...
					pImportDescriptor++;  //going to the next dll
			}
		}
		else if (IMAGE_HAS_FLAG(m_dwFileSummary, IMAGE_PE64_FLAG))
		{
			pTLSDir64 = (PIMAGE_TLS_DIRECTORY64)PERVAToPTR(dwTLSDirRVA);

			while (pImportDescriptor->Name)
			{
				if (pTLSDir64 && pTLSDir64->AddressOfIndex && (((DWORD_PTR)pImportDescriptor + offsetof(IMAGE_IMPORT_DESCRIPTOR, FirstThunk)) ==
					(DWORD_PTR)PERVAToPTR(pTLSDir64->AddressOfIndex - m_pNTHeader64->OptionalHeader.ImageBase) ||
					((DWORD_PTR)pImportDescriptor + offsetof(IMAGE_IMPORT_DESCRIPTOR, Name)) ==
					(DWORD_PTR)PERVAToPTR(pTLSDir64->AddressOfIndex - m_pNTHeader64->OptionalHeader.ImageBase)))
				{
					LPCSTR szName = (LPCSTR)PERVAToPTR(pImportDescriptor->Name);
					if (szName && (StringCchLengthA(szName, MAX_PATH, nullptr) != STRSAFE_E_INVALID_PARAMETER))
						strDllName = szName;

					strDllName += " (--> stripped by TLS::AddressOfIndex trick)";

					m_vecImportTable.push_back({ *pImportDescriptor, std::move(strDllName), std::move(vecFunc) });
					break;
				}

				pThunk64 = (PIMAGE_THUNK_DATA64)(DWORD_PTR)pImportDescriptor->OriginalFirstThunk;
				if (!pThunk64)
					pThunk64 = (PIMAGE_THUNK_DATA64)(DWORD_PTR)pImportDescriptor->FirstThunk;

				if (pThunk64)
				{
					if (pTLSDir64 && ((DWORD_PTR)pThunk64 >= (pTLSDir64->AddressOfIndex - m_pNTHeader64->OptionalHeader.ImageBase)))
					{
						m_vecImportTable.push_back({ *pImportDescriptor, "(fake import stripped)", std::move(vecFunc) });
						break;
					}

					pThunk64 = (PIMAGE_THUNK_DATA64)PERVAToPTR((DWORD_PTR)pThunk64);
					if (!pThunk64)
						return IMAGE_HAS_NO_IMPORT_DIR;

					while (pThunk64->u1.AddressOfData)
					{
						if (pThunk64->u1.Ordinal & IMAGE_ORDINAL_FLAG64)
							//if funcs are imported only by ordinals 
							//then filling only ordinal leaving Name as ""
							vecFunc.push_back({ IMAGE_ORDINAL64(pThunk64->u1.Ordinal), std::move(strFuncName), pThunk64->u1.AddressOfData });
						else
						{	//filling Hint, Name and Thunk RVA
							PIMAGE_IMPORT_BY_NAME pName = (PIMAGE_IMPORT_BY_NAME)PERVAToPTR(pThunk64->u1.AddressOfData);
							if (pName && (StringCchLengthA(pName->Name, MAX_PATH, nullptr) != STRSAFE_E_INVALID_PARAMETER))
								strFuncName = pName->Name;

							vecFunc.push_back({ pName ? pName->Hint : 0, std::move(strFuncName), pThunk64->u1.AddressOfData });
							strFuncName.clear();
						}
						pThunk64++;
					}

					LPCSTR szName = (LPCSTR)PERVAToPTR(pImportDescriptor->Name);
					if (szName && (StringCchLengthA(szName, MAX_PATH, nullptr) != STRSAFE_E_INVALID_PARAMETER))
						strDllName = szName;

					m_vecImportTable.push_back({ *pImportDescriptor, std::move(strDllName), std::move(vecFunc) });
					vecFunc.clear();
					strDllName.clear();

					pImportDescriptor++;
				}
				else
					pImportDescriptor++;
			}
		}
	}
	catch (const std::bad_alloc&)
	{
		delete [] m_szEmergencyMemory;
		MessageBox(0, L"E_OUTOFMEMORY error while trying to get Import Table.\r\n"
			L"Seems like too many Imports.", L"Error", MB_ICONERROR);

		vecFunc.clear();
		m_vecImportTable.clear();
		m_szEmergencyMemory = new char[16384];
	}
	m_dwFileSummary |= IMAGE_IMPORT_DIRECTORY_FLAG;

	return S_OK;
}

HRESULT Clibpe::PEGetResourceTable()
{
	PIMAGE_RESOURCE_DIRECTORY pRootResDir = (PIMAGE_RESOURCE_DIRECTORY)PERVAToPTR(PEGetDirEntryRVA(IMAGE_DIRECTORY_ENTRY_RESOURCE));

	if (!pRootResDir)
		return IMAGE_HAS_NO_RESOURCE_DIR;

	PIMAGE_RESOURCE_DIRECTORY_ENTRY pRootResDirEntry = (PIMAGE_RESOURCE_DIRECTORY_ENTRY)(pRootResDir + 1);
	size_t nResNameLength { };
	std::wstring strRootResName { }, strSecondResName { }, strThirdResName { };

	LIBPE_RESOURCE_ROOT_VEC vecResLvLRoot { };
	LIBPE_RESOURCE_LVL2 tupleResLvL2 { };
	LIBPE_RESOURCE_LVL2_VEC vecResLvL2 { };
	LIBPE_RESOURCE_LVL3 tupleResLvL3 { };
	LIBPE_RESOURCE_LVL3_VEC vecResLvL3 { };

	try {
		for (int iLvL1 = 0; iLvL1 < pRootResDir->NumberOfNamedEntries + pRootResDir->NumberOfIdEntries; iLvL1++)
		{
			PIMAGE_RESOURCE_DATA_ENTRY pRootResDataEntry { };
			std::vector<std::byte> vecRootResRawData { };

			//Name of Resource Type (ICON, BITMAP, MENU, etc...)
			if (pRootResDirEntry->NameIsString == 1)
			{//copy not more then MAX_PATH chars into strResName, avoiding buff overflow
				nResNameLength = ((PIMAGE_RESOURCE_DIR_STRING_U)((DWORD_PTR)pRootResDir + pRootResDirEntry->NameOffset))->Length;
				strRootResName.assign(((PIMAGE_RESOURCE_DIR_STRING_U)((DWORD_PTR)pRootResDir + pRootResDirEntry->NameOffset))->NameString,
					nResNameLength < MAX_PATH ? nResNameLength : MAX_PATH);
			}
			if (pRootResDirEntry->DataIsDirectory == 1)
			{
				PIMAGE_RESOURCE_DIRECTORY pSecondResDir = (PIMAGE_RESOURCE_DIRECTORY)((DWORD_PTR)pRootResDir + pRootResDirEntry->OffsetToDirectory);
				if (pSecondResDir == pRootResDir)//Resource loop hack
					tupleResLvL2 = { *pSecondResDir, vecResLvL2 };
				else
				{
					PIMAGE_RESOURCE_DIRECTORY_ENTRY pSecondResDirEntry = (PIMAGE_RESOURCE_DIRECTORY_ENTRY)(pSecondResDir + 1);
					for (int iLvL2 = 0; iLvL2 < pSecondResDir->NumberOfNamedEntries + pSecondResDir->NumberOfIdEntries; iLvL2++)
					{
						PIMAGE_RESOURCE_DATA_ENTRY pSecondResDataEntry { };
						std::vector<std::byte> vecSecondResRawData { };

						//Name of resource itself if not presented by ID ("AFX_MY_SUPER_DIALOG"...)
						if (pSecondResDirEntry->NameIsString == 1)
						{
							nResNameLength = ((PIMAGE_RESOURCE_DIR_STRING_U)((DWORD_PTR)pRootResDir + pSecondResDirEntry->NameOffset))->Length;
							strSecondResName.assign(((PIMAGE_RESOURCE_DIR_STRING_U)((DWORD_PTR)pRootResDir + pSecondResDirEntry->NameOffset))->NameString,
								nResNameLength < MAX_PATH ? nResNameLength : MAX_PATH);
						}

						if (pSecondResDirEntry->DataIsDirectory == 1)
						{
							PIMAGE_RESOURCE_DIRECTORY pThirdResDir = (PIMAGE_RESOURCE_DIRECTORY)((DWORD_PTR)pRootResDir + pSecondResDirEntry->OffsetToDirectory);
							if (pThirdResDir == pSecondResDir || pThirdResDir == pRootResDir)//Resource loop hack
								tupleResLvL3 = { *pThirdResDir, vecResLvL3 };
							else
							{
								PIMAGE_RESOURCE_DIRECTORY_ENTRY pThirdResDirEntry = (PIMAGE_RESOURCE_DIRECTORY_ENTRY)(pThirdResDir + 1);

								for (int iLvL3 = 0; iLvL3 < pThirdResDir->NumberOfNamedEntries + pThirdResDir->NumberOfIdEntries; iLvL3++)
								{
									PIMAGE_RESOURCE_DATA_ENTRY pThirdResDataEntry { };
									std::vector<std::byte> vecThirdResRawData { };

									if (pThirdResDirEntry->NameIsString == 1)
									{
										nResNameLength = ((PIMAGE_RESOURCE_DIR_STRING_U)((DWORD_PTR)pRootResDir + pThirdResDirEntry->NameOffset))->Length;
										strThirdResName.assign(((PIMAGE_RESOURCE_DIR_STRING_U)((DWORD_PTR)pRootResDir + pThirdResDirEntry->NameOffset))->NameString,
											nResNameLength < MAX_PATH ? nResNameLength : MAX_PATH);
									}

									pThirdResDataEntry = (PIMAGE_RESOURCE_DATA_ENTRY)((DWORD_PTR)pRootResDir + pThirdResDirEntry->OffsetToData);
									if (pThirdResDataEntry)
									{	//Resource LvL 3 RAW Data.
										//IMAGE_RESOURCE_DATA_ENTRY::OffsetToData is actually a general RVA,
										//not an offset form root IMAGE_RESOURCE_DIRECTORY, 
										//as IMAGE_RESOURCE_DIRECTORY_ENTRY::OffsetToData is.
										//MS doesn't tend to make things simpler.
										PBYTE pResRawData = (PBYTE)PERVAToPTR(pThirdResDataEntry->OffsetToData);
										if (pResRawData)
											for (unsigned i = 0; i < pThirdResDataEntry->Size; i++)
												vecThirdResRawData.push_back(std::byte(*(pResRawData + i)));
									}

									vecResLvL3.push_back({ *pThirdResDirEntry, std::move(strThirdResName),
										pThirdResDataEntry ? *pThirdResDataEntry : IMAGE_RESOURCE_DATA_ENTRY { 0 }, std::move(vecThirdResRawData) });
									vecThirdResRawData.clear();
									strThirdResName.clear();

									pThirdResDirEntry++;
								}
								tupleResLvL3 = { *pThirdResDir, std::move(vecResLvL3) };
								vecResLvL3.clear();
							}
						}
						else
						{//////Resource LvL2 RAW Data
							pSecondResDataEntry = (PIMAGE_RESOURCE_DATA_ENTRY)((DWORD_PTR)pRootResDir + pSecondResDirEntry->OffsetToData);
							if (pSecondResDataEntry)
							{
								PBYTE pResRawData = (PBYTE)PERVAToPTR(pSecondResDataEntry->OffsetToData);
								if (pResRawData)
									for (unsigned i = 0; i < pSecondResDataEntry->Size; i++)
										vecSecondResRawData.push_back(std::byte(*(pResRawData + i)));
							}
						}
						vecResLvL2.push_back({ *pSecondResDirEntry, std::move(strSecondResName),
							pSecondResDataEntry ? *pSecondResDataEntry : IMAGE_RESOURCE_DATA_ENTRY { 0 },
							std::move(vecSecondResRawData), tupleResLvL3 });
						vecSecondResRawData.clear();
						strSecondResName.clear();

						pSecondResDirEntry++;
					}
					tupleResLvL2 = { *pSecondResDir, std::move(vecResLvL2) };
					vecResLvL2.clear();
				}
			}
			else
			{	//////Resource LvL Root RAW Data
				pRootResDataEntry = (PIMAGE_RESOURCE_DATA_ENTRY)((DWORD_PTR)pRootResDir + pRootResDirEntry->OffsetToData);
				if (pRootResDataEntry)
				{
					PBYTE pResRawData = (PBYTE)PERVAToPTR(pRootResDataEntry->OffsetToData);
					if (pResRawData)
						for (unsigned i = 0; i < pRootResDataEntry->Size; i++)
							vecRootResRawData.push_back(std::byte(*(pResRawData + i)));
				}
			}
			vecResLvLRoot.push_back({ *pRootResDirEntry, std::move(strRootResName),
				pRootResDataEntry ? *pRootResDataEntry : IMAGE_RESOURCE_DATA_ENTRY { 0 }, std::move(vecRootResRawData), tupleResLvL2 });
			vecRootResRawData.clear();
			strRootResName.clear();

			pRootResDirEntry++;
		}
		m_tupResourceTable = { *pRootResDir, std::move(vecResLvLRoot) };
		vecResLvLRoot.clear();
	}
	catch (const std::bad_alloc&)
	{
		delete [] m_szEmergencyMemory;
		MessageBox(0, TEXT("E_OUTOFMEMORY error while trying to get Resource Table."), TEXT("Error"), MB_ICONERROR);

		vecResLvLRoot.clear();
		vecResLvL2.clear();
		vecResLvL3.clear();
		m_szEmergencyMemory = new char[16384];
	}
	m_dwFileSummary |= IMAGE_RESOURCE_DIRECTORY_FLAG;

	return S_OK;
}

HRESULT Clibpe::PEGetExceptionTable()
{
	//IMAGE_RUNTIME_FUNCTION_ENTRY (without leading underscore) 
	//might have different typedef depending on defined platform, see winnt.h
	_PIMAGE_RUNTIME_FUNCTION_ENTRY pRuntimeFuncsEntry = (_PIMAGE_RUNTIME_FUNCTION_ENTRY)PERVAToPTR(PEGetDirEntryRVA(IMAGE_DIRECTORY_ENTRY_EXCEPTION));
	if (!pRuntimeFuncsEntry)
		return IMAGE_HAS_NO_EXCEPTION_DIR;

	DWORD nEntries = PEGetDirEntrySize(IMAGE_DIRECTORY_ENTRY_EXCEPTION) / (DWORD)sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY);
	if (!nEntries)
		return IMAGE_HAS_NO_EXCEPTION_DIR;

	for (unsigned i = 0; i < nEntries; i++, pRuntimeFuncsEntry++)
		m_vecExceptionTable.push_back(*pRuntimeFuncsEntry);

	m_dwFileSummary |= IMAGE_EXCEPTION_DIRECTORY_FLAG;

	return S_OK;
}

HRESULT Clibpe::PEGetSecurityTable()
{
	DWORD dwSecurityDirOffset = PEGetDirEntryRVA(IMAGE_DIRECTORY_ENTRY_SECURITY);
	DWORD dwSecurityDirSize = PEGetDirEntrySize(IMAGE_DIRECTORY_ENTRY_SECURITY);

	if (dwSecurityDirOffset == 0 || dwSecurityDirSize == 0)
		return IMAGE_HAS_NO_SECURITY_DIR;

	ULONGLONG dwSecurityDirStartVA { };
	if (m_fMapViewOfFileWhole)
		dwSecurityDirStartVA = (DWORD_PTR)m_lpBase + dwSecurityDirOffset;
	else
		dwSecurityDirStartVA = (DWORD_PTR)m_lpSectionBase + m_dwDeltaFileOffsetToMap;

	ULONGLONG dwSecurityDirEndVA = dwSecurityDirStartVA + dwSecurityDirSize;

	//Checking for crossing file's size bounds.
	if (dwSecurityDirStartVA >= m_dwMaxPointerBound || dwSecurityDirEndVA > m_dwMaxPointerBound)
		return IMAGE_HAS_NO_SECURITY_DIR;

	LPWIN_CERTIFICATE pSertificate = (LPWIN_CERTIFICATE)dwSecurityDirStartVA;
	std::vector<std::byte> vecCertBytes { };
	while (dwSecurityDirStartVA < dwSecurityDirEndVA)
	{
		for (unsigned i = 0; i < pSertificate->dwLength - offsetof(WIN_CERTIFICATE, bCertificate); i++)
			vecCertBytes.push_back((std::byte)pSertificate->bCertificate[i]);

		m_vecSecurity.push_back({ *pSertificate, std::move(vecCertBytes) });
		vecCertBytes.clear();

		//Get next sertificate entry.
		//All entries starts at 8 rounded address.
		dwSecurityDirStartVA = (pSertificate->dwLength + dwSecurityDirStartVA) % 8 + (pSertificate->dwLength + dwSecurityDirStartVA);
		pSertificate = (LPWIN_CERTIFICATE)dwSecurityDirStartVA;
	}
	m_dwFileSummary |= IMAGE_SECURITY_DIRECTORY_FLAG;

	return S_OK;
}

HRESULT Clibpe::PEGetRelocationTable()
{
	PIMAGE_BASE_RELOCATION pBaseRelocDescriptor = (PIMAGE_BASE_RELOCATION)PERVAToPTR(PEGetDirEntryRVA(IMAGE_DIRECTORY_ENTRY_BASERELOC));

	if (!pBaseRelocDescriptor)
		return IMAGE_HAS_NO_BASERELOC_DIR;

	std::vector<std::tuple<WORD/*type*/, WORD/*offset*/>> vecRelocs { };

	try
	{
		while ((pBaseRelocDescriptor->SizeOfBlock) && (pBaseRelocDescriptor->VirtualAddress))
		{
			if (pBaseRelocDescriptor->SizeOfBlock < sizeof(IMAGE_BASE_RELOCATION))
				return -1;

			//Amount of Reloc entries
			DWORD iRelocEntries = (pBaseRelocDescriptor->SizeOfBlock - (DWORD)sizeof(IMAGE_BASE_RELOCATION)) / (DWORD)sizeof(WORD);
			PWORD pRelocEntry = PWORD((DWORD_PTR)pBaseRelocDescriptor + sizeof(IMAGE_BASE_RELOCATION));
			WORD relocType { };

			for (DWORD i = 0; i < iRelocEntries; i++)
			{
				if ((DWORD_PTR)pRelocEntry >= m_dwMaxPointerBound)
					break;
				// Getting HIGH 4 bits of reloc's entry WORD —> reloc type.
				relocType = (*pRelocEntry & 0xF000) >> 12;
				vecRelocs.push_back({ relocType, ((*pRelocEntry) & 0x0fff)/*Low 12 bits —> Offset*/ });

				if (relocType == IMAGE_REL_BASED_HIGHADJ)
				{   //The base relocation adds the high 16 bits of the difference to the 16-bit field at offset.
					//The 16-bit field represents the high value of a 32-bit word. 
					//The low 16 bits of the 32-bit value are stored in the 16-bit word that follows this base relocation.
					//This means that this base relocation occupies two slots. (MSDN)
					pRelocEntry++;
					vecRelocs.push_back({ relocType, *pRelocEntry/*The low 16-bit field*/ });
					iRelocEntries--; //to compensate pRelocEntry++
				}
				pRelocEntry++;
			}
			m_vecRelocationTable.push_back({ *pBaseRelocDescriptor, std::move(vecRelocs) });
			vecRelocs.clear(); //clear temp vector to fill with next entries

			//Too big (bogus) SizeOfBlock may cause DWORD_PTR overflow
#if INTPTR_MAX == INT32_MAX
			if ((DWORD_PTR)pBaseRelocDescriptor > (UINT_MAX - pBaseRelocDescriptor->SizeOfBlock))
				break;
#elif INTPTR_MAX == INT64_MAX
			if ((DWORD_PTR)pBaseRelocDescriptor > (MAXDWORD64 - pBaseRelocDescriptor->SizeOfBlock))
				break;
#endif
			pBaseRelocDescriptor = PIMAGE_BASE_RELOCATION((DWORD_PTR)pBaseRelocDescriptor + (DWORD_PTR)pBaseRelocDescriptor->SizeOfBlock);
			if ((DWORD_PTR)pBaseRelocDescriptor >= m_dwMaxPointerBound)
				break;
		}
	}
	catch (const std::bad_alloc&)
	{
		delete [] m_szEmergencyMemory;
		MessageBox(0, L"E_OUTOFMEMORY error while trying to get Relocation Table.", L"Error", MB_ICONERROR);

		vecRelocs.clear();
		m_szEmergencyMemory = new char[16384];
	}

	m_dwFileSummary |= IMAGE_BASERELOC_DIRECTORY_FLAG;

	return S_OK;
}

HRESULT Clibpe::PEGetDebugTable()
{
	DWORD dwDebugDirRVA = PEGetDirEntryRVA(IMAGE_DIRECTORY_ENTRY_DEBUG);

	if (!dwDebugDirRVA)
		return IMAGE_HAS_NO_DEBUG_DIR;

	PIMAGE_DEBUG_DIRECTORY pDebugDir { };
	DWORD dwDebugDirSize { };
	PIMAGE_SECTION_HEADER pDebugSecHeader = PEGetSecHeaderFromName(".debug");

	if (pDebugSecHeader && (pDebugSecHeader->VirtualAddress == dwDebugDirRVA))
	{
		if (m_fMapViewOfFileWhole)
			pDebugDir = (PIMAGE_DEBUG_DIRECTORY)((DWORD_PTR)pDebugSecHeader->PointerToRawData + (DWORD_PTR)m_lpBase);
		else
			pDebugDir = (PIMAGE_DEBUG_DIRECTORY)((DWORD_PTR)m_lpSectionBase + (DWORD_PTR)m_dwDeltaFileOffsetToMap);

		dwDebugDirSize = PEGetDirEntrySize(IMAGE_DIRECTORY_ENTRY_DEBUG) * (DWORD)sizeof(IMAGE_DEBUG_DIRECTORY);
	}
	else // Looking for the debug directory
	{
		pDebugSecHeader = PEGetSecHeaderFromRVA(dwDebugDirRVA);
		if (!pDebugSecHeader)
			return IMAGE_HAS_NO_DEBUG_DIR;

		if (!(pDebugDir = (PIMAGE_DEBUG_DIRECTORY)PERVAToPTR(dwDebugDirRVA)))
			return IMAGE_HAS_NO_DEBUG_DIR;

		dwDebugDirSize = PEGetDirEntrySize(IMAGE_DIRECTORY_ENTRY_DEBUG);
	}

	DWORD nDebugEntries = dwDebugDirSize / (DWORD)sizeof(IMAGE_DEBUG_DIRECTORY);

	if (!nDebugEntries)
		return -1;

	for (unsigned i = 0; i < nDebugEntries; i++)
	{
		m_vecDebugTable.push_back(*pDebugDir);
		pDebugDir++;
	}
	m_dwFileSummary |= IMAGE_DEBUG_DIRECTORY_FLAG;

	return S_OK;
}

HRESULT Clibpe::PEGetArchitectureTable()
{
	DWORD dwArchDirRVA = PEGetDirEntryRVA(IMAGE_DIRECTORY_ENTRY_ARCHITECTURE);
	if (!dwArchDirRVA)
		return IMAGE_HAS_NO_ARCHITECTURE_DIR;

	PIMAGE_ARCHITECTURE_ENTRY pArchEntry = (PIMAGE_ARCHITECTURE_ENTRY)PERVAToPTR(dwArchDirRVA);
	if (!pArchEntry)
		return IMAGE_HAS_NO_ARCHITECTURE_DIR;

	m_dwFileSummary |= IMAGE_ARCHITECTURE_DIRECTORY_FLAG;

	return S_OK;
}

HRESULT Clibpe::PEGetGlobalPTRTable()
{
	DWORD_PTR dwGlobalPTRDirRVA = (DWORD_PTR)PERVAToPTR(PEGetDirEntryRVA(IMAGE_DIRECTORY_ENTRY_GLOBALPTR));
	if (!dwGlobalPTRDirRVA)
		return IMAGE_HAS_NO_GLOBALPTR_DIR;

	m_dwFileSummary |= IMAGE_GLOBALPTR_DIRECTORY_FLAG;

	return S_OK;
}

HRESULT Clibpe::PEGetTLSTable()
{
	DWORD dwTLSDirRVA = PEGetDirEntryRVA(IMAGE_DIRECTORY_ENTRY_TLS);
	if (!dwTLSDirRVA)
		return IMAGE_HAS_NO_TLS_DIR;

	PIMAGE_TLS_DIRECTORY32 pTLSDir32 { };
	PIMAGE_TLS_DIRECTORY64 pTLSDir64 { };
	std::vector<std::byte> vecTLSRawData { };
	std::vector<DWORD> vecTLSCallbacks { };

	if (IMAGE_HAS_FLAG(m_dwFileSummary, IMAGE_PE32_FLAG))
	{
		pTLSDir32 = (PIMAGE_TLS_DIRECTORY32)PERVAToPTR(dwTLSDirRVA);
		if (!pTLSDir32)
			return IMAGE_HAS_NO_TLS_DIR;

		m_tupTLS = { *pTLSDir32, IMAGE_TLS_DIRECTORY64 { 0 }, vecTLSRawData, vecTLSCallbacks };
	}
	else if (IMAGE_HAS_FLAG(m_dwFileSummary, IMAGE_PE64_FLAG))
	{
		pTLSDir64 = (PIMAGE_TLS_DIRECTORY64)PERVAToPTR(dwTLSDirRVA);
		if (!pTLSDir64)
			return IMAGE_HAS_NO_TLS_DIR;

		m_tupTLS = { IMAGE_TLS_DIRECTORY32 { 0 }, *pTLSDir64, std::move(vecTLSRawData), std::move(vecTLSCallbacks) };
	}
	m_dwFileSummary |= IMAGE_TLS_DIRECTORY_FLAG;

	return S_OK;
}

HRESULT Clibpe::PEGetLoadConfigTable()
{
	PIMAGE_LOAD_CONFIG_DIRECTORY32 pLoadConfigDir32 { };
	PIMAGE_LOAD_CONFIG_DIRECTORY64 pLoadConfigDir64 { };

	if (IMAGE_HAS_FLAG(m_dwFileSummary, IMAGE_PE32_FLAG))
	{
		pLoadConfigDir32 = (PIMAGE_LOAD_CONFIG_DIRECTORY32)PERVAToPTR(PEGetDirEntryRVA(IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG));
		if (!pLoadConfigDir32)
			return IMAGE_HAS_NO_LOADCONFIG_DIR;

		m_tupLoadConfigDir = { *pLoadConfigDir32, IMAGE_LOAD_CONFIG_DIRECTORY64 { 0 } };
	}
	else if (IMAGE_HAS_FLAG(m_dwFileSummary, IMAGE_PE64_FLAG))
	{
		pLoadConfigDir64 = (PIMAGE_LOAD_CONFIG_DIRECTORY64)PERVAToPTR(PEGetDirEntryRVA(IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG));
		if (!pLoadConfigDir64)
			return IMAGE_HAS_NO_LOADCONFIG_DIR;

		m_tupLoadConfigDir = { IMAGE_LOAD_CONFIG_DIRECTORY32 { 0 }, *pLoadConfigDir64 };
	}
	m_dwFileSummary |= IMAGE_LOADCONFIG_DIRECTORY_FLAG;

	return S_OK;
}

HRESULT Clibpe::PEGetBoundImportTable()
{
	PIMAGE_BOUND_IMPORT_DESCRIPTOR pBoundImpDesc =
		(PIMAGE_BOUND_IMPORT_DESCRIPTOR)PERVAToPTR(PEGetDirEntryRVA(IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT));

	if (!pBoundImpDesc)
		return IMAGE_HAS_NO_BOUNDIMPORT_DIR;

	std::vector<std::tuple<IMAGE_BOUND_FORWARDER_REF, std::string>> vecBoundForwarders { };
	std::string strModuleName { };

	while (pBoundImpDesc->TimeDateStamp)
	{
		PIMAGE_BOUND_FORWARDER_REF pBoundImpForwarder = (PIMAGE_BOUND_FORWARDER_REF)(pBoundImpDesc + 1);

		for (unsigned i = 0; i < pBoundImpDesc->NumberOfModuleForwarderRefs; i++)
		{
			LPCSTR szName = (LPCSTR)((DWORD_PTR)pBoundImpDesc + pBoundImpForwarder->OffsetModuleName);
			if (szName && (StringCchLengthA(szName, MAX_PATH, nullptr) != STRSAFE_E_INVALID_PARAMETER))
				strModuleName = szName;

			vecBoundForwarders.push_back({ *pBoundImpForwarder, std::move(strModuleName) });
			strModuleName.clear();

			pBoundImpForwarder++;
			pBoundImpDesc = (PIMAGE_BOUND_IMPORT_DESCRIPTOR)((DWORD_PTR)pBoundImpDesc + sizeof(IMAGE_BOUND_FORWARDER_REF));
		}

		LPCSTR szName = (LPCSTR)((DWORD_PTR)pBoundImpDesc + pBoundImpDesc->OffsetModuleName);
		if (szName && (StringCchLengthA(szName, MAX_PATH, nullptr) != STRSAFE_E_INVALID_PARAMETER))
			strModuleName = szName;

		m_vecBoundImportTable.push_back({ *pBoundImpDesc, std::move(strModuleName), std::move(vecBoundForwarders) });
		vecBoundForwarders.clear();
		strModuleName.clear();

		pBoundImpDesc++;
	}
	m_dwFileSummary |= IMAGE_BOUNDIMPORT_DIRECTORY_FLAG;

	return S_OK;
}

HRESULT Clibpe::PEGetIATTable()
{
	DWORD_PTR dwIATDirRVA = (DWORD_PTR)PERVAToPTR(PEGetDirEntryRVA(IMAGE_DIRECTORY_ENTRY_IAT));
	if (!dwIATDirRVA)
		return IMAGE_HAS_NO_IAT_DIR;

	m_dwFileSummary |= IMAGE_IAT_DIRECTORY_FLAG;

	return S_OK;
}

HRESULT Clibpe::PEGetDelayImportTable()
{
	PIMAGE_DELAYLOAD_DESCRIPTOR pDelayImpDescriptor = (PIMAGE_DELAYLOAD_DESCRIPTOR)PERVAToPTR(PEGetDirEntryRVA(IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT));
	if (!pDelayImpDescriptor)
		return IMAGE_HAS_NO_DELAY_IMPORT_DIR;

	PIMAGE_THUNK_DATA32 pThunk32IAT { }, pThunk32Name { }, pThunk32BoundIAT { }, pThunk32UnloadInfoIAT { };
	PIMAGE_THUNK_DATA64 pThunk64IAT { }, pThunk64Name { }, pThunk64BoundIAT { }, pThunk64UnloadInfoIAT { };
	std::vector<std::tuple<LONGLONG/*Ordinal/Hint*/, std::string/*Func name*/, LONGLONG/*Thunk table RVA*/,
		LONGLONG/*IAT->u1.AddressOfData*/, LONGLONG/*BoundIAT->u1.AddressOfData*/, LONGLONG/*UnloadInfoIAT->u1.AddressOfData*/>> vecFunc { };
	std::string strDllName { };

	if (IMAGE_HAS_FLAG(m_dwFileSummary, IMAGE_PE32_FLAG))
	{
		while (pDelayImpDescriptor->DllNameRVA)
		{
			pThunk32Name = (PIMAGE_THUNK_DATA32)(DWORD_PTR)pDelayImpDescriptor->ImportNameTableRVA;

			if (!pThunk32Name)
				pDelayImpDescriptor++;
			else
			{
				pThunk32Name = (PIMAGE_THUNK_DATA32)PERVAToPTR((DWORD_PTR)pThunk32Name);
				pThunk32IAT = (PIMAGE_THUNK_DATA32)PERVAToPTR(pDelayImpDescriptor->ImportAddressTableRVA);
				pThunk32BoundIAT = (PIMAGE_THUNK_DATA32)PERVAToPTR(pDelayImpDescriptor->BoundImportAddressTableRVA);
				pThunk32UnloadInfoIAT = (PIMAGE_THUNK_DATA32)PERVAToPTR(pDelayImpDescriptor->UnloadInformationTableRVA);

				if (!pThunk32Name)
					return IMAGE_HAS_NO_DELAY_IMPORT_DIR;

				while (pThunk32Name->u1.AddressOfData)
				{
					if (pThunk32Name->u1.Ordinal & IMAGE_ORDINAL_FLAG32)
						vecFunc.push_back({ IMAGE_ORDINAL32(pThunk32Name->u1.Ordinal), "",
							pThunk32Name->u1.AddressOfData,
							pThunk32IAT ? pThunk32IAT->u1.AddressOfData : 0,
							pThunk32BoundIAT ? pThunk32BoundIAT->u1.AddressOfData : 0,
							pThunk32UnloadInfoIAT ? pThunk32UnloadInfoIAT->u1.AddressOfData : 0 });
					else {//filling Hint, Name and Thunk RVA
						PIMAGE_IMPORT_BY_NAME pName = (PIMAGE_IMPORT_BY_NAME)PERVAToPTR(pThunk32Name->u1.AddressOfData);
						if (pName && (StringCchLengthA(pName->Name, MAX_PATH, nullptr) != STRSAFE_E_INVALID_PARAMETER))
							strDllName = pName->Name;

						vecFunc.push_back({ pName ? pName->Hint : 0, std::move(strDllName),
							pThunk32Name->u1.AddressOfData,
							pThunk32IAT ? pThunk32IAT->u1.AddressOfData : 0,
							pThunk32BoundIAT ? pThunk32BoundIAT->u1.AddressOfData : 0,
							pThunk32UnloadInfoIAT ? pThunk32UnloadInfoIAT->u1.AddressOfData : 0 });
					}

					pThunk32Name++;
					if (pThunk32IAT)
						pThunk32IAT++;
					if (pThunk32BoundIAT)
						pThunk32BoundIAT++;
					if (pThunk32UnloadInfoIAT)
						pThunk32UnloadInfoIAT++;

					strDllName.clear();
				}

				LPCSTR szName = (LPCSTR)PERVAToPTR(pDelayImpDescriptor->DllNameRVA);
				if (szName && (StringCchLengthA(szName, MAX_PATH, nullptr) != STRSAFE_E_INVALID_PARAMETER))
					strDllName = szName;

				m_vecDelayImportTable.push_back({ *pDelayImpDescriptor, std::move(strDllName), std::move(vecFunc) });
				vecFunc.clear();
				strDllName.clear();

				pDelayImpDescriptor++;
			}
		}
	}
	else if (IMAGE_HAS_FLAG(m_dwFileSummary, IMAGE_PE64_FLAG))
	{
		while (pDelayImpDescriptor->DllNameRVA)
		{
			pThunk64Name = (PIMAGE_THUNK_DATA64)(DWORD_PTR)pDelayImpDescriptor->ImportNameTableRVA;

			if (!pThunk64Name)
				pDelayImpDescriptor++;
			else
			{
				pThunk64Name = (PIMAGE_THUNK_DATA64)PERVAToPTR((DWORD_PTR)pThunk64Name);
				pThunk64IAT = (PIMAGE_THUNK_DATA64)PERVAToPTR(pDelayImpDescriptor->ImportAddressTableRVA);
				pThunk64BoundIAT = (PIMAGE_THUNK_DATA64)PERVAToPTR(pDelayImpDescriptor->BoundImportAddressTableRVA);
				pThunk64UnloadInfoIAT = (PIMAGE_THUNK_DATA64)PERVAToPTR(pDelayImpDescriptor->UnloadInformationTableRVA);

				if (!pThunk64Name)
					return IMAGE_HAS_NO_DELAY_IMPORT_DIR;

				while (pThunk64Name->u1.AddressOfData)
				{
					if (pThunk64Name->u1.Ordinal & IMAGE_ORDINAL_FLAG64)
						vecFunc.push_back({ IMAGE_ORDINAL64(pThunk64Name->u1.Ordinal), "",
							pThunk64Name->u1.AddressOfData,
							pThunk64IAT ? pThunk64IAT->u1.AddressOfData : 0,
							pThunk64BoundIAT ? pThunk64BoundIAT->u1.AddressOfData : 0,
							pThunk64UnloadInfoIAT ? pThunk64UnloadInfoIAT->u1.AddressOfData : 0 });
					else {//filling Hint, Name and Thunk RVA
						PIMAGE_IMPORT_BY_NAME pName = (PIMAGE_IMPORT_BY_NAME)PERVAToPTR(pThunk64Name->u1.AddressOfData);
						if (pName && (StringCchLengthA(pName->Name, MAX_PATH, nullptr) != STRSAFE_E_INVALID_PARAMETER))
							strDllName = pName->Name;

						vecFunc.push_back({ pName ? pName->Hint : 0, std::move(strDllName),
							pThunk64Name->u1.AddressOfData,
							pThunk64IAT ? pThunk64IAT->u1.AddressOfData : 0,
							pThunk64BoundIAT ? pThunk64BoundIAT->u1.AddressOfData : 0,
							pThunk64UnloadInfoIAT ? pThunk64UnloadInfoIAT->u1.AddressOfData : 0 });
					}

					pThunk64Name++;
					if (pThunk64IAT)
						pThunk64IAT++;
					if (pThunk64BoundIAT)
						pThunk64BoundIAT++;
					if (pThunk64UnloadInfoIAT)
						pThunk64UnloadInfoIAT++;

					strDllName.clear();
				}

				LPCSTR szName = (LPCSTR)PERVAToPTR(pDelayImpDescriptor->DllNameRVA);
				if (szName && (StringCchLengthA(szName, MAX_PATH, nullptr) != STRSAFE_E_INVALID_PARAMETER))
					strDllName = szName;

				m_vecDelayImportTable.push_back({ *pDelayImpDescriptor, std::move(strDllName), std::move(vecFunc) });
				vecFunc.clear();
				strDllName.clear();

				pDelayImpDescriptor++;
			}
		}
	}
	m_dwFileSummary |= IMAGE_DELAYIMPORT_DIRECTORY_FLAG;

	return S_OK;
}

HRESULT Clibpe::PEGetCOMDescriptorTable()
{
	PIMAGE_COR20_HEADER pCOMDescriptorHeader = (PIMAGE_COR20_HEADER)PERVAToPTR(PEGetDirEntryRVA(IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR));
	if (!pCOMDescriptorHeader)
		return IMAGE_HAS_NO_COMDESCRIPTOR_DIR;

	m_stCOR20Header = *pCOMDescriptorHeader;

	m_dwFileSummary |= IMAGE_COMDESCRIPTOR_DIRECTORY_FLAG;

	return S_OK;
}
