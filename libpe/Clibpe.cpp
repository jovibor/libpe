#include "stdafx.h"
#include "libpe.h"
#include "Clibpe.h"

Clibpe::~Clibpe()
{
	delete [] m_lpszEmergencyMemory;
}

HRESULT Clibpe::LoadPe(LPCWSTR lpszFile)
{
	if (m_lpBase)//if it's not the first LoadPe call from the Ilibpe pointer
		PEResetAll();//sets all members to zero and clear() vectors

	HANDLE _hFile = CreateFileW(lpszFile, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (_hFile == INVALID_HANDLE_VALUE)
		return FILE_OPEN_FAILED;

	::GetFileSizeEx(_hFile, &m_stFileSize);
	if (m_stFileSize.QuadPart < sizeof(IMAGE_DOS_HEADER))
	{
		CloseHandle(_hFile);
		return FILE_SIZE_TOO_SMALL;
	}

	m_hMapObject = CreateFileMappingW(_hFile, NULL, PAGE_READONLY, 0, 0, NULL);
	if (!m_hMapObject)
	{
		CloseHandle(_hFile);
		return FILE_CREATE_FILE_MAPPING_FAILED;
	}

	m_lpBase = MapViewOfFile(m_hMapObject, FILE_MAP_READ, 0, 0, 0);
	if (!m_lpBase)//Not enough memmory?(File is too big?)...
	{
		if (GetLastError() == ERROR_NOT_ENOUGH_MEMORY)
		{
			//If file is too big to fit process VirtualSize limit
			//we try to allocate at least some memory to map file's beginning, where PE HEADER resides.
			//Then going to MapViewOfFile/Unmap every section separately. 
			if (!(m_lpBase = MapViewOfFile(m_hMapObject, FILE_MAP_READ, 0, 0, 0xFFFF)))
			{
				CloseHandle(m_hMapObject);
				CloseHandle(_hFile);
				return FILE_MAP_VIEW_OF_FILE_FAILED;
			}
			m_fMapViewOfFileWhole = false;
			m_dwMaxPointerBound = (DWORD_PTR)m_lpBase + 0xFFFF;
		}
		else
		{
			CloseHandle(m_hMapObject);
			CloseHandle(_hFile);
			return FILE_MAP_VIEW_OF_FILE_FAILED;
		}
	}
	else {
		m_fMapViewOfFileWhole = true;
		m_dwMaxPointerBound = (DWORD_PTR)m_lpBase + m_stFileSize.QuadPart;
	}

	HRESULT hr = PEGetHeaders();
	if (hr != S_OK)
	{//If at least IMAGE_DOS_SIGNATURE found then returning S_OK.
	 //Some PE files may consist of only DOS stub.
		if (hr != IMAGE_DOS_SIGNATURE_MISMATCH)
			hr = S_OK;

		UnmapViewOfFile(m_lpBase);
		CloseHandle(m_hMapObject);
		CloseHandle(_hFile);

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
		SYSTEM_INFO _SysInfo { };
		::GetSystemInfo(&_SysInfo);
		DWORD _dwAlignedAddressToMap { };
		SIZE_T _ulSizeToMap { };
		PIMAGE_SECTION_HEADER _pSec { };

		if (_pSec = PEGetSectionHeaderFromRVA(PEGetDirectoryEntryRVA(IMAGE_DIRECTORY_ENTRY_EXPORT)))
		{
			m_dwFileOffsetToMap = _pSec->PointerToRawData;

			if (m_dwFileOffsetToMap % _SysInfo.dwAllocationGranularity > 0)
			{
				_dwAlignedAddressToMap = (m_dwFileOffsetToMap < _SysInfo.dwAllocationGranularity) ? 0 :
					(m_dwFileOffsetToMap - (m_dwFileOffsetToMap % _SysInfo.dwAllocationGranularity));
			}
			else
				_dwAlignedAddressToMap = m_dwFileOffsetToMap;

			m_dwDeltaFileOffsetToMap = m_dwFileOffsetToMap - _dwAlignedAddressToMap;
			_ulSizeToMap = (_pSec->Misc.VirtualSize + m_dwFileOffsetToMap) > m_stFileSize.QuadPart ?
				SIZE_T(m_stFileSize.QuadPart - m_dwFileOffsetToMap) : SIZE_T(_pSec->Misc.VirtualSize + m_dwDeltaFileOffsetToMap);

			if (!(m_lpSectionBase = MapViewOfFile(m_hMapObject, FILE_MAP_READ, 0, _dwAlignedAddressToMap, _ulSizeToMap)))
				return FILE_MAP_VIEW_OF_FILE_FAILED;

			m_dwMaxPointerBound = (DWORD_PTR)m_lpSectionBase + _ulSizeToMap;
			PEGetExportTable();
			UnmapViewOfFile(m_lpSectionBase);
		}

		if (_pSec = PEGetSectionHeaderFromRVA(PEGetDirectoryEntryRVA(IMAGE_DIRECTORY_ENTRY_IMPORT)))
		{
			m_dwFileOffsetToMap = _pSec->PointerToRawData;

			if (m_dwFileOffsetToMap % _SysInfo.dwAllocationGranularity > 0)
			{
				_dwAlignedAddressToMap = (m_dwFileOffsetToMap < _SysInfo.dwAllocationGranularity) ? 0 :
					(m_dwFileOffsetToMap - (m_dwFileOffsetToMap % _SysInfo.dwAllocationGranularity));
			}
			else
				_dwAlignedAddressToMap = m_dwFileOffsetToMap;

			m_dwDeltaFileOffsetToMap = m_dwFileOffsetToMap - _dwAlignedAddressToMap;
			_ulSizeToMap = (_pSec->Misc.VirtualSize + m_dwFileOffsetToMap) > m_stFileSize.QuadPart ?
				SIZE_T(m_stFileSize.QuadPart - m_dwFileOffsetToMap) : SIZE_T(_pSec->Misc.VirtualSize + m_dwDeltaFileOffsetToMap);

			if (!(m_lpSectionBase = MapViewOfFile(m_hMapObject, FILE_MAP_READ, 0, _dwAlignedAddressToMap, _ulSizeToMap)))
				return GetLastError();

			m_dwMaxPointerBound = (DWORD_PTR)m_lpSectionBase + _ulSizeToMap;
			PEGetImportTable();
			UnmapViewOfFile(m_lpSectionBase);
		}

		if (_pSec = PEGetSectionHeaderFromRVA(PEGetDirectoryEntryRVA(IMAGE_DIRECTORY_ENTRY_RESOURCE)))
		{
			m_dwFileOffsetToMap = _pSec->PointerToRawData;

			if (m_dwFileOffsetToMap % _SysInfo.dwAllocationGranularity > 0)
			{
				_dwAlignedAddressToMap = (m_dwFileOffsetToMap < _SysInfo.dwAllocationGranularity) ? 0 :
					(m_dwFileOffsetToMap - (m_dwFileOffsetToMap % _SysInfo.dwAllocationGranularity));
			}
			else
				_dwAlignedAddressToMap = m_dwFileOffsetToMap;

			m_dwDeltaFileOffsetToMap = m_dwFileOffsetToMap - _dwAlignedAddressToMap;
			_ulSizeToMap = (_pSec->Misc.VirtualSize + m_dwFileOffsetToMap) > m_stFileSize.QuadPart ?
				SIZE_T(m_stFileSize.QuadPart - m_dwFileOffsetToMap) : SIZE_T(_pSec->Misc.VirtualSize + m_dwDeltaFileOffsetToMap);

			if (!(m_lpSectionBase = MapViewOfFile(m_hMapObject, FILE_MAP_READ, 0, _dwAlignedAddressToMap, _ulSizeToMap)))
				return FILE_MAP_VIEW_OF_FILE_FAILED;

			m_dwMaxPointerBound = (DWORD_PTR)m_lpSectionBase + _ulSizeToMap;
			PEGetResourceTable();
			UnmapViewOfFile(m_lpSectionBase);
		}

		if (_pSec = PEGetSectionHeaderFromRVA(PEGetDirectoryEntryRVA(IMAGE_DIRECTORY_ENTRY_EXCEPTION)))
		{
			m_dwFileOffsetToMap = _pSec->PointerToRawData;

			if (m_dwFileOffsetToMap % _SysInfo.dwAllocationGranularity > 0)
			{
				_dwAlignedAddressToMap = (m_dwFileOffsetToMap < _SysInfo.dwAllocationGranularity) ? 0 :
					(m_dwFileOffsetToMap - (m_dwFileOffsetToMap % _SysInfo.dwAllocationGranularity));
			}
			else
				_dwAlignedAddressToMap = m_dwFileOffsetToMap;

			m_dwDeltaFileOffsetToMap = m_dwFileOffsetToMap - _dwAlignedAddressToMap;
			_ulSizeToMap = (_pSec->Misc.VirtualSize + m_dwFileOffsetToMap) > m_stFileSize.QuadPart ?
				SIZE_T(m_stFileSize.QuadPart - m_dwFileOffsetToMap) : SIZE_T(_pSec->Misc.VirtualSize + m_dwDeltaFileOffsetToMap);

			if (!(m_lpSectionBase = MapViewOfFile(m_hMapObject, FILE_MAP_READ, 0, _dwAlignedAddressToMap, _ulSizeToMap)))
				return FILE_MAP_VIEW_OF_FILE_FAILED;

			m_dwMaxPointerBound = (DWORD_PTR)m_lpSectionBase + _ulSizeToMap;
			PEGetExceptionTable();
			UnmapViewOfFile(m_lpSectionBase);
		}

		if (PEGetDirectoryEntryRVA(IMAGE_DIRECTORY_ENTRY_SECURITY))
		{/////////////////////This is actual file RAW offset
			m_dwFileOffsetToMap = PEGetDirectoryEntryRVA(IMAGE_DIRECTORY_ENTRY_SECURITY);

			//Checking for exceeding file size bound
			if (m_dwFileOffsetToMap < m_stFileSize.QuadPart)
			{
				if (m_dwFileOffsetToMap % _SysInfo.dwAllocationGranularity > 0)
				{
					_dwAlignedAddressToMap = (m_dwFileOffsetToMap < _SysInfo.dwAllocationGranularity) ? 0 :
						(m_dwFileOffsetToMap - (m_dwFileOffsetToMap % _SysInfo.dwAllocationGranularity));
				}
				else
					_dwAlignedAddressToMap = m_dwFileOffsetToMap;

				m_dwDeltaFileOffsetToMap = m_dwFileOffsetToMap - _dwAlignedAddressToMap;

				_ulSizeToMap = SIZE_T(PEGetDirectoryEntrySize(IMAGE_DIRECTORY_ENTRY_SECURITY) + m_dwDeltaFileOffsetToMap);
				//Checking for out of bounds file sizes to map.
				if (((LONGLONG)m_dwFileOffsetToMap + (LONGLONG)_ulSizeToMap) <= (m_stFileSize.QuadPart))
				{
					if (!(m_lpSectionBase = MapViewOfFile(m_hMapObject, FILE_MAP_READ, 0, _dwAlignedAddressToMap, _ulSizeToMap)))
						return FILE_MAP_VIEW_OF_FILE_FAILED;

					m_dwMaxPointerBound = (DWORD_PTR)m_lpSectionBase + _ulSizeToMap;
					PEGetSecurityTable();
					UnmapViewOfFile(m_lpSectionBase);
				}
			}
		}

		if (_pSec = PEGetSectionHeaderFromRVA(PEGetDirectoryEntryRVA(IMAGE_DIRECTORY_ENTRY_BASERELOC)))
		{
			m_dwFileOffsetToMap = _pSec->PointerToRawData;

			if (m_dwFileOffsetToMap % _SysInfo.dwAllocationGranularity > 0)
			{
				_dwAlignedAddressToMap = (m_dwFileOffsetToMap < _SysInfo.dwAllocationGranularity) ? 0 :
					(m_dwFileOffsetToMap - (m_dwFileOffsetToMap % _SysInfo.dwAllocationGranularity));
			}
			else
				_dwAlignedAddressToMap = m_dwFileOffsetToMap;

			m_dwDeltaFileOffsetToMap = m_dwFileOffsetToMap - _dwAlignedAddressToMap;
			_ulSizeToMap = (_pSec->Misc.VirtualSize + m_dwFileOffsetToMap) > m_stFileSize.QuadPart ?
				SIZE_T(m_stFileSize.QuadPart - m_dwFileOffsetToMap) : SIZE_T(_pSec->Misc.VirtualSize + m_dwDeltaFileOffsetToMap);

			if (!(m_lpSectionBase = MapViewOfFile(m_hMapObject, FILE_MAP_READ, 0, _dwAlignedAddressToMap, _ulSizeToMap)))
				return FILE_MAP_VIEW_OF_FILE_FAILED;

			m_dwMaxPointerBound = (DWORD_PTR)m_lpSectionBase + _ulSizeToMap;
			PEGetRelocationTable();
			UnmapViewOfFile(m_lpSectionBase);
		}

		if (_pSec = PEGetSectionHeaderFromRVA(PEGetDirectoryEntryRVA(IMAGE_DIRECTORY_ENTRY_DEBUG)))
		{
			m_dwFileOffsetToMap = _pSec->PointerToRawData;

			if (m_dwFileOffsetToMap % _SysInfo.dwAllocationGranularity > 0)
			{
				_dwAlignedAddressToMap = (m_dwFileOffsetToMap < _SysInfo.dwAllocationGranularity) ? 0 :
					(m_dwFileOffsetToMap - (m_dwFileOffsetToMap % _SysInfo.dwAllocationGranularity));
			}
			else
				_dwAlignedAddressToMap = m_dwFileOffsetToMap;

			m_dwDeltaFileOffsetToMap = m_dwFileOffsetToMap - _dwAlignedAddressToMap;
			_ulSizeToMap = (_pSec->Misc.VirtualSize + m_dwFileOffsetToMap) > m_stFileSize.QuadPart ?
				SIZE_T(m_stFileSize.QuadPart - m_dwFileOffsetToMap) : SIZE_T(_pSec->Misc.VirtualSize + m_dwDeltaFileOffsetToMap);

			if (!(m_lpSectionBase = MapViewOfFile(m_hMapObject, FILE_MAP_READ, 0, _dwAlignedAddressToMap, _ulSizeToMap)))
				return FILE_MAP_VIEW_OF_FILE_FAILED;

			m_dwMaxPointerBound = (DWORD_PTR)m_lpSectionBase + _ulSizeToMap;
			PEGetDebugTable();
			UnmapViewOfFile(m_lpSectionBase);
		}

		if (_pSec = PEGetSectionHeaderFromRVA(PEGetDirectoryEntryRVA(IMAGE_DIRECTORY_ENTRY_TLS)))
		{
			m_dwFileOffsetToMap = _pSec->PointerToRawData;

			if (m_dwFileOffsetToMap % _SysInfo.dwAllocationGranularity > 0)
			{
				_dwAlignedAddressToMap = (m_dwFileOffsetToMap < _SysInfo.dwAllocationGranularity) ? 0 :
					(m_dwFileOffsetToMap - (m_dwFileOffsetToMap % _SysInfo.dwAllocationGranularity));
			}
			else
				_dwAlignedAddressToMap = m_dwFileOffsetToMap;

			m_dwDeltaFileOffsetToMap = m_dwFileOffsetToMap - _dwAlignedAddressToMap;
			_ulSizeToMap = (_pSec->Misc.VirtualSize + m_dwFileOffsetToMap) > m_stFileSize.QuadPart ?
				SIZE_T(m_stFileSize.QuadPart - m_dwFileOffsetToMap) : SIZE_T(_pSec->Misc.VirtualSize + m_dwDeltaFileOffsetToMap);

			if (!(m_lpSectionBase = MapViewOfFile(m_hMapObject, FILE_MAP_READ, 0, _dwAlignedAddressToMap, _ulSizeToMap)))
				return FILE_MAP_VIEW_OF_FILE_FAILED;

			m_dwMaxPointerBound = (DWORD_PTR)m_lpSectionBase + _ulSizeToMap;
			PEGetTLSTable();
			UnmapViewOfFile(m_lpSectionBase);
		}

		if (_pSec = PEGetSectionHeaderFromRVA(PEGetDirectoryEntryRVA(IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG)))
		{
			m_dwFileOffsetToMap = _pSec->PointerToRawData;

			if (m_dwFileOffsetToMap % _SysInfo.dwAllocationGranularity > 0)
			{
				_dwAlignedAddressToMap = (m_dwFileOffsetToMap < _SysInfo.dwAllocationGranularity) ? 0 :
					(m_dwFileOffsetToMap - (m_dwFileOffsetToMap % _SysInfo.dwAllocationGranularity));
			}
			else
				_dwAlignedAddressToMap = m_dwFileOffsetToMap;

			m_dwDeltaFileOffsetToMap = m_dwFileOffsetToMap - _dwAlignedAddressToMap;
			_ulSizeToMap = (_pSec->Misc.VirtualSize + m_dwFileOffsetToMap) > m_stFileSize.QuadPart ?
				SIZE_T(m_stFileSize.QuadPart - m_dwFileOffsetToMap) : SIZE_T(_pSec->Misc.VirtualSize + m_dwDeltaFileOffsetToMap);

			if (!(m_lpSectionBase = MapViewOfFile(m_hMapObject, FILE_MAP_READ, 0, _dwAlignedAddressToMap, _ulSizeToMap)))
				return FILE_MAP_VIEW_OF_FILE_FAILED;

			m_dwMaxPointerBound = (DWORD_PTR)m_lpSectionBase + _ulSizeToMap;
			PEGetLoadConfigTable();
			UnmapViewOfFile(m_lpSectionBase);
		}

		if (_pSec = PEGetSectionHeaderFromRVA(PEGetDirectoryEntryRVA(IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT)))
		{
			m_dwFileOffsetToMap = _pSec->PointerToRawData;

			if (m_dwFileOffsetToMap % _SysInfo.dwAllocationGranularity > 0)
			{
				_dwAlignedAddressToMap = (m_dwFileOffsetToMap < _SysInfo.dwAllocationGranularity) ? 0 :
					(m_dwFileOffsetToMap - (m_dwFileOffsetToMap % _SysInfo.dwAllocationGranularity));
			}
			else
				_dwAlignedAddressToMap = m_dwFileOffsetToMap;

			m_dwDeltaFileOffsetToMap = m_dwFileOffsetToMap - _dwAlignedAddressToMap;
			_ulSizeToMap = (_pSec->Misc.VirtualSize + m_dwFileOffsetToMap) > m_stFileSize.QuadPart ?
				SIZE_T(m_stFileSize.QuadPart - m_dwFileOffsetToMap) : SIZE_T(_pSec->Misc.VirtualSize + m_dwDeltaFileOffsetToMap);

			if (!(m_lpSectionBase = MapViewOfFile(m_hMapObject, FILE_MAP_READ, 0, _dwAlignedAddressToMap, _ulSizeToMap)))
				return FILE_MAP_VIEW_OF_FILE_FAILED;

			m_dwMaxPointerBound = (DWORD_PTR)m_lpSectionBase + _ulSizeToMap;
			PEGetBoundImportTable();
			UnmapViewOfFile(m_lpSectionBase);
		}

		if (_pSec = PEGetSectionHeaderFromRVA(PEGetDirectoryEntryRVA(IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT)))
		{
			m_dwFileOffsetToMap = _pSec->PointerToRawData;

			if (m_dwFileOffsetToMap % _SysInfo.dwAllocationGranularity > 0)
			{
				_dwAlignedAddressToMap = (m_dwFileOffsetToMap < _SysInfo.dwAllocationGranularity) ? 0 :
					(m_dwFileOffsetToMap - (m_dwFileOffsetToMap % _SysInfo.dwAllocationGranularity));
			}
			else
				_dwAlignedAddressToMap = m_dwFileOffsetToMap;

			m_dwDeltaFileOffsetToMap = m_dwFileOffsetToMap - _dwAlignedAddressToMap;
			_ulSizeToMap = (_pSec->Misc.VirtualSize + m_dwFileOffsetToMap) > m_stFileSize.QuadPart ?
				SIZE_T(m_stFileSize.QuadPart - m_dwFileOffsetToMap) : SIZE_T(_pSec->Misc.VirtualSize + m_dwDeltaFileOffsetToMap);

			if (!(m_lpSectionBase = MapViewOfFile(m_hMapObject, FILE_MAP_READ, 0, _dwAlignedAddressToMap, _ulSizeToMap)))
				return FILE_MAP_VIEW_OF_FILE_FAILED;

			m_dwMaxPointerBound = (DWORD_PTR)m_lpSectionBase + _ulSizeToMap;
			PEGetDelayImportTable();
			UnmapViewOfFile(m_lpSectionBase);
		}
	}

	UnmapViewOfFile(m_lpBase);
	CloseHandle(m_hMapObject);
	CloseHandle(_hFile);

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

HRESULT Clibpe::GetMSDOSRichHeader(PLIBPE_RICH* vecRich)
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

	*pTupleNTHeader = &m_tupleNTHeader;

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

	*tupleOptHeader = &m_tupleOptionalHeader;

	return S_OK;
}

HRESULT Clibpe::GetDataDirectories(PLIBPE_DATADIRS* vecDataDir)
{
	if (!m_fLoaded)
		return CALL_LOADPE_FIRST;

	if (!IMAGE_HAS_FLAG(m_dwFileSummary, IMAGE_DATA_DIRECTORIES_FLAG))
		return IMAGE_HAS_NO_DATA_DIRECTORIES;

	*vecDataDir = &m_vecDataDirectories;

	return S_OK;
}

HRESULT Clibpe::GetSectionHeaders(PLIBPE_SECHEADER* vecSections)
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

	*vecExport = &m_tupleExport;

	return S_OK;
}

HRESULT Clibpe::GetImportTable(PLIBPE_IMPORT* vecImport)
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

	*tupleRes = &m_tupleResourceTable;

	return S_OK;
}

HRESULT Clibpe::GetExceptionTable(PLIBPE_EXCEPTION* vecException)
{
	if (!m_fLoaded)
		return CALL_LOADPE_FIRST;

	if (!IMAGE_HAS_FLAG(m_dwFileSummary, IMAGE_EXCEPTION_DIRECTORY_FLAG))
		return IMAGE_HAS_NO_EXCEPTION_DIR;

	*vecException = &m_vecExceptionTable;

	return S_OK;

}

HRESULT Clibpe::GetSecurityTable(PLIBPE_SECURITY* vecSecurity)
{
	if (!m_fLoaded)
		return CALL_LOADPE_FIRST;

	if (!IMAGE_HAS_FLAG(m_dwFileSummary, IMAGE_SECURITY_DIRECTORY_FLAG))
		return IMAGE_HAS_NO_SECURITY_DIR;

	*vecSecurity = &m_vecSecurity;

	return S_OK;
}

HRESULT Clibpe::GetRelocationTable(PLIBPE_RELOCATION* vecRelocs)
{
	if (!m_fLoaded)
		return CALL_LOADPE_FIRST;

	if (!IMAGE_HAS_FLAG(m_dwFileSummary, IMAGE_BASERELOC_DIRECTORY_FLAG))
		return IMAGE_HAS_NO_BASERELOC_DIR;

	*vecRelocs = &m_vecRelocationTable;

	return S_OK;
}

HRESULT Clibpe::GetDebugTable(PLIBPE_DEBUG* vecDebug)
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

	*tupleTLS = &m_tupleTLS;

	return S_OK;
}

HRESULT Clibpe::GetLoadConfigTable(PLIBPE_LOADCONFIGTABLE* tupleLCD)
{
	if (!m_fLoaded)
		return CALL_LOADPE_FIRST;

	if (!IMAGE_HAS_FLAG(m_dwFileSummary, IMAGE_LOADCONFIG_DIRECTORY_FLAG))
		return IMAGE_HAS_NO_LOADCONFIG_DIR;

	*tupleLCD = &m_tupleLoadConfigDir;

	return S_OK;
}

HRESULT Clibpe::GetBoundImportTable(PLIBPE_BOUNDIMPORT* vecBoundImp)
{
	if (!m_fLoaded)
		return CALL_LOADPE_FIRST;

	if (!IMAGE_HAS_FLAG(m_dwFileSummary, IMAGE_BOUNDIMPORT_DIRECTORY_FLAG))
		return IMAGE_HAS_NO_BOUNDIMPORT_DIR;

	*vecBoundImp = &m_vecBoundImportTable;

	return S_OK;
}

HRESULT Clibpe::GetDelayImportTable(PLIBPE_DELAYIMPORT* vecDelayImport)
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


PIMAGE_SECTION_HEADER Clibpe::PEGetSectionHeaderFromRVA(ULONGLONG RVA)
{
	PIMAGE_SECTION_HEADER _pSection { };

	if (IMAGE_HAS_FLAG(m_dwFileSummary, IMAGE_PE32_FLAG))
	{
		_pSection = IMAGE_FIRST_SECTION(m_pNTHeader32);
		for (unsigned i = 0; i < m_pNTHeader32->FileHeader.NumberOfSections; i++, _pSection++)
		{
			if ((DWORD_PTR)_pSection >= m_dwMaxPointerBound)
				return nullptr;
			// is RVA within this section?
			if ((RVA >= _pSection->VirtualAddress) && (RVA < (_pSection->VirtualAddress + _pSection->Misc.VirtualSize)))
				return _pSection;
		}
	}
	else if (IMAGE_HAS_FLAG(m_dwFileSummary, IMAGE_PE64_FLAG))
	{
		_pSection = IMAGE_FIRST_SECTION(m_pNTHeader64);
		for (unsigned i = 0; i < m_pNTHeader64->FileHeader.NumberOfSections; i++, _pSection++)
		{
			if ((DWORD_PTR)_pSection >= m_dwMaxPointerBound)
				return nullptr;
			if ((RVA >= _pSection->VirtualAddress) && (RVA < (_pSection->VirtualAddress + _pSection->Misc.VirtualSize)))
				return _pSection;
		}
	}

	return nullptr;
}

PIMAGE_SECTION_HEADER Clibpe::PEGetSectionHeaderFromName(LPCSTR pName)
{
	PIMAGE_SECTION_HEADER _pSection;

	if (IMAGE_HAS_FLAG(m_dwFileSummary, IMAGE_PE32_FLAG))
	{
		_pSection = IMAGE_FIRST_SECTION(m_pNTHeader32);

		for (unsigned i = 0; i < m_pNTHeader32->FileHeader.NumberOfSections; i++, _pSection++)
		{
			if ((DWORD_PTR)_pSection >= m_dwMaxPointerBound)
				break;
			if (strncmp((char*)_pSection->Name, pName, IMAGE_SIZEOF_SHORT_NAME) == 0)
				return _pSection;
		}
	}
	else if (IMAGE_HAS_FLAG(m_dwFileSummary, IMAGE_PE64_FLAG))
	{
		_pSection = IMAGE_FIRST_SECTION(m_pNTHeader64);

		for (unsigned i = 0; i < m_pNTHeader64->FileHeader.NumberOfSections; i++, _pSection++)
		{
			if ((DWORD_PTR)_pSection >= m_dwMaxPointerBound)
				break;
			if (strncmp((char*)_pSection->Name, pName, IMAGE_SIZEOF_SHORT_NAME) == 0)
				return _pSection;
		}
	}

	return nullptr;
}

LPVOID Clibpe::PERVAToPTR(ULONGLONG RVA)
{
	PIMAGE_SECTION_HEADER _pSection = PEGetSectionHeaderFromRVA(RVA);
	if (!_pSection)
		return nullptr;

	if (!m_fMapViewOfFileWhole)
		return (LPVOID)((DWORD_PTR)m_lpSectionBase + (SIZE_T)m_dwDeltaFileOffsetToMap +
		(RVA - (DWORD_PTR)(_pSection->VirtualAddress - _pSection->PointerToRawData) - m_dwFileOffsetToMap));
	else
		return (LPVOID)((DWORD_PTR)m_lpBase + RVA - (DWORD_PTR)(_pSection->VirtualAddress - _pSection->PointerToRawData));
}

DWORD Clibpe::PEGetDirectoryEntryRVA(UINT dirEntry)
{
	if (IMAGE_HAS_FLAG(m_dwFileSummary, IMAGE_PE32_FLAG))
		return m_pNTHeader32->OptionalHeader.DataDirectory[dirEntry].VirtualAddress;
	else if (IMAGE_HAS_FLAG(m_dwFileSummary, IMAGE_PE64_FLAG))
		return m_pNTHeader64->OptionalHeader.DataDirectory[dirEntry].VirtualAddress;

	return 0;
}

DWORD Clibpe::PEGetDirectoryEntrySize(UINT dirEntry)
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
	std::get<2>(m_tupleExport).clear();
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
		m_tupleNTHeader = { *m_pNTHeader32, IMAGE_NT_HEADERS64 { 0 } };
		m_stFileHeader = m_pNTHeader32->FileHeader;
		m_tupleOptionalHeader = { m_pNTHeader32->OptionalHeader, IMAGE_OPTIONAL_HEADER64 { 0 } };
		break;
	case  IMAGE_NT_OPTIONAL_HDR64_MAGIC:
		m_dwFileSummary |= IMAGE_PE64_FLAG;
		m_pNTHeader64 = (PIMAGE_NT_HEADERS64)((DWORD_PTR)m_pDosHeader + m_pDosHeader->e_lfanew);
		m_tupleNTHeader = { IMAGE_NT_HEADERS32 { 0 }, *m_pNTHeader64 };
		m_stFileHeader = m_pNTHeader64->FileHeader;
		m_tupleOptionalHeader = { IMAGE_OPTIONAL_HEADER32 { 0 }, m_pNTHeader64->OptionalHeader };
		break;
	case  IMAGE_ROM_OPTIONAL_HDR_MAGIC:
		break;
		//not implemented yet
	default:
		return IMAGE_TYPE_UNSUPPORTED;
	}
	m_dwFileSummary |= IMAGE_FILE_HEADER_FLAG | IMAGE_OPTIONAL_HEADER_FLAG;

	return S_OK;
}

HRESULT Clibpe::PEGetRichHeader()
{
	//"Rich" stub starts at 0x80 offset,
	//before m_pDosHeader->e_lfanew (PE header start)
	//If e_lfanew < 0x80 there is no "Rich"
	if (m_pDosHeader->e_lfanew <= 0x80)
		return IMAGE_HAS_NO_RICH_HEADER;

	PDWORD _pRichStartVA = (PDWORD)((DWORD_PTR)m_pDosHeader + 0x80);
	PDWORD _pRichIter = _pRichStartVA;

	for (int i = 0; i < ((m_pDosHeader->e_lfanew - 0x80) / 4); i++)
	{
		//Check "Rich" (ANSI) sign then XOR _pRichStartVA DWORD with the DWORD following "Rich" sign
		//to find out if it is "DanS" (ANSI).
		if ((*_pRichIter == 0x68636952/*"Rich"*/) && ((*_pRichStartVA xor *(_pRichIter + 1)) == 0x536E6144/*"Dans"*/))
		{
			DWORD _nRichSize = (DWORD)(((DWORD_PTR)_pRichIter - (DWORD_PTR)m_pDosHeader) - 0x90) / 8;//amount of all "Rich" DOUBLE_DWORD structs 
			DWORD _RichXORMask = *(_pRichIter + 1);//XOR mask of this "Rich" header
			_pRichIter = (PDWORD)((DWORD_PTR)m_pDosHeader + 0x90);//VA of "Rich" DOUBLE_DWORD Struct start

			for (unsigned i = 0; i < _nRichSize; i++)
			{
				m_vecRichHeader.push_back({ HIWORD(_RichXORMask xor *_pRichIter), LOWORD(_RichXORMask xor *_pRichIter), _RichXORMask xor *(_pRichIter + 1) });
				_pRichIter += 2;//Jump next DOUBLE_DWORD
			}
			m_dwFileSummary |= IMAGE_RICH_HEADER_FLAG;

			return S_OK;
		}
		else
			_pRichIter++;
	}

	return IMAGE_HAS_NO_RICH_HEADER;
}

HRESULT Clibpe::PEGetDataDirs()
{
	PIMAGE_DATA_DIRECTORY _pDataDir { };
	PIMAGE_SECTION_HEADER _pSectionHeader { };
	std::string _strSecName { };

	if (IMAGE_HAS_FLAG(m_dwFileSummary, IMAGE_PE32_FLAG))
	{
		_pDataDir = (PIMAGE_DATA_DIRECTORY)m_pNTHeader32->OptionalHeader.DataDirectory;

		//Filling DataDirectories vector
		for (unsigned i = 0; i < (m_pNTHeader32->OptionalHeader.NumberOfRvaAndSizes > 15 ?
			15 : m_pNTHeader32->OptionalHeader.NumberOfRvaAndSizes); i++)
		{
			_pSectionHeader = PEGetSectionHeaderFromRVA(_pDataDir->VirtualAddress);
			//RVA of IMAGE_DIRECTORY_ENTRY_SECURITY is file RAW offset
			if (_pSectionHeader && (i != IMAGE_DIRECTORY_ENTRY_SECURITY))
				_strSecName.assign((char * const)_pSectionHeader->Name, 8);

			m_vecDataDirectories.push_back({ *_pDataDir, std::move(_strSecName) });

			_pDataDir++;
			_strSecName.clear();
		}
	}
	else if (IMAGE_HAS_FLAG(m_dwFileSummary, IMAGE_PE64_FLAG))
	{
		_pDataDir = (PIMAGE_DATA_DIRECTORY)m_pNTHeader64->OptionalHeader.DataDirectory;

		//Filling DataDirectories vector
		for (unsigned i = 0; i < m_pNTHeader64->OptionalHeader.NumberOfRvaAndSizes; i++)
		{
			_pSectionHeader = PEGetSectionHeaderFromRVA(_pDataDir->VirtualAddress);
			//RVA of IMAGE_DIRECTORY_ENTRY_SECURITY is file RAW offset
			if (_pSectionHeader && (i != IMAGE_DIRECTORY_ENTRY_SECURITY))
				_strSecName.assign((char * const)_pSectionHeader->Name, 8);

			m_vecDataDirectories.push_back({ *_pDataDir, std::move(_strSecName) });

			_pDataDir++;
			_strSecName.clear();
		}
	}
	if (m_vecDataDirectories.empty())
		return IMAGE_HAS_NO_DATA_DIRECTORIES;

	m_dwFileSummary |= IMAGE_DATA_DIRECTORIES_FLAG;

	return S_OK;
}

HRESULT Clibpe::PEGetSectionHeaders()
{
	PIMAGE_SECTION_HEADER _pSectionHeader { };

	if (IMAGE_HAS_FLAG(m_dwFileSummary, IMAGE_PE32_FLAG))
	{
		_pSectionHeader = IMAGE_FIRST_SECTION(m_pNTHeader32);

		for (unsigned i = 0; i < m_pNTHeader32->FileHeader.NumberOfSections; i++, _pSectionHeader++)
		{
			if ((DWORD_PTR)_pSectionHeader >= m_dwMaxPointerBound)
				break;
			m_vecSectionHeaders.push_back(*_pSectionHeader);
		}
	}
	else if (IMAGE_HAS_FLAG(m_dwFileSummary, IMAGE_PE64_FLAG))
	{
		_pSectionHeader = IMAGE_FIRST_SECTION(m_pNTHeader64);

		for (unsigned i = 0; i < m_pNTHeader64->FileHeader.NumberOfSections; i++, _pSectionHeader++)
		{
			if ((DWORD_PTR)_pSectionHeader >= m_dwMaxPointerBound)
				break;
			m_vecSectionHeaders.push_back(*_pSectionHeader);
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
	DWORD _dwExportStartRVA = PEGetDirectoryEntryRVA(IMAGE_DIRECTORY_ENTRY_EXPORT);
	DWORD _dwExportEndRVA = _dwExportStartRVA + PEGetDirectoryEntrySize(IMAGE_DIRECTORY_ENTRY_EXPORT);
	PIMAGE_SECTION_HEADER _pExportSecHeader = PEGetSectionHeaderFromRVA(_dwExportStartRVA);

	std::vector<std::tuple<DWORD/*Exported func RVA/Forwarder RVA*/, DWORD/*func Ordinal*/, std::string /*Func Name*/,
		std::string/*Forwarder func name*/>> _vecFuncs { };
	std::string _strFuncName { }, _strFuncNameForwarder { }, _strExportName { };

	if (!_pExportSecHeader)
		return IMAGE_HAS_NO_EXPORT_DIR;

	PIMAGE_EXPORT_DIRECTORY _pExportDir = (PIMAGE_EXPORT_DIRECTORY)PERVAToPTR(_dwExportStartRVA);

	if (!_pExportDir)
		return IMAGE_HAS_NO_EXPORT_DIR;

	PDWORD _pFuncs = (PDWORD)PERVAToPTR(_pExportDir->AddressOfFunctions);
	if (!_pFuncs)
		return IMAGE_HAS_NO_EXPORT_DIR;

	PWORD _pOrdinals = (PWORD)PERVAToPTR(_pExportDir->AddressOfNameOrdinals);
	LPCSTR* _pNames = (LPCSTR*)PERVAToPTR(_pExportDir->AddressOfNames);

	try {
		for (unsigned i = 0; i < _pExportDir->NumberOfFunctions; i++)
		{
			if (_pFuncs[i])//if RVA==0 —> going next entry
			{
				LPCSTR _funcName { }, _funcNameForwarder { };

				if (_pNames && _pOrdinals)
					for (unsigned j = 0; j < _pExportDir->NumberOfNames; j++)
						if (_pOrdinals[j] == i)//cycling through Ordinals table to get func name
						{
							_funcName = (LPCSTR)PERVAToPTR((DWORD_PTR)_pNames[j]);
							//checking func name for length correctness
							if (_funcName && (StringCchLengthA(_funcName, MAX_PATH, nullptr) != STRSAFE_E_INVALID_PARAMETER))
								_strFuncName = _funcName;
						}
				if ((_pFuncs[i] >= _dwExportStartRVA) && (_pFuncs[i] <= _dwExportEndRVA))
				{
					_funcNameForwarder = (LPCSTR)PERVAToPTR(_pFuncs[i]);
					//checking forwarder name for length correctness
					if (_funcNameForwarder && (StringCchLengthA(_funcNameForwarder, MAX_PATH, nullptr) != STRSAFE_E_INVALID_PARAMETER))
						_strFuncNameForwarder = _funcNameForwarder;
				}
				_vecFuncs.push_back({ _pFuncs[i], i, std::move(_strFuncName), std::move(_strFuncNameForwarder) });
				_strFuncName.clear();
				_strFuncNameForwarder.clear();
			}
		}

		LPCSTR _lpExportName = (LPCSTR)PERVAToPTR(_pExportDir->Name);
		//checking Export name for length correctness
		if (_lpExportName && (StringCchLengthA(_lpExportName, MAX_PATH, nullptr) != STRSAFE_E_INVALID_PARAMETER))
			_strExportName = _lpExportName;

		m_tupleExport = { *_pExportDir, std::move(_strExportName) /*Actual IMG name*/, std::move(_vecFuncs) };
	}
	catch (const std::bad_alloc&)
	{
		delete [] m_lpszEmergencyMemory;
		MessageBox(0, TEXT("E_OUTOFMEMORY error while trying to get Export Table."), TEXT("Error"), MB_ICONERROR);

		_vecFuncs.clear();
		m_lpszEmergencyMemory = new char[16384];
	}
	m_dwFileSummary |= IMAGE_EXPORT_DIRECTORY_FLAG;

	return S_OK;
}

HRESULT Clibpe::PEGetImportTable()
{
	PIMAGE_IMPORT_DESCRIPTOR _pImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)PERVAToPTR(PEGetDirectoryEntryRVA(IMAGE_DIRECTORY_ENTRY_IMPORT));

	if (!_pImportDescriptor)
		return IMAGE_HAS_NO_IMPORT_DIR;

	DWORD _dwTLSDirRVA = PEGetDirectoryEntryRVA(IMAGE_DIRECTORY_ENTRY_TLS);
	PIMAGE_TLS_DIRECTORY32 _pTLSDir32 { };
	PIMAGE_TLS_DIRECTORY64 _pTLSDir64 { };
	PIMAGE_THUNK_DATA32 _pThunk32 { };
	PIMAGE_THUNK_DATA64 _pThunk64 { };
	std::vector<std::tuple<LONGLONG/*Ordinal/Hint*/, std::string/*Func name*/, LONGLONG/*Thunk table RVA*/>> _vecFunc { };
	std::string _strDllName { }, _strFuncName { };

	try {
		if (IMAGE_HAS_FLAG(m_dwFileSummary, IMAGE_PE32_FLAG))
		{
			_pTLSDir32 = (PIMAGE_TLS_DIRECTORY32)PERVAToPTR(_dwTLSDirRVA);

			while (_pImportDescriptor->Name)
			{
				//Checking for TLS Index patching trick, to fade Fake Imports
				if (_pTLSDir32 && _pTLSDir32->AddressOfIndex && (((DWORD_PTR)_pImportDescriptor + offsetof(IMAGE_IMPORT_DESCRIPTOR, FirstThunk)) ==
					(DWORD_PTR)PERVAToPTR(_pTLSDir32->AddressOfIndex - m_pNTHeader32->OptionalHeader.ImageBase) ||
					((DWORD_PTR)_pImportDescriptor + offsetof(IMAGE_IMPORT_DESCRIPTOR, Name)) ==
					(DWORD_PTR)PERVAToPTR(_pTLSDir32->AddressOfIndex - m_pNTHeader32->OptionalHeader.ImageBase)))
				{
					LPCSTR _lpszName = (LPCSTR)PERVAToPTR(_pImportDescriptor->Name);
					if (_lpszName && (StringCchLengthA(_lpszName, MAX_PATH, nullptr) != STRSAFE_E_INVALID_PARAMETER))
						_strDllName = _lpszName;

					_strDllName += " (--> stripped by TLS::AddressOfIndex trick)";

					m_vecImportTable.push_back({ *_pImportDescriptor, std::move(_strDllName), std::move(_vecFunc) });
					break;
				}

				_pThunk32 = (PIMAGE_THUNK_DATA32)(DWORD_PTR)_pImportDescriptor->OriginalFirstThunk;
				if (!_pThunk32)
					_pThunk32 = (PIMAGE_THUNK_DATA32)(DWORD_PTR)_pImportDescriptor->FirstThunk;

				if (_pThunk32)
				{
					_pThunk32 = (PIMAGE_THUNK_DATA32)PERVAToPTR((DWORD_PTR)_pThunk32);
					if (!_pThunk32)
						return IMAGE_HAS_NO_IMPORT_DIR;

					while (_pThunk32->u1.AddressOfData)
					{
						if (_pThunk32->u1.Ordinal & IMAGE_ORDINAL_FLAG32)
							//If funcs are imported only by ordinals then filling only ordinal leaving Name as ""
							_vecFunc.push_back({ IMAGE_ORDINAL32(_pThunk32->u1.Ordinal), std::move(_strFuncName), _pThunk32->u1.AddressOfData });
						else
						{	//filling Hint, Name and Thunk RVA
							PIMAGE_IMPORT_BY_NAME _pName = (PIMAGE_IMPORT_BY_NAME)PERVAToPTR(_pThunk32->u1.AddressOfData);
							if (_pName && (StringCchLengthA(_pName->Name, MAX_PATH, nullptr) != STRSAFE_E_INVALID_PARAMETER))
								_strFuncName = _pName->Name;

							_vecFunc.push_back({ _pName ? _pName->Hint : 0, std::move(_strFuncName), _pThunk32->u1.AddressOfData });
							_strFuncName.clear();
						}
						_pThunk32++;
					}

					LPCSTR _lpszName = (LPCSTR)PERVAToPTR(_pImportDescriptor->Name);
					if (_lpszName && (StringCchLengthA(_lpszName, MAX_PATH, nullptr) != STRSAFE_E_INVALID_PARAMETER))
						_strDllName = _lpszName;

					m_vecImportTable.push_back({ *_pImportDescriptor, std::move(_strDllName), std::move(_vecFunc) });
					_vecFunc.clear();
					_strDllName.clear();

					_pImportDescriptor++;
				}
				else// No IMPORT pointers for that DLL?...
					_pImportDescriptor++;  //going to the next dll
			}
		}
		else if (IMAGE_HAS_FLAG(m_dwFileSummary, IMAGE_PE64_FLAG))
		{
			_pTLSDir64 = (PIMAGE_TLS_DIRECTORY64)PERVAToPTR(_dwTLSDirRVA);

			while (_pImportDescriptor->Name)
			{
				if (_pTLSDir64 && _pTLSDir64->AddressOfIndex && (((DWORD_PTR)_pImportDescriptor + offsetof(IMAGE_IMPORT_DESCRIPTOR, FirstThunk)) ==
					(DWORD_PTR)PERVAToPTR(_pTLSDir64->AddressOfIndex - m_pNTHeader64->OptionalHeader.ImageBase) ||
					((DWORD_PTR)_pImportDescriptor + offsetof(IMAGE_IMPORT_DESCRIPTOR, Name)) ==
					(DWORD_PTR)PERVAToPTR(_pTLSDir64->AddressOfIndex - m_pNTHeader64->OptionalHeader.ImageBase)))
				{
					LPCSTR _lpszName = (LPCSTR)PERVAToPTR(_pImportDescriptor->Name);
					if (_lpszName && (StringCchLengthA(_lpszName, MAX_PATH, nullptr) != STRSAFE_E_INVALID_PARAMETER))
						_strDllName = _lpszName;

					_strDllName += " (--> stripped by TLS::AddressOfIndex trick)";

					m_vecImportTable.push_back({ *_pImportDescriptor, std::move(_strDllName), std::move(_vecFunc) });
					break;
				}

				_pThunk64 = (PIMAGE_THUNK_DATA64)(DWORD_PTR)_pImportDescriptor->OriginalFirstThunk;
				if (!_pThunk64)
					_pThunk64 = (PIMAGE_THUNK_DATA64)(DWORD_PTR)_pImportDescriptor->FirstThunk;

				if (_pThunk64)
				{
					if (_pTLSDir64 && ((DWORD_PTR)_pThunk64 >= (_pTLSDir64->AddressOfIndex - m_pNTHeader64->OptionalHeader.ImageBase)))
					{
						m_vecImportTable.push_back({ *_pImportDescriptor, "(fake import stripped)", std::move(_vecFunc) });
						break;
					}

					_pThunk64 = (PIMAGE_THUNK_DATA64)PERVAToPTR((DWORD_PTR)_pThunk64);
					if (!_pThunk64)
						return IMAGE_HAS_NO_IMPORT_DIR;

					while (_pThunk64->u1.AddressOfData)
					{
						if (_pThunk64->u1.Ordinal & IMAGE_ORDINAL_FLAG64)
							//if funcs are imported only by ordinals 
							//then filling only ordinal leaving Name as ""
							_vecFunc.push_back({ IMAGE_ORDINAL64(_pThunk64->u1.Ordinal), std::move(_strFuncName), _pThunk64->u1.AddressOfData });
						else
						{	//filling Hint, Name and Thunk RVA
							PIMAGE_IMPORT_BY_NAME _pName = (PIMAGE_IMPORT_BY_NAME)PERVAToPTR(_pThunk64->u1.AddressOfData);
							if (_pName && (StringCchLengthA(_pName->Name, MAX_PATH, nullptr) != STRSAFE_E_INVALID_PARAMETER))
								_strFuncName = _pName->Name;

							_vecFunc.push_back({ _pName ? _pName->Hint : 0, std::move(_strFuncName), _pThunk64->u1.AddressOfData });
							_strFuncName.clear();
						}
						_pThunk64++;
					}

					LPCSTR _lpszName = (LPCSTR)PERVAToPTR(_pImportDescriptor->Name);
					if (_lpszName && (StringCchLengthA(_lpszName, MAX_PATH, nullptr) != STRSAFE_E_INVALID_PARAMETER))
						_strDllName = _lpszName;

					m_vecImportTable.push_back({ *_pImportDescriptor, std::move(_strDllName), std::move(_vecFunc) });
					_vecFunc.clear();
					_strDllName.clear();

					_pImportDescriptor++;
				}
				else
					_pImportDescriptor++;
			}
		}
	}
	catch (const std::bad_alloc&)
	{
		delete [] m_lpszEmergencyMemory;
		MessageBox(0, L"E_OUTOFMEMORY error while trying to get Import Table.\r\n"
			L"Seems like too many Imports.", L"Error", MB_ICONERROR);

		_vecFunc.clear();
		m_vecImportTable.clear();
		m_lpszEmergencyMemory = new char[16384];
	}
	m_dwFileSummary |= IMAGE_IMPORT_DIRECTORY_FLAG;

	return S_OK;
}

HRESULT Clibpe::PEGetResourceTable()
{
	PIMAGE_RESOURCE_DIRECTORY _pRootResDir = (PIMAGE_RESOURCE_DIRECTORY)PERVAToPTR(PEGetDirectoryEntryRVA(IMAGE_DIRECTORY_ENTRY_RESOURCE));

	if (!_pRootResDir)
		return IMAGE_HAS_NO_RESOURCE_DIR;

	PIMAGE_RESOURCE_DIRECTORY_ENTRY _pRootResDirEntry = (PIMAGE_RESOURCE_DIRECTORY_ENTRY)(_pRootResDir + 1);
	size_t _nResNameLength { };
	std::wstring _strRootResName { }, _strSecondResName { }, _strThirdResName { };

	LIBPE_RESOURCE_VEC_ROOT _vecResLvLRoot { };
	LIBPE_RESOURCE_LVL2 _tupleResLvL2 { };
	LIBPE_RESOURCE_VEC_LVL2 _vecResLvL2 { };
	LIBPE_RESOURCE_LVL3 _tupleResLvL3 { };
	LIBPE_RESOURCE_VEC_LVL3 _vecResLvL3 { };

	try {
		for (int iLvL1 = 0; iLvL1 < _pRootResDir->NumberOfNamedEntries + _pRootResDir->NumberOfIdEntries; iLvL1++)
		{
			PIMAGE_RESOURCE_DATA_ENTRY _pRootResDataEntry { };
			std::vector<std::byte> _vecRootResRawData { };

			//Name of Resource Type (ICON, BITMAP, MENU, etc...)
			if (_pRootResDirEntry->NameIsString == 1)
			{//copy not more then MAX_PATH chars into _strResName, avoiding buff overflow
				_nResNameLength = ((PIMAGE_RESOURCE_DIR_STRING_U)((DWORD_PTR)_pRootResDir + _pRootResDirEntry->NameOffset))->Length;
				_strRootResName.assign(((PIMAGE_RESOURCE_DIR_STRING_U)((DWORD_PTR)_pRootResDir + _pRootResDirEntry->NameOffset))->NameString,
					_nResNameLength < MAX_PATH ? _nResNameLength : MAX_PATH);
			}
			if (_pRootResDirEntry->DataIsDirectory == 1)
			{
				PIMAGE_RESOURCE_DIRECTORY _pSecondResDir = (PIMAGE_RESOURCE_DIRECTORY)((DWORD_PTR)_pRootResDir + _pRootResDirEntry->OffsetToDirectory);
				if (_pSecondResDir == _pRootResDir)//Resource loop hack
					_tupleResLvL2 = { *_pSecondResDir, _vecResLvL2 };
				else
				{
					PIMAGE_RESOURCE_DIRECTORY_ENTRY _pSecondResDirEntry = (PIMAGE_RESOURCE_DIRECTORY_ENTRY)(_pSecondResDir + 1);
					for (int iLvL2 = 0; iLvL2 < _pSecondResDir->NumberOfNamedEntries + _pSecondResDir->NumberOfIdEntries; iLvL2++)
					{
						PIMAGE_RESOURCE_DATA_ENTRY _pSecondResDataEntry { };
						std::vector<std::byte> _vecSecondResRawData { };

						//Name of resource itself if not presented by ID ("AFX_MY_SUPER_DIALOG"...)
						if (_pSecondResDirEntry->NameIsString == 1)
						{
							_nResNameLength = ((PIMAGE_RESOURCE_DIR_STRING_U)((DWORD_PTR)_pRootResDir + _pSecondResDirEntry->NameOffset))->Length;
							_strSecondResName.assign(((PIMAGE_RESOURCE_DIR_STRING_U)((DWORD_PTR)_pRootResDir + _pSecondResDirEntry->NameOffset))->NameString,
								_nResNameLength < MAX_PATH ? _nResNameLength : MAX_PATH);
						}

						if (_pSecondResDirEntry->DataIsDirectory == 1)
						{
							PIMAGE_RESOURCE_DIRECTORY _pThirdResDir = (PIMAGE_RESOURCE_DIRECTORY)((DWORD_PTR)_pRootResDir + _pSecondResDirEntry->OffsetToDirectory);
							if (_pThirdResDir == _pSecondResDir || _pThirdResDir == _pRootResDir)//Resource loop hack
								_tupleResLvL3 = { *_pThirdResDir, _vecResLvL3 };
							else
							{
								PIMAGE_RESOURCE_DIRECTORY_ENTRY _pThirdResDirEntry = (PIMAGE_RESOURCE_DIRECTORY_ENTRY)(_pThirdResDir + 1);

								for (int iLvL3 = 0; iLvL3 < _pThirdResDir->NumberOfNamedEntries + _pThirdResDir->NumberOfIdEntries; iLvL3++)
								{
									PIMAGE_RESOURCE_DATA_ENTRY _pThirdResDataEntry { };
									std::vector<std::byte> _vecThirdResRawData { };

									if (_pThirdResDirEntry->NameIsString == 1)
									{
										_nResNameLength = ((PIMAGE_RESOURCE_DIR_STRING_U)((DWORD_PTR)_pRootResDir + _pThirdResDirEntry->NameOffset))->Length;
										_strThirdResName.assign(((PIMAGE_RESOURCE_DIR_STRING_U)((DWORD_PTR)_pRootResDir + _pThirdResDirEntry->NameOffset))->NameString,
											_nResNameLength < MAX_PATH ? _nResNameLength : MAX_PATH);
									}

									_pThirdResDataEntry = (PIMAGE_RESOURCE_DATA_ENTRY)((DWORD_PTR)_pRootResDir + _pThirdResDirEntry->OffsetToData);
									if (_pThirdResDataEntry)
									{	//Resource LvL 3 RAW Data.
										//IMAGE_RESOURCE_DATA_ENTRY::OffsetToData is actually a general RVA,
										//not an offset form root IMAGE_RESOURCE_DIRECTORY, 
										//as IMAGE_RESOURCE_DIRECTORY_ENTRY::OffsetToData is.
										//MS doesn't tend to make things simpler.
										PBYTE _pResRawData = (PBYTE)PERVAToPTR(_pThirdResDataEntry->OffsetToData);
										if (_pResRawData)
											for (unsigned i = 0; i < _pThirdResDataEntry->Size; i++)
												_vecThirdResRawData.push_back(std::byte(*(_pResRawData + i)));
									}

									_vecResLvL3.push_back({ *_pThirdResDirEntry, std::move(_strThirdResName),
										_pThirdResDataEntry ? *_pThirdResDataEntry : IMAGE_RESOURCE_DATA_ENTRY { 0 }, std::move(_vecThirdResRawData) });
									_vecThirdResRawData.clear();
									_strThirdResName.clear();

									_pThirdResDirEntry++;
								}
								_tupleResLvL3 = { *_pThirdResDir, std::move(_vecResLvL3) };
								_vecResLvL3.clear();
							}
						}
						else
						{//////Resource LvL2 RAW Data
							_pSecondResDataEntry = (PIMAGE_RESOURCE_DATA_ENTRY)((DWORD_PTR)_pRootResDir + _pSecondResDirEntry->OffsetToData);
							if (_pSecondResDataEntry)
							{
								PBYTE _pResRawData = (PBYTE)PERVAToPTR(_pSecondResDataEntry->OffsetToData);
								if (_pResRawData)
									for (unsigned i = 0; i < _pSecondResDataEntry->Size; i++)
										_vecSecondResRawData.push_back(std::byte(*(_pResRawData + i)));
							}
						}
						_vecResLvL2.push_back({ *_pSecondResDirEntry, std::move(_strSecondResName),
							_pSecondResDataEntry ? *_pSecondResDataEntry : IMAGE_RESOURCE_DATA_ENTRY { 0 },
							std::move(_vecSecondResRawData), _tupleResLvL3 });
						_vecSecondResRawData.clear();
						_strSecondResName.clear();

						_pSecondResDirEntry++;
					}
					_tupleResLvL2 = { *_pSecondResDir, std::move(_vecResLvL2) };
					_vecResLvL2.clear();
				}
			}
			else
			{	//////Resource LvL Root RAW Data
				_pRootResDataEntry = (PIMAGE_RESOURCE_DATA_ENTRY)((DWORD_PTR)_pRootResDir + _pRootResDirEntry->OffsetToData);
				if (_pRootResDataEntry)
				{
					PBYTE _pResRawData = (PBYTE)PERVAToPTR(_pRootResDataEntry->OffsetToData);
					if (_pResRawData)
						for (unsigned i = 0; i < _pRootResDataEntry->Size; i++)
							_vecRootResRawData.push_back(std::byte(*(_pResRawData + i)));
				}
			}
			_vecResLvLRoot.push_back({ *_pRootResDirEntry, std::move(_strRootResName),
				_pRootResDataEntry ? *_pRootResDataEntry : IMAGE_RESOURCE_DATA_ENTRY { 0 }, std::move(_vecRootResRawData), _tupleResLvL2 });
			_vecRootResRawData.clear();
			_strRootResName.clear();

			_pRootResDirEntry++;
		}
		m_tupleResourceTable = { *_pRootResDir, std::move(_vecResLvLRoot) };
		_vecResLvLRoot.clear();
	}
	catch (const std::bad_alloc&)
	{
		delete [] m_lpszEmergencyMemory;
		MessageBox(0, TEXT("E_OUTOFMEMORY error while trying to get Resource Table."), TEXT("Error"), MB_ICONERROR);

		_vecResLvLRoot.clear();
		_vecResLvL2.clear();
		_vecResLvL3.clear();
		m_lpszEmergencyMemory = new char[16384];
	}
	m_dwFileSummary |= IMAGE_RESOURCE_DIRECTORY_FLAG;

	return S_OK;
}

HRESULT Clibpe::PEGetExceptionTable()
{
	//IMAGE_RUNTIME_FUNCTION_ENTRY (without leading underscore) 
	//might have different typedef depending on defined platform, see winnt.h
	_PIMAGE_RUNTIME_FUNCTION_ENTRY _pRuntimeFuncsEntry = (_PIMAGE_RUNTIME_FUNCTION_ENTRY)PERVAToPTR(PEGetDirectoryEntryRVA(IMAGE_DIRECTORY_ENTRY_EXCEPTION));
	if (!_pRuntimeFuncsEntry)
		return IMAGE_HAS_NO_EXCEPTION_DIR;

	DWORD _nEntries = PEGetDirectoryEntrySize(IMAGE_DIRECTORY_ENTRY_EXCEPTION) / (DWORD)sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY);
	if (!_nEntries)
		return IMAGE_HAS_NO_EXCEPTION_DIR;

	for (unsigned i = 0; i < _nEntries; i++, _pRuntimeFuncsEntry++)
		m_vecExceptionTable.push_back(*_pRuntimeFuncsEntry);

	m_dwFileSummary |= IMAGE_EXCEPTION_DIRECTORY_FLAG;

	return S_OK;
}

HRESULT Clibpe::PEGetSecurityTable()
{
	DWORD _dwSecurityDirOffset = PEGetDirectoryEntryRVA(IMAGE_DIRECTORY_ENTRY_SECURITY);
	DWORD _dwSecurityDirSize = PEGetDirectoryEntrySize(IMAGE_DIRECTORY_ENTRY_SECURITY);

	if (_dwSecurityDirOffset == 0 || _dwSecurityDirSize == 0)
		return IMAGE_HAS_NO_SECURITY_DIR;

	ULONGLONG _dwSecurityDirStartVA { };
	if (m_fMapViewOfFileWhole)
		_dwSecurityDirStartVA = (DWORD_PTR)m_lpBase + _dwSecurityDirOffset;
	else
		_dwSecurityDirStartVA = (DWORD_PTR)m_lpSectionBase + m_dwDeltaFileOffsetToMap;

	ULONGLONG _dwSecurityDirEndVA = _dwSecurityDirStartVA + _dwSecurityDirSize;

	//Checking for crossing file's size bounds.
	if (_dwSecurityDirStartVA >= m_dwMaxPointerBound || _dwSecurityDirEndVA > m_dwMaxPointerBound)
		return IMAGE_HAS_NO_SECURITY_DIR;

	LPWIN_CERTIFICATE _pSertificate = (LPWIN_CERTIFICATE)_dwSecurityDirStartVA;
	std::vector<std::byte> _vecCertBytes { };
	while (_dwSecurityDirStartVA < _dwSecurityDirEndVA)
	{
		for (unsigned i = 0; i < _pSertificate->dwLength - offsetof(WIN_CERTIFICATE, bCertificate); i++)
			_vecCertBytes.push_back((std::byte)_pSertificate->bCertificate[i]);

		m_vecSecurity.push_back({ *_pSertificate, std::move(_vecCertBytes) });
		_vecCertBytes.clear();

		//Get next sertificate entry.
		//All entries starts at 8 rounded address.
		_dwSecurityDirStartVA = (_pSertificate->dwLength + _dwSecurityDirStartVA) % 8 + (_pSertificate->dwLength + _dwSecurityDirStartVA);
		_pSertificate = (LPWIN_CERTIFICATE)_dwSecurityDirStartVA;
	}
	m_dwFileSummary |= IMAGE_SECURITY_DIRECTORY_FLAG;

	return S_OK;
}

HRESULT Clibpe::PEGetRelocationTable()
{
	PIMAGE_BASE_RELOCATION _pBaseRelocDescriptor = (PIMAGE_BASE_RELOCATION)PERVAToPTR(PEGetDirectoryEntryRVA(IMAGE_DIRECTORY_ENTRY_BASERELOC));

	if (!_pBaseRelocDescriptor)
		return IMAGE_HAS_NO_BASERELOC_DIR;

	std::vector<std::tuple<WORD/*type*/, WORD/*offset*/>> _vecRelocs { };

	try
	{
		while ((_pBaseRelocDescriptor->SizeOfBlock) && (_pBaseRelocDescriptor->VirtualAddress))
		{
			if (_pBaseRelocDescriptor->SizeOfBlock < sizeof(IMAGE_BASE_RELOCATION))
				return -1;

			//Amount of Reloc entries
			DWORD _iRelocEntries = (_pBaseRelocDescriptor->SizeOfBlock - (DWORD)sizeof(IMAGE_BASE_RELOCATION)) / (DWORD)sizeof(WORD);
			PWORD _pRelocEntry = PWORD((DWORD_PTR)_pBaseRelocDescriptor + sizeof(IMAGE_BASE_RELOCATION));
			WORD _relocType { };

			for (DWORD i = 0; i < _iRelocEntries; i++)
			{
				if ((DWORD_PTR)_pRelocEntry >= m_dwMaxPointerBound)
					break;
				// Getting HIGH 4 bits of reloc's entry WORD —> reloc type.
				_relocType = (*_pRelocEntry & 0xF000) >> 12;
				_vecRelocs.push_back({ _relocType, ((*_pRelocEntry) & 0x0fff)/*Low 12 bits —> Offset*/ });

				if (_relocType == IMAGE_REL_BASED_HIGHADJ)
				{   //The base relocation adds the high 16 bits of the difference to the 16-bit field at offset.
					//The 16-bit field represents the high value of a 32-bit word. 
					//The low 16 bits of the 32-bit value are stored in the 16-bit word that follows this base relocation.
					//This means that this base relocation occupies two slots. (MSDN)
					_pRelocEntry++;
					_vecRelocs.push_back({ _relocType, *_pRelocEntry/*The low 16-bit field*/ });
					_iRelocEntries--; //to compensate _pRelocEntry++
				}
				_pRelocEntry++;
			}
			m_vecRelocationTable.push_back({ *_pBaseRelocDescriptor, std::move(_vecRelocs) });
			_vecRelocs.clear(); //clear temp vector to fill with next entries

			//Too big (bogus) SizeOfBlock may cause DWORD_PTR overflow
#if INTPTR_MAX == INT32_MAX
			if ((DWORD_PTR)_pBaseRelocDescriptor > (UINT_MAX - _pBaseRelocDescriptor->SizeOfBlock))
				break;
#elif INTPTR_MAX == INT64_MAX
			if ((DWORD_PTR)_pBaseRelocDescriptor > (MAXDWORD64 - _pBaseRelocDescriptor->SizeOfBlock))
				break;
#endif
			_pBaseRelocDescriptor = PIMAGE_BASE_RELOCATION((DWORD_PTR)_pBaseRelocDescriptor + (DWORD_PTR)_pBaseRelocDescriptor->SizeOfBlock);
			if ((DWORD_PTR)_pBaseRelocDescriptor >= m_dwMaxPointerBound)
				break;
		}
	}
	catch (const std::bad_alloc&)
	{
		delete [] m_lpszEmergencyMemory;
		MessageBox(0, L"E_OUTOFMEMORY error while trying to get Relocation Table.", L"Error", MB_ICONERROR);

		_vecRelocs.clear();
		m_lpszEmergencyMemory = new char[16384];
	}

	m_dwFileSummary |= IMAGE_BASERELOC_DIRECTORY_FLAG;

	return S_OK;
}

HRESULT Clibpe::PEGetDebugTable()
{
	DWORD _dwDebugDirRVA = PEGetDirectoryEntryRVA(IMAGE_DIRECTORY_ENTRY_DEBUG);

	if (!_dwDebugDirRVA)
		return IMAGE_HAS_NO_DEBUG_DIR;

	PIMAGE_DEBUG_DIRECTORY _pDebugDir { };
	DWORD _dwDebugDirSize { };
	PIMAGE_SECTION_HEADER _pDebugSecHeader = PEGetSectionHeaderFromName(".debug");

	if (_pDebugSecHeader && (_pDebugSecHeader->VirtualAddress == _dwDebugDirRVA))
	{
		if (m_fMapViewOfFileWhole)
			_pDebugDir = (PIMAGE_DEBUG_DIRECTORY)((DWORD_PTR)_pDebugSecHeader->PointerToRawData + (DWORD_PTR)m_lpBase);
		else
			_pDebugDir = (PIMAGE_DEBUG_DIRECTORY)((DWORD_PTR)m_lpSectionBase + (DWORD_PTR)m_dwDeltaFileOffsetToMap);

		_dwDebugDirSize = PEGetDirectoryEntrySize(IMAGE_DIRECTORY_ENTRY_DEBUG) * (DWORD)sizeof(IMAGE_DEBUG_DIRECTORY);
	}
	else // Looking for the debug directory
	{
		_pDebugSecHeader = PEGetSectionHeaderFromRVA(_dwDebugDirRVA);
		if (!_pDebugSecHeader)
			return IMAGE_HAS_NO_DEBUG_DIR;

		if (!(_pDebugDir = (PIMAGE_DEBUG_DIRECTORY)PERVAToPTR(_dwDebugDirRVA)))
			return IMAGE_HAS_NO_DEBUG_DIR;

		_dwDebugDirSize = PEGetDirectoryEntrySize(IMAGE_DIRECTORY_ENTRY_DEBUG);
	}

	DWORD _nDebugEntries = _dwDebugDirSize / (DWORD)sizeof(IMAGE_DEBUG_DIRECTORY);

	if (!_nDebugEntries)
		return -1;

	for (unsigned i = 0; i < _nDebugEntries; i++)
	{
		m_vecDebugTable.push_back(*_pDebugDir);
		_pDebugDir++;
	}
	m_dwFileSummary |= IMAGE_DEBUG_DIRECTORY_FLAG;

	return S_OK;
}

HRESULT Clibpe::PEGetArchitectureTable()
{
	DWORD _dwArchDirRVA = PEGetDirectoryEntryRVA(IMAGE_DIRECTORY_ENTRY_ARCHITECTURE);
	if (!_dwArchDirRVA)
		return IMAGE_HAS_NO_ARCHITECTURE_DIR;

	PIMAGE_ARCHITECTURE_ENTRY _pArchEntry = (PIMAGE_ARCHITECTURE_ENTRY)PERVAToPTR(_dwArchDirRVA);
	if (!_pArchEntry)
		return IMAGE_HAS_NO_ARCHITECTURE_DIR;

	m_dwFileSummary |= IMAGE_ARCHITECTURE_DIRECTORY_FLAG;

	return S_OK;
}

HRESULT Clibpe::PEGetGlobalPTRTable()
{
	DWORD_PTR _dwGlobalPTRDirRVA = (DWORD_PTR)PERVAToPTR(PEGetDirectoryEntryRVA(IMAGE_DIRECTORY_ENTRY_GLOBALPTR));
	if (!_dwGlobalPTRDirRVA)
		return IMAGE_HAS_NO_GLOBALPTR_DIR;

	m_dwFileSummary |= IMAGE_GLOBALPTR_DIRECTORY_FLAG;

	return S_OK;
}

HRESULT Clibpe::PEGetTLSTable()
{
	DWORD _dwTLSDirRVA = PEGetDirectoryEntryRVA(IMAGE_DIRECTORY_ENTRY_TLS);
	if (!_dwTLSDirRVA)
		return IMAGE_HAS_NO_TLS_DIR;

	PIMAGE_TLS_DIRECTORY32 _pTLSDir32 { };
	PIMAGE_TLS_DIRECTORY64 _pTLSDir64 { };
	std::vector<std::byte> _vecRawTLSData { };
	std::vector<DWORD> _vecTLSCallbacks { };

	if (IMAGE_HAS_FLAG(m_dwFileSummary, IMAGE_PE32_FLAG))
	{
		_pTLSDir32 = (PIMAGE_TLS_DIRECTORY32)PERVAToPTR(_dwTLSDirRVA);
		if (!_pTLSDir32)
			return IMAGE_HAS_NO_TLS_DIR;

		m_tupleTLS = { *_pTLSDir32, IMAGE_TLS_DIRECTORY64 { 0 }, _vecRawTLSData, _vecTLSCallbacks };
	}
	else if (IMAGE_HAS_FLAG(m_dwFileSummary, IMAGE_PE64_FLAG))
	{
		_pTLSDir64 = (PIMAGE_TLS_DIRECTORY64)PERVAToPTR(_dwTLSDirRVA);
		if (!_pTLSDir64)
			return IMAGE_HAS_NO_TLS_DIR;

		m_tupleTLS = { IMAGE_TLS_DIRECTORY32 { 0 }, *_pTLSDir64, std::move(_vecRawTLSData), std::move(_vecTLSCallbacks) };
	}
	m_dwFileSummary |= IMAGE_TLS_DIRECTORY_FLAG;

	return S_OK;
}

HRESULT Clibpe::PEGetLoadConfigTable()
{
	PIMAGE_LOAD_CONFIG_DIRECTORY32 _pLoadConfigDir32 { };
	PIMAGE_LOAD_CONFIG_DIRECTORY64 _pLoadConfigDir64 { };

	if (IMAGE_HAS_FLAG(m_dwFileSummary, IMAGE_PE32_FLAG))
	{
		_pLoadConfigDir32 = (PIMAGE_LOAD_CONFIG_DIRECTORY32)PERVAToPTR(PEGetDirectoryEntryRVA(IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG));
		if (!_pLoadConfigDir32)
			return IMAGE_HAS_NO_LOADCONFIG_DIR;

		m_tupleLoadConfigDir = { *_pLoadConfigDir32, IMAGE_LOAD_CONFIG_DIRECTORY64 { 0 } };
	}
	else if (IMAGE_HAS_FLAG(m_dwFileSummary, IMAGE_PE64_FLAG))
	{
		_pLoadConfigDir64 = (PIMAGE_LOAD_CONFIG_DIRECTORY64)PERVAToPTR(PEGetDirectoryEntryRVA(IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG));
		if (!_pLoadConfigDir64)
			return IMAGE_HAS_NO_LOADCONFIG_DIR;

		m_tupleLoadConfigDir = { IMAGE_LOAD_CONFIG_DIRECTORY32 { 0 }, *_pLoadConfigDir64 };
	}
	m_dwFileSummary |= IMAGE_LOADCONFIG_DIRECTORY_FLAG;

	return S_OK;
}

HRESULT Clibpe::PEGetBoundImportTable()
{
	PIMAGE_BOUND_IMPORT_DESCRIPTOR _pBoundImpDesc =
		(PIMAGE_BOUND_IMPORT_DESCRIPTOR)PERVAToPTR(PEGetDirectoryEntryRVA(IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT));

	if (!_pBoundImpDesc)
		return IMAGE_HAS_NO_BOUNDIMPORT_DIR;

	std::vector<std::tuple<IMAGE_BOUND_FORWARDER_REF, std::string>> _vecBoundForwarders { };
	std::string _strModuleName { };

	while (_pBoundImpDesc->TimeDateStamp)
	{
		PIMAGE_BOUND_FORWARDER_REF _pBoundImpForwarder = (PIMAGE_BOUND_FORWARDER_REF)(_pBoundImpDesc + 1);

		for (unsigned i = 0; i < _pBoundImpDesc->NumberOfModuleForwarderRefs; i++)
		{
			LPCSTR _lpszName = (LPCSTR)((DWORD_PTR)_pBoundImpDesc + _pBoundImpForwarder->OffsetModuleName);
			if (_lpszName && (StringCchLengthA(_lpszName, MAX_PATH, nullptr) != STRSAFE_E_INVALID_PARAMETER))
				_strModuleName = _lpszName;

			_vecBoundForwarders.push_back({ *_pBoundImpForwarder, std::move(_strModuleName) });
			_strModuleName.clear();

			_pBoundImpForwarder++;
			_pBoundImpDesc = (PIMAGE_BOUND_IMPORT_DESCRIPTOR)((DWORD_PTR)_pBoundImpDesc + sizeof(IMAGE_BOUND_FORWARDER_REF));
		}

		LPCSTR _lpszName = (LPCSTR)((DWORD_PTR)_pBoundImpDesc + _pBoundImpDesc->OffsetModuleName);
		if (_lpszName && (StringCchLengthA(_lpszName, MAX_PATH, nullptr) != STRSAFE_E_INVALID_PARAMETER))
			_strModuleName = _lpszName;

		m_vecBoundImportTable.push_back({ *_pBoundImpDesc, std::move(_strModuleName), std::move(_vecBoundForwarders) });
		_vecBoundForwarders.clear();
		_strModuleName.clear();

		_pBoundImpDesc++;
	}
	m_dwFileSummary |= IMAGE_BOUNDIMPORT_DIRECTORY_FLAG;

	return S_OK;
}

HRESULT Clibpe::PEGetIATTable()
{
	DWORD_PTR _dwIATDirRVA = (DWORD_PTR)PERVAToPTR(PEGetDirectoryEntryRVA(IMAGE_DIRECTORY_ENTRY_IAT));
	if (!_dwIATDirRVA)
		return IMAGE_HAS_NO_IAT_DIR;

	m_dwFileSummary |= IMAGE_IAT_DIRECTORY_FLAG;

	return S_OK;
}

HRESULT Clibpe::PEGetDelayImportTable()
{
	PIMAGE_DELAYLOAD_DESCRIPTOR _pDelayImpDescriptor = (PIMAGE_DELAYLOAD_DESCRIPTOR)PERVAToPTR(PEGetDirectoryEntryRVA(IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT));
	if (!_pDelayImpDescriptor)
		return IMAGE_HAS_NO_DELAY_IMPORT_DIR;

	PIMAGE_THUNK_DATA32 _pThunk32IAT { }, _pThunk32Name { }, _pThunk32BoundIAT { }, _pThunk32UnloadInfoIAT { };
	PIMAGE_THUNK_DATA64 _pThunk64IAT { }, _pThunk64Name { }, _pThunk64BoundIAT { }, _pThunk64UnloadInfoIAT { };
	std::vector<std::tuple<LONGLONG/*Ordinal/Hint*/, std::string/*Func name*/, LONGLONG/*Thunk table RVA*/,
		LONGLONG, LONGLONG, LONGLONG>> _vecFunc { };
	std::string _strDllName { };

	if (IMAGE_HAS_FLAG(m_dwFileSummary, IMAGE_PE32_FLAG))
	{
		while (_pDelayImpDescriptor->DllNameRVA)
		{
			_pThunk32Name = (PIMAGE_THUNK_DATA32)(DWORD_PTR)_pDelayImpDescriptor->ImportNameTableRVA;

			if (!_pThunk32Name)
				_pDelayImpDescriptor++;
			else
			{
				_pThunk32Name = (PIMAGE_THUNK_DATA32)PERVAToPTR((DWORD_PTR)_pThunk32Name);
				_pThunk32IAT = (PIMAGE_THUNK_DATA32)PERVAToPTR(_pDelayImpDescriptor->ImportAddressTableRVA);
				_pThunk32BoundIAT = (PIMAGE_THUNK_DATA32)PERVAToPTR(_pDelayImpDescriptor->BoundImportAddressTableRVA);
				_pThunk32UnloadInfoIAT = (PIMAGE_THUNK_DATA32)PERVAToPTR(_pDelayImpDescriptor->UnloadInformationTableRVA);

				if (!_pThunk32Name)
					return IMAGE_HAS_NO_DELAY_IMPORT_DIR;

				while (_pThunk32Name->u1.AddressOfData)
				{
					if (_pThunk32Name->u1.Ordinal & IMAGE_ORDINAL_FLAG32)
						_vecFunc.push_back({ IMAGE_ORDINAL32(_pThunk32Name->u1.Ordinal), "", _pThunk32Name->u1.AddressOfData,
							_pThunk32IAT ? _pThunk32IAT->u1.AddressOfData : 0,
							_pThunk32BoundIAT ? _pThunk32BoundIAT->u1.AddressOfData : 0,
							_pThunk32UnloadInfoIAT ? _pThunk32UnloadInfoIAT->u1.AddressOfData : 0 });
					else {//filling Hint, Name and Thunk RVA
						PIMAGE_IMPORT_BY_NAME _pName = (PIMAGE_IMPORT_BY_NAME)PERVAToPTR(_pThunk32Name->u1.AddressOfData);
						if (_pName && (StringCchLengthA(_pName->Name, MAX_PATH, nullptr) != STRSAFE_E_INVALID_PARAMETER))
							_strDllName = _pName->Name;

						_vecFunc.push_back({ _pName ? _pName->Hint : 0, std::move(_strDllName), _pThunk32Name->u1.AddressOfData,
							_pThunk32IAT ? _pThunk32IAT->u1.AddressOfData : 0,
							_pThunk32BoundIAT ? _pThunk32BoundIAT->u1.AddressOfData : 0,
							_pThunk32UnloadInfoIAT ? _pThunk32UnloadInfoIAT->u1.AddressOfData : 0 });
					}

					_pThunk32Name++;
					if (_pThunk32IAT)
						_pThunk32IAT++;
					if (_pThunk32BoundIAT)
						_pThunk32BoundIAT++;
					if (_pThunk32UnloadInfoIAT)
						_pThunk32UnloadInfoIAT++;

					_strDllName.clear();
				}

				LPCSTR _lpszName = (LPCSTR)PERVAToPTR(_pDelayImpDescriptor->DllNameRVA);
				if (_lpszName && (StringCchLengthA(_lpszName, MAX_PATH, nullptr) != STRSAFE_E_INVALID_PARAMETER))
					_strDllName = _lpszName;

				m_vecDelayImportTable.push_back({ *_pDelayImpDescriptor, std::move(_strDllName), std::move(_vecFunc) });
				_vecFunc.clear();
				_strDllName.clear();

				_pDelayImpDescriptor++;
			}
		}
	}
	else if (IMAGE_HAS_FLAG(m_dwFileSummary, IMAGE_PE64_FLAG))
	{
		while (_pDelayImpDescriptor->DllNameRVA)
		{
			_pThunk64Name = (PIMAGE_THUNK_DATA64)(DWORD_PTR)_pDelayImpDescriptor->ImportNameTableRVA;

			if (!_pThunk64Name)
				_pDelayImpDescriptor++;
			else
			{
				_pThunk64Name = (PIMAGE_THUNK_DATA64)PERVAToPTR((DWORD_PTR)_pThunk64Name);
				_pThunk64IAT = (PIMAGE_THUNK_DATA64)PERVAToPTR(_pDelayImpDescriptor->ImportAddressTableRVA);
				_pThunk64BoundIAT = (PIMAGE_THUNK_DATA64)PERVAToPTR(_pDelayImpDescriptor->BoundImportAddressTableRVA);
				_pThunk64UnloadInfoIAT = (PIMAGE_THUNK_DATA64)PERVAToPTR(_pDelayImpDescriptor->UnloadInformationTableRVA);

				if (!_pThunk64Name)
					return IMAGE_HAS_NO_DELAY_IMPORT_DIR;

				while (_pThunk64Name->u1.AddressOfData)
				{
					if (_pThunk64Name->u1.Ordinal & IMAGE_ORDINAL_FLAG64)
						_vecFunc.push_back({ IMAGE_ORDINAL64(_pThunk64Name->u1.Ordinal), "", _pThunk64Name->u1.AddressOfData,
							_pThunk64IAT ? _pThunk64IAT->u1.AddressOfData : 0,
							_pThunk64BoundIAT ? _pThunk64BoundIAT->u1.AddressOfData : 0,
							_pThunk64UnloadInfoIAT ? _pThunk64UnloadInfoIAT->u1.AddressOfData : 0 });
					else {//filling Hint, Name and Thunk RVA
						PIMAGE_IMPORT_BY_NAME _pName = (PIMAGE_IMPORT_BY_NAME)PERVAToPTR(_pThunk64Name->u1.AddressOfData);
						if (_pName && (StringCchLengthA(_pName->Name, MAX_PATH, nullptr) != STRSAFE_E_INVALID_PARAMETER))
							_strDllName = _pName->Name;

						_vecFunc.push_back({ _pName ? _pName->Hint : 0, std::move(_strDllName), _pThunk64Name->u1.AddressOfData,
							_pThunk64IAT ? _pThunk64IAT->u1.AddressOfData : 0,
							_pThunk64BoundIAT ? _pThunk64BoundIAT->u1.AddressOfData : 0,
							_pThunk64UnloadInfoIAT ? _pThunk64UnloadInfoIAT->u1.AddressOfData : 0 });
					}

					_pThunk64Name++;
					if (_pThunk64IAT)
						_pThunk64IAT++;
					if (_pThunk64BoundIAT)
						_pThunk64BoundIAT++;
					if (_pThunk64UnloadInfoIAT)
						_pThunk64UnloadInfoIAT++;

					_strDllName.clear();
				}

				LPCSTR _lpszName = (LPCSTR)PERVAToPTR(_pDelayImpDescriptor->DllNameRVA);
				if (_lpszName && (StringCchLengthA(_lpszName, MAX_PATH, nullptr) != STRSAFE_E_INVALID_PARAMETER))
					_strDllName = _lpszName;

				m_vecDelayImportTable.push_back({ *_pDelayImpDescriptor, std::move(_strDllName), std::move(_vecFunc) });
				_vecFunc.clear();
				_strDllName.clear();

				_pDelayImpDescriptor++;
			}
		}
	}
	m_dwFileSummary |= IMAGE_DELAYIMPORT_DIRECTORY_FLAG;

	return S_OK;
}

HRESULT Clibpe::PEGetCOMDescriptorTable()
{
	PIMAGE_COR20_HEADER _pCOMDescriptorHeader = (PIMAGE_COR20_HEADER)PERVAToPTR(PEGetDirectoryEntryRVA(IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR));
	if (!_pCOMDescriptorHeader)
		return IMAGE_HAS_NO_COMDESCRIPTOR_DIR;
	
	m_stCOR20Header = *_pCOMDescriptorHeader;

	m_dwFileSummary |= IMAGE_COMDESCRIPTOR_DIRECTORY_FLAG;

	return S_OK;
}
