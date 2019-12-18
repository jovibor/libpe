/****************************************************************************************
* Copyright (C) 2018-2019, Jovibor: https://github.com/jovibor/                         *
* Windows library for reading PE (x86) and PE+ (x64) files' inner information.	        *
* Official git repository: https://github.com/jovibor/libpe                             *
* This software is available under the "MIT License".                                   *
****************************************************************************************/
#pragma once
#include "../libpe.h"

namespace libpe {
	//Implementation of pure virtual class Ilibpe.
	class Clibpe : public Ilibpe
	{
	public:
		Clibpe() = default;
		~Clibpe() = default;
		Clibpe(const Clibpe&) = delete;
		Clibpe(Clibpe&&) = delete;
		Clibpe& operator=(const Clibpe&) = delete;
		Clibpe& operator=(Clibpe&&) = delete;
		HRESULT LoadPe(LPCWSTR) override;
		HRESULT GetImageInfo(DWORD&)noexcept override;
		HRESULT GetImageFlag(DWORD dwFlag, bool& f)noexcept override;
		HRESULT GetOffsetFromRVA(ULONGLONG ullRVA, DWORD& dwOffset)noexcept override;
		HRESULT GetOffsetFromVA(ULONGLONG ullVA, DWORD& dwOffset)noexcept override;
		HRESULT GetMSDOSHeader(PLIBPE_DOSHEADER&)noexcept override;
		HRESULT GetRichHeader(PLIBPE_RICHHEADER_VEC&)noexcept override;
		HRESULT GetNTHeader(PLIBPE_NTHEADER&)noexcept override;
		HRESULT GetFileHeader(PLIBPE_FILEHEADER&)noexcept override;
		HRESULT GetOptionalHeader(PLIBPE_OPTHEADER_VAR&)noexcept override;
		HRESULT GetDataDirectories(PLIBPE_DATADIRS_VEC&)noexcept override;
		HRESULT GetSectionsHeaders(PLIBPE_SECHEADERS_VEC&)noexcept override;
		HRESULT GetExport(PLIBPE_EXPORT&)noexcept override;
		HRESULT GetImport(PLIBPE_IMPORT_VEC&)noexcept override;
		HRESULT GetResources(PLIBPE_RESOURCE_ROOT&)noexcept override;
		HRESULT GetExceptions(PLIBPE_EXCEPTION_VEC&)noexcept override;
		HRESULT GetSecurity(PLIBPE_SECURITY_VEC&)noexcept override;
		HRESULT GetRelocations(PLIBPE_RELOCATION_VEC&)noexcept override;
		HRESULT GetDebug(PLIBPE_DEBUG_VEC&)noexcept override;
		HRESULT GetTLS(PLIBPE_TLS&)noexcept override;
		HRESULT GetLoadConfig(PLIBPE_LOADCONFIG&)noexcept override;
		HRESULT GetBoundImport(PLIBPE_BOUNDIMPORT_VEC&)noexcept override;
		HRESULT GetDelayImport(PLIBPE_DELAYIMPORT_VEC&)noexcept override;
		HRESULT GetCOMDescriptor(PLIBPE_COMDESCRIPTOR&)noexcept override;
		HRESULT Destroy()override;
	private:
		PIMAGE_SECTION_HEADER getSecHdrFromRVA(ULONGLONG ullRVA) const;
		PIMAGE_SECTION_HEADER getSecHdrFromName(LPCSTR lpszName) const;
		LPVOID rVAToPtr(ULONGLONG ullRVA) const;
		DWORD rVAToOffset(ULONGLONG ullRVA) const;
		DWORD ptrToOffset(LPCVOID lp) const;
		DWORD getDirEntryRVA(DWORD dwEntry) const;
		DWORD getDirEntrySize(DWORD dwEntry) const;
		BYTE getByte(ULONGLONG ullOffset);
		DWORD getDword(ULONGLONG ullOffset);
		template<typename T> bool isPtrSafe(const T tPtr, bool fCanReferenceBoundary = false) const;
		bool mapFileOffset(ULONGLONG ullOffset);   //Maps file's raw offset. For big files.
		void unmapFileOffset();
		bool mapDirSection(DWORD dwDirectory);
		void unmapDirSection() const;
		HRESULT getDirBySecMapping();
		void clearAll();
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

		//Maximum address that can be dereferenced.
		ULONGLONG m_ullMaxPointerBound { };

		//Reserved 16K of memory that we can delete to properly handle 
		//E_OUTOFMEMORY exceptions, in case we catch one.
		std::unique_ptr<char []> m_pEmergencyMemory { std::make_unique<char []>(0x8FFF) };

		//Minimum bytes to map, if it's not possible to map file as a whole.
		const DWORD m_dwMinBytesToMap { 0xFFFF };

		//System information getting from GetSystemInfo().
		//Needed for dwAllocationGranularity.
		SYSTEM_INFO m_stSysInfo { };

		//For big files that can't be mapped completely
		//shows offset the mapping begins from.
		DWORD m_dwFileOffsetMapped { };

		//Delta after file mapping alignment.
		//m_dwDeltaFileOffsetMapped = m_dwFileOffsetMapped - dwAlignedAddressToMap;
		//dwAlignedAddressToMap = (m_dwFileOffsetMapped < SysInfo.dwAllocationGranularity) ? 0 :
		//(m_dwFileOffsetMapped - (m_dwFileOffsetMapped % SysInfo.dwAllocationGranularity));
		DWORD m_dwDeltaFileOffsetMapped { };

		//Is file loaded (mapped) completely, or section by section?
		bool m_fMapViewOfFileWhole { };

		//Flag shows PE load succession.
		bool m_fLoaded { false };

		//File summary info (type, sections, directories, etc...).
		DWORD m_dwImageFlags { };

		//Returned by CreateFileW.
		HANDLE m_hFile { };

		//Returned by CreateFileMappingW.
		HANDLE m_hMapObject { };

		//Pointer to file mapping beginning,
		//no matter if mapped completely or section by section.
		LPVOID m_lpBase { };

		//Pointer to beginning of mapping, if mapped section by section.
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
		LIBPE_NTHEADER m_stNTHeader { };

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
		LIBPE_EXCEPTION_VEC m_vecException { };

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

		//Helper struct for mapping file's parts, in case of big PE files.
		struct QUERYDATA
		{
			ULONGLONG ullStartOffsetMapped { };    //File is mapped starting from this raw offset.
			ULONGLONG ullEndOffsetMapped { };      //File's raw offset where mapping ends.
			DWORD     dwDeltaFileOffsetMapped { }; //Delta after ullStartOffsetMapped % m_stSysInfo.dwAllocationGranularity.
			LPVOID    lpData { };                  //File's Mapped data.
		}m_stQuery;
	};
}