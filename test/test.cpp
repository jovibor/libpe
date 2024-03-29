#include <format>
#include <iostream>
#include <string>

import libpe;
using namespace libpe;

int wmain(int argc, wchar_t* argv[])
{
	std::wstring_view wsvFile { L"C:\\Windows\\notepad.exe" }; //Default file.
	if (argc > 1) {
		wsvFile = argv[1];
	}

	libpe::Clibpe pe;
	if (pe.OpenFile(wsvFile.data()) != PEOK) {
		std::cout << "Open file failed.";
		return -1;
	}

	constexpr auto svFormat = "{:*^{}}\r\n";
	constexpr auto wsvFormat = L"{:*^{}}\r\n";
	constexpr auto uiWidth = 100UL;

	std::string strRich = std::format(svFormat, "Rich", uiWidth);
	if (const auto peRich = pe.GetRichHeader(); peRich) {
		for (const auto& ref : *peRich) {
			strRich += std::format("ID: {:04X}, Ver: {:05}, Count: {}\r\n", ref.wId, ref.wVersion, ref.dwCount);
		}
	}
	else {
		strRich += "No Rich header.\r\n";
	}
	std::cout << strRich << "\r\n";

	std::wstring wstrResources = std::format(wsvFormat, L"Resources", uiWidth);
	if (const auto peResRoot = pe.GetResources(); peResRoot) {
		for (const auto& iterRoot : peResRoot->vecResData) { //Main loop to extract Resources.
			auto ilvlRoot = 0;
			auto pResDirEntry = &iterRoot.stResDirEntry; //ROOT IMAGE_RESOURCE_DIRECTORY_ENTRY
			if (pResDirEntry->NameIsString) {
				wstrResources += std::format(L"Entry: {} [Name: {}]\r\n", ilvlRoot, iterRoot.wstrResName);
			}
			else {
				if (const auto iter = MapResID.find(pResDirEntry->Id); iter != MapResID.end()) {
					wstrResources += std::format(L"Entry: {} [Id: {}, {}]\r\n", ilvlRoot, pResDirEntry->Id, iter->second);
				}
				else {
					wstrResources += std::format(L"Entry: {} [Id: {}]\r\n", ilvlRoot, pResDirEntry->Id);
				}
			}

			if (pResDirEntry->DataIsDirectory) {
				auto ilvl2 = 0;
				auto pstResLvL2 = &iterRoot.stResLvL2;
				for (const auto& iterLvL2 : pstResLvL2->vecResData) {
					pResDirEntry = &iterLvL2.stResDirEntry; //Level 2 IMAGE_RESOURCE_DIRECTORY_ENTRY
					if (pResDirEntry->NameIsString) {
						wstrResources += std::format(L"    Entry: {}, Name: {}\r\n", ilvl2, iterLvL2.wstrResName);
					}
					else {
						wstrResources += std::format(L"    Entry: {}, Id: {}\r\n", ilvl2, pResDirEntry->Id);
					}

					if (pResDirEntry->DataIsDirectory) {
						auto ilvl3 = 0;
						auto pstResLvL3 = &iterLvL2.stResLvL3;
						for (const auto& iterLvL3 : pstResLvL3->vecResData) {
							pResDirEntry = &iterLvL3.stResDirEntry; //Level 3 IMAGE_RESOURCE_DIRECTORY_ENTRY
							if (pResDirEntry->NameIsString) {
								wstrResources += std::format(L"        Entry: {}, Name: {}\r\n", ilvl3, iterLvL3.wstrResName);
							}
							else {
								wstrResources += std::format(L"        Entry: {}, lang: {}\r\n", ilvl3, pResDirEntry->Id);
							}
							++ilvl3;
						}
					}
					++ilvl2;
				}
			}
			++ilvlRoot;
		}
	}
	else {
		wstrResources += L"No Resources found.\r\n";
	}
	std::wcout << wstrResources << L"\r\n";

	std::string strImports = std::format(svFormat, "Imports", uiWidth);
	if (const auto peImp = pe.GetImport(); peImp) {
		for (const auto& itModule : *peImp) { //Cycle through all imports.
			strImports += std::format("{}, Funcs: {}\r\n", itModule.strModuleName, itModule.vecImportFunc.size());
		}
	}
	else {
		strImports += "No Imports found.\r\n";
	}
	std::cout << strImports << "\r\n";

	std::string strSecurity = std::format(svFormat, "Security Directory", uiWidth);
	if (const auto peSecur = pe.GetSecurity(); peSecur) {
		for (const auto& itSecur : *peSecur) {
			const auto& refWinSert = itSecur.stWinSert;
			strSecurity += std::format("Offset: {}, Length: {}, Revision: {}, Cert Type: {}\r\n",
				itSecur.dwOffset, refWinSert.dwLength, refWinSert.wRevision, refWinSert.wCertificateType);
		}
	}
	else {
		strSecurity += "No Security directory found.\r\n";
	}
	std::cout << strSecurity << "\r\n";

	return 0;
}