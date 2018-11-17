#### **libpe** — win32 library for reading PE file format information. Supports x32 (PE32) and x64 (PE32+) binares.  
MSVS 2017, C++17.  
[Microsoft Visual C++ Redistributable for Visual Studio 2017 required.](https://aka.ms/vs/15/release/VC_redist.x86.exe)
___________________________________
**Usage:**  
```C++
#pragma comment(lib, "libpe.lib")
#include "libpe.h"  
  
Ilibpe* pLibpe;  
Getlibpe(&pLibpe);  
pLibpe->LoadPe("FileName");  

PCLIBPE_IMPORT_VEC pImport;
pLibpe->GetImportTable(&pImport);

PCLIBPE_EXPORT_TUP pExport;
pLibpe->GetExportTable(&pExport)
.  
.  
.  
pLibpe->Release();
```
