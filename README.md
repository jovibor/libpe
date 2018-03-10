#### **libpe** — win32 library for reading PE file format information. Supports x32 and x64 bin. C++17, STL.
[Microsoft Visual C++ Redistributable for Visual Studio 2017 needed.](https://aka.ms/vs/15/release/VC_redist.x64.exe)
___________________________________
**Usage:**<br>
#import "libpe.lib" <br>
#include "libpe.h"
  
Ilibpe* peHandle;<br>
Getlibpe(&peHandle);<br>
peHandle->LoadPe(fileName);<br>
.<br>
.<br>
.<br>
peHandle->Release();<br>
