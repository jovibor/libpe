#include "stdafx.h"
#include "libpe.h"
#include "Clibpe.h"

extern "C" HRESULT ILIBPEAPI Getlibpe(Ilibpe** pp)
{
	*pp = new Clibpe;

	return S_OK;
}
