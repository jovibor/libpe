/*********************************************************************
* Copyright (C) 2018, Jovibor: https://github.com/jovibor/			 *
* PE viewer library for x86 (PE32) and x64 (PE32+) binares.			 *
* This code is provided «AS IS» without any warranty, and			 *
* can be used without any limitations for non-commercial usage.		 *
* Additional info can be found at https://github.com/jovibor/libpe	 *
*********************************************************************/
#include "stdafx.h"
#include "libpe.h"
#include "Clibpe.h"

extern "C" HRESULT ILIBPEAPI Getlibpe(Ilibpe** pIlibpe)
{
	*pIlibpe = new Clibpe;

	return S_OK;
}
