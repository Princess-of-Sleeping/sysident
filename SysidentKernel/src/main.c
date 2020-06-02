/*
 * Sysident Kernel
 * Copyright (C) 2020, 浅倉麗子, sysie, Princess of Sleeping
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, version 3 of the License.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#include <psp2kern/kernel/modulemgr.h>
#include <psp2kern/kernel/sysmem.h>
#include <psp2kern/kernel/cpu.h>
#include <taihen.h>

#include "sysident_helper.h"
#include "sysroot.h"

#define HookExport(module_name, library_nid, func_nid, func_name) taiHookFunctionExportForKernel(0x10005, &func_name ## _ref, module_name, library_nid, func_nid, func_name ## _patched)
#define HookImport(module_name, library_nid, func_nid, func_name) taiHookFunctionImportForKernel(0x10005, &func_name ## _ref, module_name, library_nid, func_nid, func_name ## _patched)
#define HookOffset(modid, offset, thumb, func_name) taiHookFunctionOffsetForKernel(0x10005, &func_name ## _ref, modid, 0, offset, thumb, func_name ## _patched)

#define HookRelease(hook_uid, hook_func_name) ({ \
	(hook_uid > 0) ? taiHookReleaseForKernel(hook_uid, hook_func_name ## _ref) : -1; \
})

int module_get_export_func(SceUID pid, const char *modname, unsigned int lib_nid, unsigned int func_nid, uintptr_t *func);

#define GetExport(modname, lib_nid, func_nid, func) module_get_export_func(KERNEL_PID, modname, lib_nid, func_nid, (uintptr_t *)func)

// #define printf ksceDebugPrintf
#define printf(...)

// old name is sceKernelGetSysrootBuffer
SceBootArgs *(* sceKernelSysrootGetKblParam)(void);

int (* scePervasiveGetSoCRevision)(void);

int  (* sceSysconGetBaryonVersion)(void);
void (* sceSysconGetErnieDLVersion)(int *result);
int  (* sceSysconGetBatteryVersion)(int *HWinfo, int *FWinfo, int *DFinfo);

int sysidentGetBootloaderRevision(int *pRev){

	int state, res;

	ENTER_SYSCALL(state);

	if(pRev == NULL){
		res = 0x80020006;
	}else{
		res = ksceKernelMemcpyKernelToUser((uintptr_t)pRev, (const void *)&sceKernelSysrootGetKblParam()->bootldr_revision, 4);
	}

	EXIT_SYSCALL(state);

	return res;
}

int sysidentGetSoCRevision(int *pRev){

	int state, res;

	ENTER_SYSCALL(state);

	if(pRev == NULL){
		res = 0x80020006;
	}else{
		res = scePervasiveGetSoCRevision();
		res = ksceKernelMemcpyKernelToUser((uintptr_t)pRev, &res, 4);
	}

	EXIT_SYSCALL(state);

	return res;
}

int sysidentGetBaryonVersion(void){

	int state, res;

	ENTER_SYSCALL(state);

	res = sceSysconGetBaryonVersion();

	EXIT_SYSCALL(state);

	return res;
}

int sysidentGetErnieDLVersion(int *pVersion){

	int state, res;

	ENTER_SYSCALL(state);

	if(pVersion == NULL){
		res = 0x80020006;
	}else{
		sceSysconGetErnieDLVersion(&res);
		res = ksceKernelMemcpyKernelToUser((uintptr_t)pVersion, &res, 4);
	}

	EXIT_SYSCALL(state);

	return res;
}

int sysidentGetBatteryVersion(int *pHWinfo, int *pFWinfo, int *pDFinfo){

	int state, res, HWinfo, FWinfo, DFinfo;

	ENTER_SYSCALL(state);

	res = sceSysconGetBatteryVersion(&HWinfo, &FWinfo, &DFinfo);

	if(res >= 0 && pHWinfo != NULL)
		res = ksceKernelMemcpyKernelToUser((uintptr_t)pHWinfo, &HWinfo, 4);

	if(res >= 0 && pFWinfo != NULL)
		res = ksceKernelMemcpyKernelToUser((uintptr_t)pFWinfo, &FWinfo, 4);

	if(res >= 0 && pDFinfo != NULL)
		res = ksceKernelMemcpyKernelToUser((uintptr_t)pDFinfo, &DFinfo, 4);

	EXIT_SYSCALL(state);

	return res;
}

void _start() __attribute__ ((weak, alias ("module_start")));
int module_start(SceSize argc, const void *args){

	if(GetExport("SceSysmem", 0x3691DA45, 0x9DB56D1F, &sceKernelSysrootGetKblParam) < 0)
		return SCE_KERNEL_START_NO_RESIDENT;

	if(GetExport("SceLowio", 0xE692C727, 0x714EEFB7, &scePervasiveGetSoCRevision) < 0)
		return SCE_KERNEL_START_NO_RESIDENT;

	if(GetExport("SceSyscon", 0x60A35F64, 0xFF86F4C5, &sceSysconGetBaryonVersion) < 0)
		return SCE_KERNEL_START_NO_RESIDENT;

	if(GetExport("SceSyscon", 0x60A35F64, 0xD2F456DC, &sceSysconGetErnieDLVersion) < 0)
		return SCE_KERNEL_START_NO_RESIDENT;

	if(GetExport("SceSyscon", 0x60A35F64, 0x68E0031E, &sceSysconGetBatteryVersion) < 0)
		return SCE_KERNEL_START_NO_RESIDENT;

	return SCE_KERNEL_START_SUCCESS;
}

__attribute__((noinline))
int module_stop(SceSize argc, const void *args){
	return SCE_KERNEL_STOP_SUCCESS;
}
