#include <psp2/kernel/modulemgr.h>
#include <taihen.h>

int module_get_offset(SceUID modid, int segidx, uint32_t offset, void *stub_out){

	int res = 0;
	SceKernelModuleInfo info;

	if(segidx > 3){
		return -1;
	}

	if(stub_out == NULL){
		return -2;
	}

	res = sceKernelGetModuleInfo(modid, &info);
	if(res < 0){
		return res;
	}

	if(offset > info.segments[segidx].memsz){
		return -3;
	}

	*(uint32_t *)stub_out = (uint32_t)(info.segments[segidx].vaddr + offset);

	return 0;
}
