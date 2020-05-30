#ifndef _TAIHEN_HELPER_H_
#define _TAIHEN_HELPER_H_

#define HookImport(module_name, library_nid, func_nid, func_name) ({ \
	taiHookFunctionImport(&func_name ## _ref, module_name, library_nid, func_nid, func_name ## _patch); \
})

#define HookOffset(modid, offset, thumb, func_name) ({ \
	taiHookFunctionOffset(&func_name ## _ref, modid, 0, offset, thumb, func_name ## _patch); \
})

#define HookRelease(hook_uid, hook_func_name) ({ \
	if (hook_uid >= 0)taiHookRelease(hook_uid, hook_func_name ## _ref); \
})

int module_get_offset(SceUID modid, int segidx, uint32_t offset, void *stub_out);

#endif // _TAIHEN_HELPER_H_
