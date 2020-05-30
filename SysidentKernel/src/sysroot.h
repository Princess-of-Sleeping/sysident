
#ifndef _PSP2_KERNEL_SYSROOT_H_
#define _PSP2_KERNEL_SYSROOT_H_

#include <psp2kern/types.h>

typedef struct SceBootArgs {
	unsigned short version;
	unsigned short size;
	int current_fw_version;
	int factory_fw_version;
	uint8_t unk_C[0x14];
	uint8_t qa_flags[0x10];
	uint8_t boot_flags[0x10];

	// Begin Dipsw
	uint32_t devkit_cp_timestamp_1;
	uint16_t devkit_cp_version;
	uint16_t devkit_cp_build_id;
	uint32_t devkit_cp_timestamp_2;
	uint32_t aslr_seed;
	uint32_t devkit_boot_parameters;
	uint32_t unk_54;
	uint32_t devkit_unk_flags;
	uint32_t devkit_flags_3;
	// End Dipsw

	unsigned int dram_base;
	SceSize dram_size;
	uint32_t unk_68;
	uint32_t boot_type_indicator_1;
	uint8_t open_psid[0x10];

	unsigned int secure_kernel_enp_addr;
	SceSize      secure_kernel_enp_size;
	unsigned int context_auth_sm_self_addr;
	SceSize      context_auth_sm_self_size;
	unsigned int kprx_auth_sm_self_addr;
	SceSize      kprx_auth_sm_self_size;
	unsigned int prog_rvk_srvk_addr;
	SceSize      prog_rvk_srvk_size;

	uint8_t pscode[0x8];
	uint8_t unk_A8[0x8];
	uint8_t session_id[0x10];
	uint32_t unk_C0;
	uint32_t wakeup_factor;
	uint32_t unk_C8;
	uint32_t unk_CC;
	unsigned int resume_context_addr;
	uint32_t hardware_info;
	uint32_t boot_type_indicator_2;
	uint8_t unk_DC[0xC];
	uint8_t hardware_flags[0x10];
	uint32_t bootldr_revision;
	uint32_t magic;
	uint8_t session_key[0x20];
	uint8_t unused[0xE0];
} __attribute__((packed)) SceBootArgs;

#endif // _PSP2_KERNEL_SYSROOT_H_
