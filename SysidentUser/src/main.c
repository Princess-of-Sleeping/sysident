/*
 * Sysident
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

#include <psp2/kernel/modulemgr.h>
#include <psp2/kernel/threadmgr.h>
#include <psp2/kernel/sysmem.h>
#include <psp2/kernel/clib.h>
#include <psp2/io/devctl.h>
#include <psp2/vshbridge.h>

#include <taihen.h>
#include "taihen_min.h"
#include "../../SysidentKernel/src/sysident_helper.h"

SceUID _vshKernelSearchModuleByName(const char *module_name, void *vsh_buf);
int _vshSblAimgrGetSMI(int *result);
int _vshSysconGetHardwareInfo(unsigned char *info);
int sceSblPmMgrGetCurrentMode(int *result);
int _sceKernelGetOpenPsId(char *pOpenPsid);

#define DEBUG 0

int (* register_tag)(void *idk_ptr, const char *type, const char *string);
int (* add_string)(void *idk_ptr, const char *string); // add text

void *(* SceSystemSettingsCore_321CFB2E)(void *memptr, int a2); // type:box
void *(* SceSystemSettingsCore_AD9B37CF)(void *memptr, int a2); // type:button
void *(* SceSystemSettingsCore_DA2AFC21)(void *memptr, int a2); // type:title and text

int (* SceSystemSettingsCore_A4AB36D1)(int a1, void *idk_ptr);

void *(* scePafMalloc)(SceSize len);

int advanced_mode;

#if DEBUG != 0
SceUID hook[6];
#else
SceUID hook[2];
#endif

void add_category(const char *id, const char *title){

	void *ptr;
	void *idk_ptr = NULL;

	ptr = scePafMalloc(0x24);
	if (ptr != NULL)
		idk_ptr = SceSystemSettingsCore_DA2AFC21(ptr, 1);

	register_tag(idk_ptr, "id", id);
	register_tag(idk_ptr, "title", title);
	register_tag(idk_ptr, "icon", "tex_spanner");

	SceSystemSettingsCore_A4AB36D1(0, idk_ptr);
}

void add_entry(const char *id, const char *title, const char *string){

	void *ptr;
	void *idk_ptr = NULL;

	ptr = scePafMalloc(0x24);
	if (ptr != NULL)
		idk_ptr = SceSystemSettingsCore_DA2AFC21(ptr, 1);

	register_tag(idk_ptr, "id", id);

	register_tag(idk_ptr, "title", title);
	add_string(idk_ptr, string);

	SceSystemSettingsCore_A4AB36D1(0, idk_ptr);
}

void add_entry_box(const char *id, const char *title){

	void *ptr;
	void *idk_ptr = NULL;

	ptr = scePafMalloc(0x24);
	if (ptr != NULL)
		idk_ptr = SceSystemSettingsCore_321CFB2E(ptr, 1);

	register_tag(idk_ptr, "id", id);
	register_tag(idk_ptr, "file", "system_update_com.xml");
	register_tag(idk_ptr, "title", title);

	SceSystemSettingsCore_A4AB36D1(0, idk_ptr);
}

/*
 * 0x00000800 : R
 * 0x00000400 : L
 * 0x00000200 : START
 * 0x00000100 : SELECT
 * 0x00000080 : SQUARE
 * 0x00000040 : TRIANGLE
 * 0x00000020 : CROSS
 * 0x00000010 : CIRCLE
 * 0x00000008 : RIGHT
 * 0x00000004 : LEFT
 * 0x00000002 : DOWN
 * 0x00000001 : UP
 */
typedef struct SceSettingsCtrl {
	uint64_t	timeStamp;
	unsigned int 	buttons;
	unsigned short 	lx;
	unsigned short 	ly;
	unsigned short 	rx;
	unsigned short 	ry;

	// more?
} SceSettingsCtrl;

typedef struct SceSettingsCtrlArg {
	SceSettingsCtrl **ctrl;

	// more?
} SceSettingsCtrlArg;

typedef struct SceSettingsHiddenParam {
	char data[0xB0];
	int m_nStep;

	// more?
} SceSettingsHiddenParam;

int addCurrentFw(void){

	char text[0x80];
	SceKernelFwInfo data;

	sceClibMemset(&data, 0, sizeof(data));
	data.size = sizeof(data);

	_vshSblGetSystemSwVersion(&data);

	sceClibSnprintf(text, sizeof(text) - 1, "%X.%03X.%03X", ((data.version >> 24) & 0xFF), ((data.version >> 12) & 0xFFF), (data.version & 0xFFF));

	add_entry("info_vita_current_fw", "Current FW", text);

	return 0;
}

int addFactoryFw(void){

	char text[0x80];
	int version = 0;

	_vshSblAimgrGetSMI(&version);

	sceClibSnprintf(text, sizeof(text) - 1, "%X.%03X.%03X", ((version >> 24) & 0xFF), ((version >> 12) & 0xFFF), (version & 0xFFF));

	add_entry("info_vita_factory_fw", "Factory FW", text);

	return 0;
}

int addConsoleID(char *cid){

	char text[0x80];

	sceClibSnprintf(text, sizeof(text) - 1,
		"%02X%02X %02X%02X %02X%02X %02X%02X \n%02X%02X %02X%02X %02X%02X %02X%02X",
		cid[0x0], cid[0x1], cid[0x2], cid[0x3], cid[0x4], cid[0x5], cid[0x6], cid[0x7],
		cid[0x8], cid[0x9], cid[0xA], cid[0xB], cid[0xC], cid[0xD], cid[0xE], cid[0xF]
	);

	add_entry("info_vita_console_id", "Console ID", text);

	return 0;
}

int addOpenPSID(void){

	char OpenPSID[0x10];
	char text[0x80];

	sceClibMemset(OpenPSID, 0, sizeof(OpenPSID));

	_sceKernelGetOpenPsId(OpenPSID);

	sceClibSnprintf(text, sizeof(text) - 1,
		"%02X%02X%02X%02X %02X%02X%02X%02X\n%02X%02X%02X%02X %02X%02X%02X%02X",
		OpenPSID[0x0], OpenPSID[0x1], OpenPSID[0x2], OpenPSID[0x3],
		OpenPSID[0x4], OpenPSID[0x5], OpenPSID[0x6], OpenPSID[0x7],
		OpenPSID[0x8], OpenPSID[0x9], OpenPSID[0xA], OpenPSID[0xB],
		OpenPSID[0xC], OpenPSID[0xD], OpenPSID[0xE], OpenPSID[0xF]
	);

	add_entry("info_vita_open_psid", "Open PSID", text);

	return 0;
}

int addDeviceModel(char *cid){

	char text[0x80];

	sceClibSnprintf(text, sizeof(text) - 1, "Unknown");

	if(vshSblAimgrIsGenuineDolce() != 0){
		sceClibSnprintf(text, sizeof(text) - 1, "PlayStation TV");

	}else if(vshSblAimgrIsGenuineVITA() != 0){
		if(cid[7] == 0x14 || cid[7] == 0x18){
			sceClibSnprintf(text, sizeof(text) - 1, "PlayStation Vita Slim");
		}else if(cid[7] == 0x10){
			sceClibSnprintf(text, sizeof(text) - 1, "PlayStation Vita Fat%s", (vshSysconHasWWAN() == 0) ? "" : "(3G)");
		}else{
			sceClibSnprintf(text, sizeof(text) - 1, "PlayStation Vita Unknown");
		}
	}

	add_entry("info_vita_model", "Device Model", text);

	return 0;
}

int addDeviceType(char *cid){

	char text[0x80];

	sceClibSnprintf(text, sizeof(text) - 1, "Unknown");

	if(cid[5] < 0xF){
		switch(cid[5]){
		case 0x00:
			sceClibStrncpy(text, "Internal Test Unit", sizeof(text) - 1);
			break;
		case 0x01:
			sceClibStrncpy(text, "Development kit", sizeof(text) - 1);
			break;
		case 0x02:
			sceClibStrncpy(text, "Testing kit", sizeof(text) - 1);
			break;
		case 0x03:
			sceClibSnprintf(text, sizeof(text) - 1, "%s(%s)", "Retail", "J1/Japan");
			break;
		case 0x04:
			sceClibSnprintf(text, sizeof(text) - 1, "%s(%s)", "Retail", "UC2/United States");
			break;
		case 0x05:
			sceClibSnprintf(text, sizeof(text) - 1, "%s(%s)", "Retail", "CEL");
			break;
		case 0x06:
			sceClibSnprintf(text, sizeof(text) - 1, "%s(%s)", "Retail", "KR2");
			break;
		case 0x07:
			sceClibSnprintf(text, sizeof(text) - 1, "%s(%s)", "Retail", "CEK");
			break;
		case 0x08:
			sceClibSnprintf(text, sizeof(text) - 1, "%s(%s)", "Retail", "MX2");
			break;
		case 0x09:
			sceClibSnprintf(text, sizeof(text) - 1, "%s(%s)", "Retail", "AU3");
			break;
		case 0x0A:
			sceClibSnprintf(text, sizeof(text) - 1, "%s(%s)", "Retail", "E12");
			break;
		case 0x0B:
			sceClibSnprintf(text, sizeof(text) - 1, "%s(%s)", "Retail", "TW1/Taiwan");
			break;
		case 0x0C:
			sceClibSnprintf(text, sizeof(text) - 1, "%s(%s)", "Retail", "RU3");
			break;
		case 0x0D:
			sceClibSnprintf(text, sizeof(text) - 1, "%s(%s)", "Retail", "CN9");
			break;
		case 0x0E:
			sceClibSnprintf(text, sizeof(text) - 1, "%s(%s)", "Retail", "HK5");
			break;
		case 0x0F:
			sceClibSnprintf(text, sizeof(text) - 1, "%s(%s)", "Retail", "RSV1/reserved1");
			break;
		case 0x10:
			sceClibSnprintf(text, sizeof(text) - 1, "%s(%s)", "Retail", "RSV2/reserved2");
			break;
		case 0x11:
			sceClibSnprintf(text, sizeof(text) - 1, "%s(%s)", "Retail", "RSV3/reserved3");
			break;
		}
	}

	add_entry("info_vita_type", "Device Type", text);

	return 0;
}

int addSystemType(void){

	char text[0x80];

	sceClibSnprintf(text, sizeof(text) - 1, "Unknown");

	if(vshSblAimgrIsCEX() != 0){
		sceClibSnprintf(text, sizeof(text) - 1, "Retail");
	}else if(vshSblAimgrIsDEX() != 0){
		sceClibSnprintf(text, sizeof(text) - 1, "Testing kit");
	}else if(vshSblAimgrIsTool() != 0){
		sceClibSnprintf(text, sizeof(text) - 1, "Development kit");
	}else if(vshSblAimgrIsTest() != 0){
		sceClibSnprintf(text, sizeof(text) - 1, "Internal Test Unit");
	}

	add_entry("info_vita_sys_type", "System Type", text);

	return 0;
}

int addDevelopmentMode(void){

	add_entry("info_mode_devmode", "Development Mode", (vshSblSsIsDevelopmentMode() != 0) ? "Yes" : "No");

	return 0;
}

int addDownloaderMode(void){

	add_entry("info_mode_dlmode", "Downloader Mode", (vshSysconIsDownLoaderMode() != 0) ? "Yes" : "No");

	return 0;
}

int addIduMode(void){

	add_entry("info_mode_idu_mode", "IDU Mode", (vshSysconIsIduMode() != 0) ? "Yes" : "No");

	return 0;
}

int addShowMode(void){

	add_entry("info_mode_show_mode", "Show Mode", (vshSysconIsShowMode() != 0) ? "Yes" : "No");

	return 0;
}

int addManuMode(void){

	int result = 0;

	sceSblPmMgrGetCurrentMode(&result);

	add_entry("info_mode_manu_mode", "Manufacturing Mode", (result != 0) ? "Yes" : "No");

	return 0;
}

const char *byte_count[] = {
	"Byte",
	"KB",
	"MB",
	"GB",
	"TB"
};

int i2f(float *dst, uint32_t val);

int addDeviceSpace(const char *dev){

	int res, count_max = 0, count_used = 0;
	SceOff max, used;
	float used_size, max_size;
	char text[0x80];

	SceIoDevInfo info;
	sceClibMemset(&info, 0, sizeof(SceIoDevInfo));

	res = sceIoDevctl(dev, 0x3001, 0, 0, &info, sizeof(SceIoDevInfo));

	if(res == 0){

		used = info.max_size - info.free_size;
		max  = info.max_size;

		while(max > 0x100000){
			max >>= 10; count_max++;
		}

		if(max < 0x400){
			max <<= 10; count_max = 0xFFFFFFFF;
		}

		i2f(&max_size, (uint32_t)max);

		while(used > 0x100000){
			used >>= 10; count_used++;
		}

		if(used < 0x400){
			used <<= 10; count_used = 0xFFFFFFFF;
		}

		i2f(&used_size, (uint32_t)used);

		sceClibSnprintf(text, sizeof(text) - 1, "%.2lf %s / %.2lf %s", used_size, byte_count[count_used + 1], max_size, byte_count[count_max + 1]);

	}else{
		sceClibStrncpy(text, "not found", sizeof(text) - 1);
	}

	add_entry("info_dev_space", dev, text);

	return 0;
}

int addSerialNo(void){

	int start_idx = 0;
	char text[0x80];
	short buf[0x200 >> 1];

	sceClibMemset(buf, 0, sizeof(buf));
	vshIdStorageReadLeaf(0x112, buf);

	while(buf[start_idx] == buf[start_idx + 1])
		start_idx++;

	sceClibSnprintf(text, sizeof(text) - 1, "%X%X-%X%X%X%X%X%X%X%X %X%X%X%X%X%X%X",
		(buf[start_idx + 0x0] >> 8 & 0xF), (buf[start_idx + 0x1] >> 8 & 0xF),

		(buf[start_idx + 0x2] >> 8 & 0xF), (buf[start_idx + 0x3] >> 8 & 0xF),
		(buf[start_idx + 0x4] >> 8 & 0xF), (buf[start_idx + 0x5] >> 8 & 0xF),
		(buf[start_idx + 0x6] >> 8 & 0xF), (buf[start_idx + 0x7] >> 8 & 0xF),
		(buf[start_idx + 0x8] >> 8 & 0xF), (buf[start_idx + 0x9] >> 8 & 0xF),

		(buf[start_idx + 0xA] >> 8 & 0xF), (buf[start_idx + 0xB] >> 8 & 0xF),
		(buf[start_idx + 0xC] >> 8 & 0xF), (buf[start_idx + 0xD] >> 8 & 0xF),
		(buf[start_idx + 0xE] >> 8 & 0xF), (buf[start_idx + 0xF] >> 8 & 0xF),
		(buf[start_idx + 0x10] >> 8 & 0xF)
	);

	add_entry("info_serial_no", "Serial No", text);

	return 0;
}

int addModelFromIdStorage(void){

	char text[0x80];
	char temp[0x10];
	char buf[0x200];

	sceClibMemset(buf, 0, sizeof(buf));
	vshIdStorageReadLeaf(0x115, buf);

	sceClibMemset(temp, 0, sizeof(temp));
	sceClibMemcpy(temp, buf, 8);
	buf[0x10] = 0;

	if(temp[3] == 0x30)
		temp[3] = '-';

	buf[0xC] = 0;

	sceClibSnprintf(text, sizeof(text) - 1, "%s/%s", temp, &buf[0x8]);

	add_entry("info_model_from_idstorage", "Model", text);

	return 0;
}

int addHardwareInfo(void){

	char text[0x80];
	unsigned char info[4];

	sceClibMemset(info, 0, sizeof(info));
	_vshSysconGetHardwareInfo(info);

	sceClibSnprintf(text, sizeof(text) - 1, "%02X %02X %02X %02X", info[3], info[2], info[1], info[0]);

	add_entry("info_hardware_info", "Hardware Info", text);

	return 0;
}

int addBootloaderRevision(void){

	int rev = 0;
	char text[0x80];

	sysidentGetBootloaderRevision(&rev);

	sceClibSnprintf(text, sizeof(text) - 1, "%d", rev);

	add_entry("info_bootloader_rev", "Bootloader Revision", text);

	return 0;
}

int addSoCRevision(void){

	int rev = 0;
	char text[0x80];

	sysidentGetSoCRevision(&rev);

	sceClibSnprintf(text, sizeof(text) - 1, "%d", rev & 0xFFFF);

	add_entry("info_soc_rev", "SoC Revision", text);

	return 0;
}

int addErnieDLVersion(void){

	int ver = 0;
	char text[0x80];

	sysidentGetErnieDLVersion(&ver);

	sceClibSnprintf(text, sizeof(text) - 1, "0x%08X", ver);

	add_entry("info_ernie_dl_version", "Ernie DL Version", text);

	return 0;
}

int addBatteryVersion(void){

	int HWinfo, FWinfo, DFinfo;
	char text[0x80];

	sysidentGetBatteryVersion(&HWinfo, &FWinfo, &DFinfo);

	add_entry("info_battery_version", "Battery Version", " ");

	sceClibSnprintf(text, sizeof(text) - 1, "0x%08X(%s)", HWinfo, (HWinfo > 7) ? "Abby" : "Bert");
	add_entry("info_battery_version_1", "HWinfo", text);

	sceClibSnprintf(text, sizeof(text) - 1, "0x%08X", FWinfo);
	add_entry("info_battery_version_2", "FWinfo", text);

	sceClibSnprintf(text, sizeof(text) - 1, "0x%08X", DFinfo);
	add_entry("info_battery_version_3", "DFinfo", text);

	return 0;
}

int addBaryonVersion(void){

	char text[0x80];

	sceClibSnprintf(text, sizeof(text) - 1, "0x%08X", sysidentGetBaryonVersion());

	add_entry("info_baryon_version", "Baryon Version", text);

	return 0;
}

int addSysident(SceSize args, void *argp){

	char cid[0x20];

	_vshSblAimgrGetConsoleId(cid);

	add_category("sysident_system", "System Info");

	addCurrentFw();
	addFactoryFw();

	addSerialNo();
	addModelFromIdStorage();

	addConsoleID(cid);
	addOpenPSID();
	addDeviceModel(cid);
	addDeviceType(cid);
	addSystemType();

	add_category("sysident_system_mode", "System Mode");

	addIduMode();
	addShowMode();
	addManuMode();
	addDevelopmentMode();
	addDownloaderMode();

	add_category("sysident_dev_space", "Device Space");

	addDeviceSpace("gro0:");
	addDeviceSpace("grw0:");
	addDeviceSpace("imc0:");
	addDeviceSpace("os0:");
	addDeviceSpace("pd0:");
	addDeviceSpace("sa0:");
	addDeviceSpace("tm0:");
	addDeviceSpace("sd0:");
	addDeviceSpace("ud0:");
	addDeviceSpace("uma0:");
	addDeviceSpace("ur0:");
	addDeviceSpace("ux0:");
	addDeviceSpace("vd0:");
	addDeviceSpace("vs0:");
	addDeviceSpace("xmc0:");

	if(advanced_mode != 0){
		add_category("sysident_advanced_mode", "Advanced Mode");
		addHardwareInfo();
		addBootloaderRevision();
		addSoCRevision();
		addBaryonVersion();
		addErnieDLVersion();
		addBatteryVersion();
	}

	return 0;
}

#define WAIT_FRAME 21

tai_hook_ref_t SettingsShowHiddenInfo_ref;
int SettingsShowHiddenInfo_patch(SceSettingsHiddenParam *a1, SceSettingsCtrlArg *a2){

	int ret = 0;

	if(a1->m_nStep < WAIT_FRAME)
		a1->m_nStep++;

	if (a1->m_nStep != WAIT_FRAME)
		return ret;

	a1->m_nStep++;

	addSysident(0, NULL);

	return ret;
}

static tai_hook_ref_t sceKernelLoadStartModule_ref;
static SceUID sceKernelLoadStartModule_patch(const char *path, SceSize args, void *argp, int flags, SceKernelLMOption *option, int *status){
	SceUID ret;

	ret = TAI_CONTINUE(SceUID, sceKernelLoadStartModule_ref, path, args, argp, flags, option, status);

	if(ret > 0 && sceClibStrncmp(path, "vs0:app/NPXS10015/system_settings_core.suprx", 44) == 0){

		taiGetModuleExportFunc("SceSystemSettingsCore", 0x4562B26E, 0x321CFB2E, (uintptr_t *)&SceSystemSettingsCore_321CFB2E);
		taiGetModuleExportFunc("SceSystemSettingsCore", 0x4562B26E, 0xA4AB36D1, (uintptr_t *)&SceSystemSettingsCore_A4AB36D1);
		taiGetModuleExportFunc("SceSystemSettingsCore", 0x4562B26E, 0xAD9B37CF, (uintptr_t *)&SceSystemSettingsCore_AD9B37CF);
		taiGetModuleExportFunc("SceSystemSettingsCore", 0x4562B26E, 0xDA2AFC21, (uintptr_t *)&SceSystemSettingsCore_DA2AFC21);

		taiGetModuleExportFunc("ScePaf", 0xA7D28DAE, 0xFC5CD359, (uintptr_t *)&scePafMalloc);
	}

	return ret;
}

#if DEBUG != 0
tai_hook_ref_t sceSblQafMgrIsAllowAllDebugMenuDisplay_ref;
int sceSblQafMgrIsAllowAllDebugMenuDisplay_patch(void){

	TAI_CONTINUE(int, sceSblQafMgrIsAllowAllDebugMenuDisplay_ref);

	return 0;
}

tai_hook_ref_t sceSblQafMgrIsAllowMinimumDebugMenuDisplay_ref;
int sceSblQafMgrIsAllowMinimumDebugMenuDisplay_patch(void){

	TAI_CONTINUE(int, sceSblQafMgrIsAllowMinimumDebugMenuDisplay_ref);

	return 0;
}

tai_hook_ref_t sceSblQafMgrIsAllowLimitedDebugMenuDisplay_ref;
int sceSblQafMgrIsAllowLimitedDebugMenuDisplay_patch(void){

	TAI_CONTINUE(int, sceSblQafMgrIsAllowLimitedDebugMenuDisplay_ref);

	return 0;
}

tai_hook_ref_t vshSblUtMgrHasStoreFlag_ref;
int vshSblUtMgrHasStoreFlag_patch(void){

	TAI_CONTINUE(int, vshSblUtMgrHasStoreFlag_ref);

	return 0;
}
#endif

int vshSblUtMgrHasStoreFlag(void);
int sceSblQafMgrIsAllowAllDebugMenuDisplay(void);
int sceSblQafMgrIsAllowMinimumDebugMenuDisplay(void);
int sceSblQafMgrIsAllowLimitedDebugMenuDisplay(void);

void _start() __attribute__ ((weak, alias ("module_start")));
int module_start(SceSize argc, const void *args){

	tai_module_info_t info;
	info.size = sizeof(info);

	if(taiGetModuleInfo("SceSettings", &info) < 0)
		return SCE_KERNEL_START_FAILED;

	int buf[2];

	advanced_mode = (_vshKernelSearchModuleByName("SysidentKernel", buf) < 0) ? 0 : 1;

	int old_cmd = 0;

	if(old_cmd == 0)
		old_cmd = vshSblUtMgrHasStoreFlag();

	if(old_cmd == 0)
		old_cmd = sceSblQafMgrIsAllowAllDebugMenuDisplay();

	if(old_cmd == 0)
		old_cmd = sceSblQafMgrIsAllowMinimumDebugMenuDisplay();

	if(old_cmd == 0)
		old_cmd = sceSblQafMgrIsAllowLimitedDebugMenuDisplay();

	switch(info.module_nid){
	case 0xC2A86F54: // SceSettings 3.60 retail
		module_get_offset(info.modid, 0, 0x1628F, &register_tag);
		module_get_offset(info.modid, 0, 0x16421, &add_string);
		hook[0] = HookOffset(info.modid, (old_cmd == 0) ? 0x1A0358 : 0x1A0298, 1, SettingsShowHiddenInfo);
	break;

	case 0x3C331B4C: // SceSettings 3.61 retail
	case 0x663D16BA: // SceSettings 3.63 retail
	case 0x13B4C016: // SceSettings 3.65 retail
		module_get_offset(info.modid, 0, 0x1628F, &register_tag);
		module_get_offset(info.modid, 0, 0x16421, &add_string);
		hook[0] = HookOffset(info.modid, (old_cmd == 0) ? 0x1A035C : 0x1A029C, 1, SettingsShowHiddenInfo);
	break;

	case 0x313B7C2F: // SceSettings 3.67 retail
	case 0xEECD991F: // SceSettings 3.69 retail
		module_get_offset(info.modid, 0, 0x1628F, &register_tag);
		module_get_offset(info.modid, 0, 0x16421, &add_string);
		hook[0] = HookOffset(info.modid, (old_cmd == 0) ? 0x19DC9C : 0x19DBDC, 1, SettingsShowHiddenInfo);
	break;

	case 0xC70F5DBF: // SceSettings 3.68 retail
		module_get_offset(info.modid, 0, 0x1628F, &register_tag);
		module_get_offset(info.modid, 0, 0x16421, &add_string);
		hook[0] = HookOffset(info.modid, (old_cmd == 0) ? 0x19DC98 : 0x19DBD8, 1, SettingsShowHiddenInfo);
	break;

	case 0x87B0BDAA: // SceSettings 3.70 retail
		module_get_offset(info.modid, 0, 0x1628F, &register_tag);
		module_get_offset(info.modid, 0, 0x16421, &add_string);
		hook[0] = HookOffset(info.modid, (old_cmd == 0) ? 0x19DD10 : 0x19DC50, 1, SettingsShowHiddenInfo);
	break;

	case 0xF432CA79: // SceSettings 3.71 retail
	case 0xB3D172E6: // SceSettings 3.72 retail
	case 0xE37F668C: // SceSettings 3.73 retail
		module_get_offset(info.modid, 0, 0x1628F, &register_tag);
		module_get_offset(info.modid, 0, 0x16421, &add_string);
		hook[0] = HookOffset(info.modid, (old_cmd == 0) ? 0x19DD14 : 0x19DC54, 1, SettingsShowHiddenInfo);
	break;

	case 0x10BA2399: // SceSettings 3.60 Testkit
		module_get_offset(info.modid, 0, 0x1628F, &register_tag);
		module_get_offset(info.modid, 0, 0x16421, &add_string);
		hook[0] = HookOffset(info.modid, (old_cmd == 0) ? 0x1A4B2C : 0x1A4A6C, 1, SettingsShowHiddenInfo);
	break;

	case 0xDFC5F186: // SceSettings 3.61 Testkit
	case 0x163D1795: // SceSettings 3.63 Testkit
	case 0xDDBDCA22: // SceSettings 3.65 Testkit
		module_get_offset(info.modid, 0, 0x1628F, &register_tag);
		module_get_offset(info.modid, 0, 0x16421, &add_string);
		hook[0] = HookOffset(info.modid, (old_cmd == 0) ? 0x1A4B30 : 0x1A4A70, 1, SettingsShowHiddenInfo);
	break;

	case 0x9F6C8C9B: // SceSettings 3.67 Testkit
		module_get_offset(info.modid, 0, 0x1628F, &register_tag);
		module_get_offset(info.modid, 0, 0x16421, &add_string);
		hook[0] = HookOffset(info.modid, (old_cmd == 0) ? 0x1A2470 : 0x1A23B0, 1, SettingsShowHiddenInfo);
	break;

	case 0xCE26FE98: // SceSettings 3.68 Testkit
		module_get_offset(info.modid, 0, 0x1628F, &register_tag);
		module_get_offset(info.modid, 0, 0x16421, &add_string);
		hook[0] = HookOffset(info.modid, (old_cmd == 0) ? 0x1A246C : 0x1A23AC, 1, SettingsShowHiddenInfo);
	break;

	case 0xDD4118A4: // SceSettings 3.60 Devkit
		module_get_offset(info.modid, 0, 0x16343, &register_tag);
		module_get_offset(info.modid, 0, 0x164D5, &add_string);
		hook[0] = HookOffset(info.modid, (old_cmd == 0) ? 0x1A99E4 : 0x1A9924, 1, SettingsShowHiddenInfo);
	break;

	case 0xE44106DE: // SceSettings 3.61 Devkit
	case 0x5B1FDA3E: // SceSettings 3.63 Devkit
	case 0x00994D5D: // SceSettings 3.65 Devkit
		module_get_offset(info.modid, 0, 0x16343, &register_tag);
		module_get_offset(info.modid, 0, 0x164D5, &add_string);
		hook[0] = HookOffset(info.modid, (old_cmd == 0) ? 0x1A99E8 : 0x1A9928, 1, SettingsShowHiddenInfo);
	break;

	case 0xE55683E6: // SceSettings 3.67 Devkit
		module_get_offset(info.modid, 0, 0x16343, &register_tag);
		module_get_offset(info.modid, 0, 0x164D5, &add_string);
		hook[0] = HookOffset(info.modid, (old_cmd == 0) ? 0x1A7328 : 0x1A7268, 1, SettingsShowHiddenInfo);
	break;

	case 0xAD2E2D54: // SceSettings 3.68 Devkit
		module_get_offset(info.modid, 0, 0x16343, &register_tag);
		module_get_offset(info.modid, 0, 0x164D5, &add_string);
		hook[0] = HookOffset(info.modid, (old_cmd == 0) ? 0x1A7324 : 0x1A7264, 1, SettingsShowHiddenInfo);
	break;

	default:
		sceClibPrintf("Module nid : 0x%08X\n", info.module_nid);
		return SCE_KERNEL_START_FAILED;
	}

	hook[1] = HookImport("SceSettings", 0xCAE9ACE6, 0x2DCC4AFA, sceKernelLoadStartModule);

#if DEBUG != 0
	hook[2] = HookImport("SceSettings", 0x35C5ACD4, 0x4A004B05, vshSblUtMgrHasStoreFlag);
	hook[3] = HookImport("SceSettings", 0x756B7E89, 0x66843305, sceSblQafMgrIsAllowAllDebugMenuDisplay);
	hook[4] = HookImport("SceSettings", 0x756B7E89, 0xA156BBD2, sceSblQafMgrIsAllowMinimumDebugMenuDisplay);
	hook[5] = HookImport("SceSettings", 0x756B7E89, 0xC456212D, sceSblQafMgrIsAllowLimitedDebugMenuDisplay);
#endif

	return SCE_KERNEL_START_SUCCESS;
}

int module_stop(SceSize argc, const void *args){

	HookRelease(hook[0], SettingsShowHiddenInfo);
	HookRelease(hook[1], sceKernelLoadStartModule);

#if DEBUG != 0
	HookRelease(hook[2], vshSblUtMgrHasStoreFlag);
	HookRelease(hook[3], sceSblQafMgrIsAllowAllDebugMenuDisplay);
	HookRelease(hook[4], sceSblQafMgrIsAllowMinimumDebugMenuDisplay);
	HookRelease(hook[5], sceSblQafMgrIsAllowLimitedDebugMenuDisplay);
#endif

	return SCE_KERNEL_STOP_SUCCESS;
}
