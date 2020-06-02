/*
 * Sysident Helper header
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

#ifndef _SYSIDENT_KERNEL_H_
#define _SYSIDENT_KERNEL_H_

int sysidentGetBootloaderRevision(int *rev);

int sysidentGetSoCRevision(int *pRev);

int sysidentGetBaryonVersion(void);
int sysidentGetErnieDLVersion(int *pVersion);
int sysidentGetBatteryVersion(int *pHWinfo, int *pFWinfo, int *pDFinfo);

#endif // _SYSIDENT_KERNEL_H_
