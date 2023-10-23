/*
 * Copyright (C) 2022 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef OHOS_HDI_STA_IMPL_H
#define OHOS_HDI_STA_IMPL_H

#include "wifi_hal_define.h"
#include "wifi_hal_struct.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @Description hdi sta init
 *
 * @return void
 */
void HdiStaInit();

/**
 * @Description hdi sta uninit
 *
 * @return void
 */
void HdiStaUnInit();

/**
 * @Description start scan wifi info.
 *
 * @return WifiErrorNo - operation result
 */
WifiErrorNo HdiStartScan(const ScanSettings *settings);

/**
 * @Description start pno scan wifi info.
 *
 * @return WifiErrorNo - operation result
 */
WifiErrorNo HdiStartPnoScan(const PnoScanSettings *settings);

/**
 * @Description stop pno scan wifi info.
 *
 * @return WifiErrorNo - operation result
 */
WifiErrorNo HdiStopPnoScan(void);

/**
 * @Description Get the scan infos from saved info.
 *
 * @param infos - saved infos
 * @param *size - input max size,and output scan size
 * @return WifiErrorNo - operation result
 */
WifiErrorNo GetHdiScanInfos(ScanInfo* infos, int *size);

/**
 * @Description Get the signal infos from hdi.
 *
 * @param infos - saved infos
 * @return WifiErrorNo - operation result
 */
WifiErrorNo GetHdiSignalInfo(WpaSignalInfo *info);

/**
 * @Description register hdi callback event
 *
 * @return WifiHdiProxy - interface proxy object
 */
WifiErrorNo RegisterHdiStaCallbackEvent();

/**
 * @Description unregister hdi callback event
 *
 * @return NONE
 */
void UnRegisterHdiStaCallbackEvent();

/**
 * @Description release local resources is hdi remote died
 *
 * @return NONE
 */
void ReleaseLocalResources();

#ifdef RANDOM_MAC_SUPPORT
/**
 * @Description Set RandomMac to hdi.
 *
 * @param mac - random mac
 * @param lenMac - mac string length
 * @return WifiErrorNo - operation result
 */
WifiErrorNo SetAssocMacAddr(const unsigned char *mac, int lenMac);
#endif

#ifdef __cplusplus
}
#endif
#endif