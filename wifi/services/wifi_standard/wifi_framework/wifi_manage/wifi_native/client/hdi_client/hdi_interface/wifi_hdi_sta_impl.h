/*
 * Copyright (C) 2023 Huawei Device Co., Ltd.
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

#ifdef HDI_INTERFACE_SUPPORT
#ifndef OHOS_WIFI_HDI_STA_IMPL_H
#define OHOS_WIFI_HDI_STA_IMPL_H

#include "wifi_hdi_define.h"
#include "wifi_error_no.h"
#include "wifi_hdi_struct.h"
#include "v1_2/iwlan_interface.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @Description Turn on the Wi-Fi switch.
 *
 * @return WifiErrorNo - operation result
 */
WifiErrorNo HdiWifiStart(const char *ifaceName);

/**
 * @Description Disabling Wi-Fi
 *
 * @return WifiErrorNo - operation result
 */
WifiErrorNo HdiWifiStop();

/**
 * @Description start scan wifi info.
 *
 * @return WifiErrorNo - operation result
 */
WifiErrorNo HdiWifiStartScan(const ScanSettings *settings);

/**
 * @Description start pno scan wifi info.
 *
 * @return WifiErrorNo - operation result
 */
WifiErrorNo HdiWifiStartPnoScan(const PnoScanSettings *settings);

/**
 * @Description stop pno scan wifi info.
 *
 * @return WifiErrorNo - operation result
 */
WifiErrorNo HdiWifiStopPnoScan(void);

/**
 * @Description Get the scan infos from saved info.
 *
 * @param infos - saved infos
 * @param *size - input max size,and output scan size
 * @return WifiErrorNo - operation result
 */
WifiErrorNo HdiWifiGetScanInfos(ScanInfo *results, int *size);

/**
 * @Description Register event callback
 *
 * @param callback - event callback
 * @return WifiErrorNo - operation result
 */
WifiErrorNo HdiRegisterEventCallback(struct IWlanCallback *callback);

/**
 * @Description Get the signal infos from hdi.
 *
 * @param infos - saved infos
 * @return WifiErrorNo - operation result
 */
WifiErrorNo HdiWifiGetConnectSignalInfo(const char *endBssid, WpaSignalInfo *info);

/**
 * @Description register hdi callback event
 *
 * @return WifiHdiProxy - interface proxy object
 */
int32_t HdiWifiScanResultsCallback(struct IWlanCallback *self, uint32_t event,
    const struct HdfWifiScanResults *scanResults, const char* ifName);

/**
 * @Description unregister hdi callback event
 *
 * @return WifiErrorNo - operation result
 */
void HdiUnRegisterStaCallbackEvent();

/**
 * @Description unregister hdi callback event
 *
 * @return WifiErrorNo - operation result
 */
WifiErrorNo HdiRegisterStaCallbackEvent(struct IWlanCallback *callback);

/**
 * @Description set supplicant callback event
 *
 * @return NONE
 */
void HdiSetSupplicantEventCallback(ISupplicantEventCallback callback);

/**
 * @Description get supplicant callback event
 *
 * @return ISupplicantEventCallback
 */
ISupplicantEventCallback *HdiGetSupplicantEventCallback();

/**
 * @Description release local resources is hdi remote died
 *
 * @return NONE
 */
void HdiReleaseLocalResources();

/**
 * @Description set power save mode
 *
 * @return WifiErrorNo
 */
WifiErrorNo HdiSetPmMode(int frequency, int mode);

/**
 * @Description set data packet identification mark rule
 *
 * @return NONE
 */
WifiErrorNo HdiSetDpiMarkRule(int uid, int protocol, int enable);

void HdiNotifyScanResult(int status);

/**
 * @Description Get wifi chipset category form driver
 *
 * @return WifiErrorNo - operation result
 */
WifiErrorNo HdiGetChipsetCategory(int* chipsetCategory);

/**
 * @Description Get wifi featrure capability form driver
 *
 * @return WifiErrorNo - operation result
 */
WifiErrorNo HdiGetChipsetWifiFeatrureCapability(int* chipsetFeatrureCapability);
#ifdef __cplusplus
}
#endif
#endif
#endif