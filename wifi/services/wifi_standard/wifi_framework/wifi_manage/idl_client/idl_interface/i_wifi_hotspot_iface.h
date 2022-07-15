/*
 * Copyright (C) 2021 Huawei Device Co., Ltd.
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

#ifndef OHOS_IDL_IWIFI_HOTSPOT_IFACE_H
#define OHOS_IDL_IWIFI_HOTSPOT_IFACE_H

#include <stdint.h>
#include "wifi_error_no.h"
#include "i_wifi_struct.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @Description Sets the AP event callback function.
 *
 * @param callback
 * @param id - ap id
 */
void SetWifiApEventCallback(IWifiApEventCallback callback, int id);

/**
 * @Description Obtains the AP event callback structure.
 *
 * @return IWifiApEventCallback*
 */
IWifiApEventCallback *GetWifiApEventCallback(int id);

/**
 * @Description Start Ap.
 *
 * @return WifiErrorNo
 * @param id - ap id
 */
WifiErrorNo StartSoftAp(int id);

/**
 * @Description Close Ap.
 *
 * @return WifiErrorNo
 * @param id - ap id
 */
WifiErrorNo StopSoftAp(int id);

/**
 * @Description Setting the startup configuration items of the hostapd.
 *
 * @param config - HostapdConfig object's point.
 * @param id - ap id
 * @return WifiErrorNo
 */
WifiErrorNo SetHostapdConfig(HostapdConfig *config, int id);

/**
 * @Description Obtains information about all connected STAs.
 *
 * @param infos
 * @param size
 * @param id - ap id
 * @return WifiErrorNo
 */
WifiErrorNo GetStaInfos(char *infos, int32_t *size, int id);

/**
 * @Description To set the blocklist filtering in AP mode to prohibit the MAC
 *              address connection.
 *
 * @param mac - Mac address.
 * @param lenMac - Mac string length.
 * @param id - ap id
 * @return WifiErrorNo
 */
WifiErrorNo SetMacFilter(unsigned char *mac, int lenMac, int id);

/**
 * @Description This command is used to set blocklist filtering in AP mode and delete
 *              a specified MAC address from the blocklist.
 *
 * @param mac - Mac address.
 * @param lenMac - Mac string length.
 * @param id - ap id
 * @return WifiErrorNo
 */
WifiErrorNo DelMacFilter(unsigned char *mac, int lenMac, int id);

/**
 * @Description Disconnect the STA with a specified MAC address.
 *
 * @param mac - Mac address.
 * @param lenMac - Mac string length.
 * @param id - ap id
 * @return WifiErrorNo
 */
WifiErrorNo DisassociateSta(unsigned char *mac, int lenMac, int id);

/**
 * @Description Obtains the hotspot frequency supported by a specified frequency band.
 *
 * @param band - Band type.
 * @param frequencies - Numeric group pointer of the int type.
 * @param size - Size of the memory to which the frequencies point and the
 *               number of obtained data.
 * @param id - ap id
 * @return WifiErrorNo
 */
WifiErrorNo GetValidFrequenciesForBand(int32_t band, int *frequencies, int32_t *size, int id);

/**
 * @Description Setting the Wi-Fi Country Code.
 *
 * @param code
 * @param id - ap id
 * @return WifiErrorNo
 */
WifiErrorNo SetCountryCode(const char *code, int id);

/**
 * @Description Disconnect the STA connection based on the MAC address.
 *
 * @param mac - MAC address of the STA to be disconnected.
 * @param id - ap id
 * @return WifiErrorNo
 */
WifiErrorNo DisconnectStaByMac(const char *mac);

/**
 * @Description Information about the disconnected or connected STA.
 *
 * @param callback
 * @param id - ap id
 * @return WifiErrorNo
 */
WifiErrorNo RegisterAsscociatedEvent(IWifiApEventCallback callback, int id);

/**
 * @Description Get supported power model list
 *
 * @param model - the model to be set
 * @param id - ap id
 * @return ErrCode - operation result
 */
WifiErrorNo WpaSetPowerModel(const int model, int id);

/**
 * @Description Get power model
 *
 * @param model - current power model
 * @param id - ap id
 * @return ErrCode - operation result
 */
WifiErrorNo WpaGetPowerModel(int* model, int id);
#ifdef __cplusplus
}
#endif
#endif