/*
 * Copyright (C) 2021-2022 Huawei Device Co., Ltd.
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

#ifndef OHOS_WIFI_HAL_AP_INTERFACE_H
#define OHOS_WIFI_HAL_AP_INTERFACE_H

#include "wifi_hal_define.h"
#include "wifi_hal_struct.h"

#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @Description Start Ap.
 *
 * @param id - ap id
 * @return WifiErrorNo
 */
WifiErrorNo StartSoftAp(int id);

/**
 * @Description Start Hostapd.
 *
 * @param id - ap id
 * @return WifiErrorNo
 */
WifiErrorNo StartHostapd(void);

/**
 * @Description Init hostapd hal module.
 *
 * @param id - ap id
 * @return WifiErrorNo
 */
WifiErrorNo StartHostapdHal(int id);

/**
 * @Description Stop Ap.
 *
 * @return WifiErrorNo
 */
WifiErrorNo StopSoftAp(int id);

/**
 * @Description Stop hostapd.
 *
 * @return WifiErrorNo
 */
WifiErrorNo StopHostapd(void);

/**
 * @Description Release hostapd hal.
 *
 * @param id - ap id
 * @return WifiErrorNo
 */
WifiErrorNo StopHostapdHal(int id);

/**
 * @Description Obtains information about all connected STAs.
 *
 * @param infos - Connected STA information array.
 * @param size - Obtains the size of all sta information arrays and Size of the
 *               obtained sta information array.
 * @param id - ap id
 * @return WifiErrorNo
 */
WifiErrorNo GetStaInfos(char *infos, int32_t *size, int id);

/**
 * @Description Setting the AP Country Code.
 *
 * @param code - Country code.
 * @param id - ap id
 * @return WifiErrorNo
 */
WifiErrorNo SetCountryCode(const char *code, int id);

/**
 * @Description Setting the startup configuration items of the hostapd.
 *
 * @param config - Hostapd startup configuration.
 * @param id - ap id
 * @return WifiErrorNo
 */
WifiErrorNo SetHostapdConfig(HostapdConfig *config, int id);

/**
 * @Description To set the blocklist filtering in AP mode to prohibit
 *              the MAC address connection.
 *
 * @param mac - Blocklisted MAC address.
 * @param lenMac - Blocklist MAC address length.
 * @param id - ap id
 * @return WifiErrorNo
 */
WifiErrorNo SetMacFilter(const unsigned char *mac, int lenMac, int id);

/**
 * @Description To set blocklist filtering in AP mode and delete a specified MAC
 *              address from the blocklist.
 *
 * @param mac - Blocklisted MAC address.
 * @param lenMac - Blocklist MAC address length.
 * @param id - ap id
 * @return WifiErrorNo
 */
WifiErrorNo DelMacFilter(const unsigned char *mac, int lenMac, int id);

/**
 * @Description Disconnect the STA with a specified MAC address.
 *
 * @param mac - Blocklisted MAC address.
 * @param lenMac - Blocklist MAC address length.
 * @param id - ap id
 * @return WifiErrorNo
 */
WifiErrorNo DisassociateSta(const unsigned char *mac, int lenMac, int id);

/**
 * @Description Obtains the hotspot frequency supported by a specified
 *              frequency band.
 *
 * @param band - Specified frequency band.
 * @param frequencies - Frequency array.
 * @param size - Frequency array memory size and Returns the size of the frequency array.
 * @param id - ap id
 * @return WifiErrorNo
 */
WifiErrorNo WEAK_FUNC GetValidFrequenciesForBand(int32_t band, int *frequencies, int32_t *size, int id);

/**
 * @Description Set the power mode.
 *
 * @param mode - power mode.
 * @param id - ap id
 * @return WifiErrorNo
 */
WifiErrorNo WEAK_FUNC WifiSetPowerModel(const int mode, int id);

/**
 * @Description Get the power mode.
 *
 * @param mode - power mode.
 * @param id - ap id
 * @return WifiErrorNo
 */
WifiErrorNo WEAK_FUNC WifiGetPowerModel(int* mode, int id);
#ifdef __cplusplus
}
#endif
#endif