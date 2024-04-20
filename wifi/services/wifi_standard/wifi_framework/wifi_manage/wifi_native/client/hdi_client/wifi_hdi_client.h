/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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
#ifndef OHOS_WIFI_HDI_CLIENT_H
#define OHOS_WIFI_HDI_CLIENT_H

#include <string>
#include <vector>

#include "wifi_msg.h"
#include "wifi_scan_param.h"
#include "wifi_internal_msg.h"
#include "wifi_hdi_define.h"
#include "wifi_hdi_struct.h"
#include "wifi_error_no.h"
#include "wifi_idl_struct.h"
#include "supplicant_event_callback.h"

namespace OHOS {
namespace Wifi {
class WifiHdiClient {
public:
    WifiHdiClient() = default;
    ~WifiHdiClient() = default;

    /* ************************ Sta Interface ************************** */
    /**
     * @Description Open WiFi.
     *
     * @return WifiErrorNo
     */
    WifiErrorNo StartWifi(const std::string &ifaceName);

    /**
     * @Description Turn off WiFi.
     *
     * @return WifiErrorNo
     */
    WifiErrorNo StopWifi();

    /**
     * @Description Scan by specified parameter.
     *
     * @param scanParam
     * @return WifiErrorNo
     */
    WifiErrorNo Scan(const WifiScanParam &scanParam);

    /**
     * @Description Register event callback
     *
     * @param scanParam
     * @return WifiErrorNo
     */
    WifiErrorNo ReqRegisterSupplicantEventCallback(const SupplicantEventCallback &callback);

    /**
     * @Description Unregister event callback
     *
     * @return WifiErrorNo
     */
    WifiErrorNo ReqUnRegisterSupplicantEventCallback();

    /**
     * @Description Initiate PNO scanning.
     *
     * @param scanParam
     * @return WifiErrorNo
     */
    WifiErrorNo ReqStartPnoScan(const WifiPnoScanParam &scanParam);

    /**
     * @Description Stop PNO Scanning.
     *
     * @return WifiErrorNo
     */
    WifiErrorNo ReqStopPnoScan(void);

    /**
     * @Description Query scan results.
     *
     * @return WifiErrorNo
     */
    WifiErrorNo QueryScanInfos(std::vector<InterScanInfo> &scanInfos);

    /**
     * @Description Obtain connection signaling information.
     *
     * @return WifiErrorNo
     */
    WifiErrorNo ReqGetConnectSignalInfo(const std::string &endBssid, WifiWpaSignalInfo &info) const;

    /**
     * @Description set power save mode
     *
     * @return WifiErrorNo
     */
    WifiErrorNo ReqSetPmMode(int frequency, int mode);

    /**
     * @Description set data packet identification mark rule
     *
     * @return WifiErrorNo
     */
    WifiErrorNo ReqSetDpiMarkRule(int uid, int protocol, int enable);

    /**
     * @Description get chipset category
     *
     * @return WifiErrorNo
     */
    WifiErrorNo ReqGetChipsetCategory(int& chipsetCategory) const;

    /**
     * @Description get chipset feature capability
     *
     * @return WifiErrorNo
     */
    WifiErrorNo ReqGetChipsetWifiFeatrureCapability(int& chipsetFeatrureCapability) const;

    /* ************************ softAp Interface ************************** */
    /**
     * @Description Start Ap.
     *
     * @return WifiErrorNo
     */
    WifiErrorNo StartAp(int id = 0);

    /**
     * @Description Close Ap.
     *
     * @return WifiErrorNo
     */
    WifiErrorNo StopAp(int id = 0);

    /**
     * @Description Obtains the hotspot frequency supported by a specified frequency band.
     *
     * @param band
     * @param frequencies
     * @return WifiErrorNo
     */
    WifiErrorNo GetFrequenciesByBand(int32_t band, std::vector<int> &frequencies, int id);

    /**
     * @Description Request set the power mode.
     *
     * @param mode - The mode to set.
     * @return WifiErrorNo
     */
    WifiErrorNo ReqSetPowerModel(const int& model, int id = 0);

    /**
     * @Description Request get the power mode.
     *
     * @param mode - The mode of power.
     * @return WifiErrorNo
     */
    WifiErrorNo ReqGetPowerModel(int& model, int id = 0);

    /**
     * @Description Sets the Wi-Fi country code.
     *
     * @param code
     * @return WifiErrorNo
     */
    WifiErrorNo SetWifiCountryCode(const std::string &code, int id = 0);

    /* ************************ Common Interface ************************** */
    /**
     * @Description Set MAC address.
     *
     * @return WifiErrorNo
     */
    WifiErrorNo SetConnectMacAddr(const std::string &mac, const int portType);

    /**
     * @Description Req updown network interface.
     *
     * @return WifiErrorNo
     */
    WifiErrorNo ReqUpDownNetworkInterface(const std::string &ifaceName, bool upDown);
private:
    char **ConVectorToCArrayString(const std::vector<std::string> &vec) const;
    WifiErrorNo ConvertPnoScanParam(const WifiPnoScanParam &param, PnoScanSettings *pSettings) const;
};
}  // namespace Wifi
}  // namespace OHOS
#endif
#endif