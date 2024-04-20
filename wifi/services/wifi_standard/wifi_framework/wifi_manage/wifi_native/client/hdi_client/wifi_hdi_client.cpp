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
#include "wifi_hdi_client.h"
#include "wifi_hdi_common.h"
#include "wifi_idl_define.h"
#include "wifi_hdi_sta_impl.h"
#include "wifi_hdi_ap_impl.h"
#include "wifi_hdi_callback.h"
#include "wifi_hdi_proxy.h"
#include "wifi_log.h"
#include "securec.h"

#undef LOG_TAG
#define LOG_TAG "WifiHdiClient"

namespace OHOS {
namespace Wifi {
/* ************************ Sta Interface ************************** */
WifiErrorNo WifiHdiClient::StartWifi(const std::string &ifaceName)
{
    return HdiWifiStart(ifaceName.c_str());
}

WifiErrorNo WifiHdiClient::StopWifi()
{
    return HdiWifiStop();
}

WifiErrorNo WifiHdiClient::Scan(const WifiScanParam &scanParam)
{
    ScanSettings settings;
    if (memset_s(&settings, sizeof(settings), 0, sizeof(settings)) != EOK) {
        LOGE("%{public}s: failed to memset", __func__);
        return WIFI_IDL_OPT_FAILED;
    }
    LOGI("enter to %{public}s", __func__);
    bool bfail = false;
    do {
        if (scanParam.hiddenNetworkSsid.size() > 0) {
            LOGI("%{public}s begin to save ssid", __func__);
            settings.hiddenSsidSize = scanParam.hiddenNetworkSsid.size();
            settings.hiddenSsid = ConVectorToCArrayString(scanParam.hiddenNetworkSsid);
            if (settings.hiddenSsid == nullptr) {
                bfail = true;
                break;
            }
        }
        if (scanParam.scanFreqs.size() > 0) {
            LOGI("%{public}s begin to save freqs", __func__);
            settings.freqSize = scanParam.scanFreqs.size();
            settings.freqs = (int *)calloc(settings.freqSize, sizeof(int));
            if (settings.freqs == nullptr) {
                bfail = true;
                break;
            }
            for (int i = 0; i < settings.freqSize; ++i) {
                settings.freqs[i] = scanParam.scanFreqs[i];
            }
        }
        if (scanParam.scanStyle > 0) {
            LOGI("%{public}s begin to save scanStyle:%{public}d", __func__, scanParam.scanStyle);
            settings.scanStyle = scanParam.scanStyle;
        }
    } while (0);
    LOGI("%{public}s: bfail is %{public}d", __func__, bfail);
    WifiErrorNo err = WIFI_IDL_OPT_FAILED;
    if (!bfail) {
        err = HdiWifiStartScan(&settings);
    }
    if (settings.freqs != nullptr) {
        free(settings.freqs);
        settings.freqs = nullptr;
    }
    if (settings.hiddenSsid != nullptr) {
        for (int i = 0; i < settings.hiddenSsidSize; ++i) {
            free(settings.hiddenSsid[i]);
            settings.hiddenSsid[i] = nullptr;
        }
        free(settings.hiddenSsid);
        settings.hiddenSsid = nullptr;
    }
    return err;
}

WifiErrorNo WifiHdiClient::ReqRegisterSupplicantEventCallback(const SupplicantEventCallback &callback)
{
    ISupplicantEventCallback cEventCallback;
    if (memset_s(&cEventCallback, sizeof(cEventCallback), 0, sizeof(cEventCallback)) != EOK) {
        LOGE("%{public}s: failed to memset", __func__);
        return WIFI_IDL_OPT_FAILED;
    }
    if (callback.onScanNotify != nullptr) {
        cEventCallback.onScanNotify = OnEventScanNotify;
    }
    HdiSetSupplicantEventCallback(cEventCallback);
    return WIFI_IDL_OPT_OK;
}

WifiErrorNo WifiHdiClient::ReqUnRegisterSupplicantEventCallback()
{
    HdiUnRegisterStaCallbackEvent();
    return WIFI_IDL_OPT_OK;
}

WifiErrorNo WifiHdiClient::ReqStartPnoScan(const WifiPnoScanParam &scanParam)
{
    PnoScanSettings settings;
    if (memset_s(&settings, sizeof(settings), 0, sizeof(settings)) != EOK) {
        LOGE("%{public}s: failed to memset", __func__);
        return WIFI_IDL_OPT_FAILED;
    }
    WifiErrorNo err = ConvertPnoScanParam(scanParam, &settings);
    if (err == WIFI_IDL_OPT_OK) {
        err = HdiWifiStartPnoScan(&settings);
    }
    if (settings.freqs != nullptr) {
        free(settings.freqs);
        settings.freqs = nullptr;
    }
    if (settings.hiddenSsid != nullptr) {
        for (int i = 0; i < settings.hiddenSsidSize; ++i) {
            free(settings.hiddenSsid[i]);
            settings.hiddenSsid[i] = nullptr;
        }
        free(settings.hiddenSsid);
        settings.hiddenSsid = nullptr;
    }
    if (settings.savedSsid != nullptr) {
        for (int i = 0; i < settings.savedSsidSize; ++i) {
            free(settings.savedSsid[i]);
            settings.savedSsid[i] = nullptr;
        }
        free(settings.savedSsid);
        settings.savedSsid = nullptr;
    }
    return err;
}

WifiErrorNo WifiHdiClient::ReqStopPnoScan(void)
{
    return HdiWifiStopPnoScan();
}

WifiErrorNo WifiHdiClient::QueryScanInfos(std::vector<InterScanInfo> &scanInfos)
{
    int size = HDI_GET_MAX_SCAN_INFO;
    ScanInfo results[HDI_GET_MAX_SCAN_INFO];
    if (memset_s(results, sizeof(results), 0, sizeof(results)) != EOK) {
        LOGE("%{public}s: failed to memset", __func__);
        return WIFI_IDL_OPT_FAILED;
    }

    WifiErrorNo  ret = HdiWifiGetScanInfos(results, &size);
    if (ret == WIFI_IDL_OPT_FAILED) {
        return size == 0 ? WIFI_IDL_OPT_OK : WIFI_IDL_OPT_FAILED;
    }
    for (int i = 0; i < size; ++i) {
        InterScanInfo tmp;
        tmp.ssid = results[i].ssid;
        tmp.bssid = results[i].bssid;
        tmp.frequency = results[i].freq;
        tmp.rssi = results[i].siglv;
        tmp.timestamp = results[i].timestamp;
        tmp.capabilities = results[i].flags;
        tmp.channelWidth = (WifiChannelWidth)results[i].channelWidth;
        tmp.centerFrequency0 = results[i].centerFrequency0;
        tmp.centerFrequency1 = results[i].centerFrequency1;
        tmp.isVhtInfoExist = results[i].isVhtInfoExist;
        tmp.isHtInfoExist = results[i].isHtInfoExist;
        tmp.isHeInfoExist = results[i].isHeInfoExist;
        tmp.isErpExist = results[i].isErpExist;
        tmp.maxRates = results[i].maxRates > results[i].extMaxRates ? results[i].maxRates : results[i].extMaxRates;

        for (int j = 0; j < results[i].ieSize; ++j) {
            WifiInfoElem infoElemTmp;
            int infoElemSize = results[i].infoElems[j].size;
            infoElemTmp.id = results[i].infoElems[j].id;
            for (int k = 0; k < infoElemSize; ++k) {
                infoElemTmp.content.emplace_back(results[i].infoElems[j].content[k]);
            }
            if (results[i].infoElems[j].content) {
                free(results[i].infoElems[j].content);
            }
            tmp.infoElems.emplace_back(infoElemTmp);
        }
        if (results[i].infoElems) {
            free(results[i].infoElems);
        }
        tmp.isHiLinkNetwork = results[i].isHiLinkNetwork;
        scanInfos.emplace_back(tmp);
    }
    return WIFI_IDL_OPT_OK;
}

WifiErrorNo WifiHdiClient::ReqGetConnectSignalInfo(const std::string &endBssid, WifiWpaSignalInfo &info) const
{
    WpaSignalInfo req = {0};
    WifiErrorNo err = HdiWifiGetConnectSignalInfo(endBssid.c_str(), &req);
    if (err == WIFI_IDL_OPT_OK) {
        info.signal = req.signal;
        info.txrate = req.txrate;
        info.rxrate = req.rxrate;
        info.noise = req.noise;
        info.frequency = req.frequency;
        info.txPackets = req.txPackets;
        info.rxPackets = req.rxPackets;
        info.snr = req.snr;
        info.chload = req.chload;
        info.ulDelay = req.ulDelay;
        info.txBytes = req.txBytes;
        info.rxBytes = req.rxBytes;
        info.txFailed = req.txFailed;
    }
    return err;
}

WifiErrorNo WifiHdiClient::ReqSetPmMode(int frequency, int mode)
{
    return HdiSetPmMode(frequency, mode);
}

WifiErrorNo WifiHdiClient::ReqSetDpiMarkRule(int uid, int protocol, int enable)
{
    return HdiSetDpiMarkRule(uid, protocol, enable);
}

WifiErrorNo WifiHdiClient::ReqGetChipsetCategory(int& chipsetCategory) const
{
    return HdiGetChipsetCategory(&chipsetCategory);
}

WifiErrorNo WifiHdiClient::ReqGetChipsetWifiFeatrureCapability(int& chipsetFeatrureCapability) const
{
    return HdiGetChipsetWifiFeatrureCapability(&chipsetFeatrureCapability);
}

/* ************************ softAp Interface ************************** */
WifiErrorNo WifiHdiClient::StartAp(int id)
{
    WifiErrorNo ret = WIFI_IDL_OPT_OK;
    ret = StartHdiWifi();
    if (ret != WIFI_IDL_OPT_OK) {
        LOGE("%{public}s: failed to StartHdiWifi", __func__);
        return ret;
    }
    ret = CheckHdiNormalStart(PROTOCOL_80211_IFTYPE_AP);
    if (ret != WIFI_IDL_OPT_OK) {
        LOGE("%{public}s: check hdi abnormal start, failed to start hdi wifi!", __func__);
        return ret;
    }
    return ret;
}

WifiErrorNo WifiHdiClient::StopAp(int id)
{
    if (IsHdiStopped() == WIFI_IDL_OPT_OK) {
        LOGE("%{public}s: HdiAp already stopped", __func__);
        return WIFI_IDL_OPT_OK;
    }
    return HdiStop();
}

WifiErrorNo WifiHdiClient::GetFrequenciesByBand(int32_t band, std::vector<int> &frequencies, int id)
{
    int values[WIFI_IDL_GET_MAX_BANDS] = {0};
    int size = WIFI_IDL_GET_MAX_BANDS;
    if (HdiGetFrequenciesForBand(band, values, &size, id) != 0) {
        LOGI("%{public}s: failed to get frenquency", __func__);
        return WIFI_IDL_OPT_FAILED;
    }
    for (int i = 0; i < size; i++) {
        frequencies.push_back(values[i]);
    }
    return WIFI_IDL_OPT_OK;
}

WifiErrorNo WifiHdiClient::ReqSetPowerModel(const int& model, int id)
{
    return HdiWifiSetPowerModel(model, id);
}

WifiErrorNo WifiHdiClient::ReqGetPowerModel(int& model, int id)
{
    return HdiWifiGetPowerModel(&model, id);
}

WifiErrorNo WifiHdiClient::SetWifiCountryCode(const std::string &code, int id)
{
    if (code.length() != HDI_COUNTRY_CODE_LENGTH) {
        LOGE("%{public}s: invalid code", __func__);
        return WIFI_IDL_OPT_INVALID_PARAM;
    }
    return HdiWifiSetCountryCode(code.c_str(), id);
}

/* ************************ Common Interface ************************** */
WifiErrorNo WifiHdiClient::SetConnectMacAddr(const std::string &mac, const int portType)
{
#ifdef SUPPORT_LOCAL_RANDOM_MAC
    if (CheckMacIsValid((const char *)mac.c_str()) != 0) {
        return WIFI_IDL_OPT_INPUT_MAC_INVALID;
    }
    return HdiSetAssocMacAddr((unsigned char *)mac.c_str(), mac.length(), portType);
#else
    return WIFI_IDL_OPT_OK;
#endif
}

WifiErrorNo WifiHdiClient::ReqUpDownNetworkInterface(const std::string &ifaceName, bool upDown)
{
    LOGI("%{public}s: ifaceName:%{public}s, upDown:%{public}d", __func__, ifaceName.c_str(), upDown);
    UpDownLink(static_cast<int>(upDown), 0, ifaceName.c_str());
    return WIFI_IDL_OPT_OK;
}

char **WifiHdiClient::ConVectorToCArrayString(const std::vector<std::string> &vec) const
{
    int size = vec.size();
    if (size == 0) {
        return nullptr;
    }
    char **list = (char **)calloc(size, sizeof(char *));
    if (list == nullptr) {
        return nullptr;
    }
    int i = 0;
    for (; i < size; ++i) {
        int len = vec[i].length();
        list[i] = (char *)calloc(len + 1, sizeof(char));
        if (list[i] == nullptr) {
            break;
        }
        if (strncpy_s(list[i], len + 1, vec[i].c_str(), len) != EOK) {
            break;
        }
    }
    if (i < size) {
        for (int j = 0; j <= i; ++j) {
            free(list[j]);
        }
        free(list);
        list = nullptr;
        return nullptr;
    } else {
        return list;
    }
}

WifiErrorNo WifiHdiClient::ConvertPnoScanParam(const WifiPnoScanParam &param, PnoScanSettings *pSettings) const
{
    if (param.scanInterval > 0) {
        pSettings->scanInterval = param.scanInterval;
    }
    pSettings->minRssi2Dot4Ghz = param.minRssi2Dot4Ghz;
    pSettings->minRssi5Ghz = param.minRssi5Ghz;
    if (param.hiddenSsid.size() > 0) {
        pSettings->hiddenSsidSize = param.hiddenSsid.size();
        pSettings->hiddenSsid = ConVectorToCArrayString(param.hiddenSsid);
        if (pSettings->hiddenSsid == nullptr) {
            return WIFI_IDL_OPT_FAILED;
        }
    }
    if (param.savedSsid.size() > 0) {
        pSettings->savedSsidSize = param.savedSsid.size();
        pSettings->savedSsid = ConVectorToCArrayString(param.savedSsid);
        if (pSettings->savedSsid == nullptr) {
            return WIFI_IDL_OPT_FAILED;
        }
    }
    if (param.scanFreqs.size() > 0) {
        pSettings->freqSize = param.scanFreqs.size();
        pSettings->freqs = (int *)calloc(pSettings->freqSize, sizeof(int));
        if (pSettings->freqs == nullptr) {
            return WIFI_IDL_OPT_FAILED;
        }
        for (int i = 0; i < pSettings->freqSize; ++i) {
            pSettings->freqs[i] = param.scanFreqs[i];
        }
    }
    return WIFI_IDL_OPT_OK;
}

}  // namespace Wifi
}  // namespace OHOS
#endif