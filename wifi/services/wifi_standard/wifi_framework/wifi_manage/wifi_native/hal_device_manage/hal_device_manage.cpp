/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#ifdef HDI_CHIP_INTERFACE_SUPPORT

#include <unistd.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include "hal_device_manage.h"
#include "wifi_log.h"
#include "wifi_sta_hal_interface.h"
#include "wifi_p2p_hal_interface.h"
#include "wifi_ap_hal_interface.h"
#include "wifi_supplicant_hal_interface.h"
#include "servmgr_hdi.h"
#include "hdf_remote_service.h"
#include "wifi_config_center.h"
#include "wifi_hisysevent.h"

#undef LOG_TAG
#define LOG_TAG "HalDeviceManager"

namespace OHOS {
namespace Wifi {
constexpr const char *CHIP_SERVICE_NAME = "chip_interface_service";
std::atomic_bool HalDeviceManager::g_chipHdiServiceDied = false;
std::mutex HalDeviceManager::mMutex;
static HdfRemoteService *g_chipHdiService = nullptr;
static RssiReportCallback g_rssiReportCallback = nullptr;
static NetlinkReportCallback g_netlinkReportCallback = nullptr;
std::map<std::pair<std::string, IfaceType>, InterfaceCacheEntry> HalDeviceManager::mInterfaceInfoCache;
std::map<std::string, sptr<IChipIface>> HalDeviceManager::mIWifiStaIfaces;
std::map<std::string, sptr<IChipIface>> HalDeviceManager::mIWifiApIfaces;
std::map<std::string, sptr<IChipIface>> HalDeviceManager::mIWifiP2pIfaces;
sptr<IChipController> HalDeviceManager::g_IWifi = nullptr;
sptr<ChipControllerCallback> HalDeviceManager::g_chipControllerCallback = nullptr;
sptr<ChipIfaceCallback> HalDeviceManager::g_chipIfaceCallback = nullptr;
OnChipServiceDied HalDeviceManager::g_chipHdiServiceDiedCb = nullptr;
constexpr int32_t CMD_SET_MAX_CONNECT = 102;
constexpr int32_t MAX_CONNECT_DEFAULT = 8;
constexpr int32_t CMD_SET_P2P_HIGH_PERF = 103;

HalDeviceManager::HalDeviceManager()
{
    LOGI("HalDeviceManager::HalDeviceManager");
    mInterfaceInfoCache.clear();
    mIWifiStaIfaces.clear();
    mIWifiApIfaces.clear();
    mIWifiP2pIfaces.clear();
}

HalDeviceManager::~HalDeviceManager()
{
    LOGI("HalDeviceManager::~HalDeviceManager");
#ifndef __UT__
    StopChipHdi();
#endif
    ResetHalDeviceManagerInfo(false);
}

HalDeviceManager &HalDeviceManager::GetInstance()
{
    static HalDeviceManager instance;
    return instance;
}

bool HalDeviceManager::StartChipHdi()
{
    std::lock_guard<std::mutex> lock(mMutex);
    LOGI("StartChipHdi start...");
    if (g_IWifi != nullptr) {
        bool isInit = false;
        g_IWifi->IsInit(isInit);
        if (isInit) {
            LOGI("has start");
            return true;
        }
    }
    g_IWifi = IChipController::Get(CHIP_SERVICE_NAME, false);
    CHECK_NULL_AND_RETURN(g_IWifi, false);

    if (g_chipControllerCallback == nullptr) {
        g_chipControllerCallback = new (std::nothrow) ChipControllerCallback();
    }
    CHECK_NULL_AND_RETURN(g_chipControllerCallback, false);
    int32_t ret = g_IWifi->RegisterWifiEventCallback(g_chipControllerCallback);
    if (ret != HDF_SUCCESS) {
        LOGE("StartChipHdi, call RegisterWifiEventCallback failed! ret:%{public}d", ret);
        return false;
    }

    if (g_chipIfaceCallback == nullptr) {
        g_chipIfaceCallback = new (std::nothrow) ChipIfaceCallback();
    }

    AddChipHdiDeathRecipient();

    ret = g_IWifi->Init();
    if (ret != HDF_SUCCESS) {
        LOGE("StartChipHdi, call Init failed! ret:%{public}d", ret);
        return false;
    }
    LOGI("StartChipHdi success...");
    return true;
}

void HalDeviceManager::StopChipHdi()
{
    std::lock_guard<std::mutex> lock(mMutex);
    LOGI("StopChipHdi start...");
    CHECK_NULL_AND_RETURN_NULL(g_IWifi);
    int32_t ret = g_IWifi->Release();
    if (ret != HDF_SUCCESS) {
        LOGE("StopChipHdi, call Release failed! ret:%{public}d", ret);
        return;
    }
    LOGI("StopChipHdi success...");
    return;
}

bool HalDeviceManager::CreateStaIface(const IfaceDestoryCallback &ifaceDestoryCallback,
                                      const RssiReportCallback &rssiReportCallback,
                                      const NetlinkReportCallback &netlinkReportCallback, std::string &ifaceName,
                                      int instId)
{
    LOGI("CreateStaIface, ifaceName: %{public}s, instId = %{public}d", ifaceName.c_str(), instId);
    if (!CheckReloadChipHdiService()) {
        LOGE("CreateStaIface CheckReloadChipHdiService failed");
        return false;
    }

    std::lock_guard<std::mutex> lock(mMutex);
    sptr<IChipIface> iface = nullptr;
    if (!CreateIface(IfaceType::STA, ifaceDestoryCallback, ifaceName, iface)) {
        LOGE("CreateStaIface failed");
        return false;
    }

    CHECK_NULL_AND_RETURN(iface, false);
    CHECK_NULL_AND_RETURN(g_chipIfaceCallback, false);
    if (instId == INSTID_WLAN0) {
        int32_t ret = iface->RegisterChipIfaceCallBack(g_chipIfaceCallback);
        if (ret != HDF_SUCCESS) {
            LOGE("CreateStaIface, call RegisterChipIfaceCallBack failed! ret:%{public}d", ret);
            return false;
        }
        g_rssiReportCallback = rssiReportCallback;
        g_netlinkReportCallback = netlinkReportCallback;
    } else {
        LOGE("CreateStaIface wlan1 skip scan callback instId = %{public}d", instId);
    }
    
    mIWifiStaIfaces[ifaceName] = iface;
    LOGI("CreateStaIface success! ifaceName:%{public}s", ifaceName.c_str());
    return true;
}

bool HalDeviceManager::CreateApIface(const IfaceDestoryCallback &ifaceDestoryCallback, std::string &ifaceName)
{
    if (!CheckReloadChipHdiService()) {
        return false;
    }

    std::lock_guard<std::mutex> lock(mMutex);
    sptr<IChipIface> iface = nullptr;
    if (!CreateIface(IfaceType::AP, ifaceDestoryCallback, ifaceName, iface)) {
        LOGE("CreateApIface failed");
        return false;
    }

    mIWifiApIfaces[ifaceName] = iface;
    LOGI("CreateApIface success! ifaceName:%{public}s", ifaceName.c_str());
    return true;
}

bool HalDeviceManager::CreateP2pIface(const IfaceDestoryCallback &ifaceDestoryCallback, std::string &ifaceName)
{
    if (!CheckReloadChipHdiService()) {
        return false;
    }

    std::lock_guard<std::mutex> lock(mMutex);
    sptr<IChipIface> iface = nullptr;
    if (!CreateIface(IfaceType::P2P, ifaceDestoryCallback, ifaceName, iface)) {
        LOGE("CreateP2pIface failed");
        return false;
    }

    mIWifiP2pIfaces[ifaceName] = iface;
    LOGI("CreateP2pIface success! ifaceName:%{public}s", ifaceName.c_str());
    return true;
}

bool HalDeviceManager::RemoveStaIface(const std::string &ifaceName)
{
    if (!CheckReloadChipHdiService()) {
        return false;
    }

    std::lock_guard<std::mutex> lock(mMutex);
    LOGI("RemoveStaIface, ifaceName:%{public}s", ifaceName.c_str());
    auto iter = mIWifiStaIfaces.find(ifaceName);
    if (iter == mIWifiStaIfaces.end()) {
        LOGE("RemoveStaIface, not find iface info");
        return false;
    }

    if (!RemoveIface(iter->second, false, IfaceType::STA)) {
        LOGE("RemoveStaIface, remove iface failed");
        return false;
    }

    LOGI("RemoveStaIface success");
    return true;
}

bool HalDeviceManager::RemoveApIface(const std::string &ifaceName)
{
    if (!CheckReloadChipHdiService()) {
        return false;
    }

    std::lock_guard<std::mutex> lock(mMutex);
    LOGI("RemoveApIface, ifaceName:%{public}s", ifaceName.c_str());
    auto iter = mIWifiApIfaces.find(ifaceName);
    if (iter == mIWifiApIfaces.end()) {
        LOGE("RemoveApIface, not find iface info");
        return false;
    }

    if (!RemoveIface(iter->second, false, IfaceType::AP)) {
        LOGE("RemoveApIface, remove iface failed");
        return false;
    }

    LOGI("RemoveApIface success");
    return true;
}

bool HalDeviceManager::RemoveP2pIface(const std::string &ifaceName)
{
    if (!CheckReloadChipHdiService()) {
        return false;
    }

    std::lock_guard<std::mutex> lock(mMutex);
    LOGI("RemoveP2pIface, ifaceName:%{public}s", ifaceName.c_str());
    auto iter = mIWifiP2pIfaces.find(ifaceName);
    if (iter == mIWifiP2pIfaces.end()) {
        LOGE("RemoveP2pIface, not find iface info");
        return false;
    }

    if (!RemoveIface(iter->second, false, IfaceType::P2P)) {
        LOGE("RemoveP2pIface, remove iface failed");
        return false;
    }

    LOGI("RemoveP2pIface success");
    return true;
}

bool HalDeviceManager::Scan(const std::string &ifaceName, const ScanParams &scanParams)
{
    if (!CheckReloadChipHdiService()) {
        WriteWifiScanApiFailHiSysEvent("HAL_SCAN", WifiScanFailReason::HDI_SERVICE_DIED);
        return false;
    }

    std::lock_guard<std::mutex> lock(mMutex);
    LOGD("Scan, ifaceName:%{public}s", ifaceName.c_str());
    auto iter = mIWifiStaIfaces.find(ifaceName);
    if (iter == mIWifiStaIfaces.end()) {
        LOGE("Scan, not find iface info");
        return false;
    }

    sptr<IChipIface> &iface = iter->second;
    CHECK_NULL_AND_RETURN(iface, false);
    int32_t ret = iface->StartScan(scanParams);
    if (ret != HDF_SUCCESS) {
        LOGE("Scan, call StartScan failed! ret:%{public}d", ret);
        WriteWifiScanApiFailHiSysEvent("HAL_SCAN", WifiScanFailReason::HDI_SCAN_FAIL);
        return false;
    }

    LOGI("Scan success");
    return true;
}

bool HalDeviceManager::StartPnoScan(const std::string &ifaceName, const PnoScanParams &scanParams)
{
    if (!CheckReloadChipHdiService()) {
        WriteWifiScanApiFailHiSysEvent("HAL_PNO_SCAN", WifiScanFailReason::HDI_SERVICE_DIED);
        return false;
    }

    std::lock_guard<std::mutex> lock(mMutex);
    LOGI("StartPnoScan, ifaceName:%{public}s", ifaceName.c_str());
    auto iter = mIWifiStaIfaces.find(ifaceName);
    if (iter == mIWifiStaIfaces.end()) {
        LOGE("StartPnoScan, not find iface info");
        return false;
    }

    sptr<IChipIface> &iface = iter->second;
    CHECK_NULL_AND_RETURN(iface, false);
    int32_t ret = iface->StartPnoScan(scanParams);
    if (ret != HDF_SUCCESS) {
        LOGE("StartPnoScan, call StartPnoScan failed! ret:%{public}d", ret);
        WriteWifiScanApiFailHiSysEvent("HAL_PNO_SCAN", WifiScanFailReason::HDI_PNO_SCAN_FAIL);
        return false;
    }

    LOGI("StartPnoScan success");
    return true;
}

bool HalDeviceManager::StopPnoScan(const std::string &ifaceName)
{
    if (!CheckReloadChipHdiService()) {
        WriteWifiScanApiFailHiSysEvent("HAL_PNO_SCAN", WifiScanFailReason::HDI_SERVICE_DIED);
        return false;
    }

    std::lock_guard<std::mutex> lock(mMutex);
    LOGI("StopPnoScan, ifaceName:%{public}s", ifaceName.c_str());
    auto iter = mIWifiStaIfaces.find(ifaceName);
    if (iter == mIWifiStaIfaces.end()) {
        LOGE("StopPnoScan, not find iface info");
        return false;
    }

    sptr<IChipIface> &iface = iter->second;
    CHECK_NULL_AND_RETURN(iface, false);
    int32_t ret = iface->StopPnoScan();
    if (ret != HDF_SUCCESS) {
        LOGE("StopPnoScan, call StopPnoScan failed! ret:%{public}d", ret);
        return false;
    }

    LOGI("StopPnoScan success");
    return true;
}

bool HalDeviceManager::GetScanInfos(const std::string &ifaceName, std::vector<ScanResultsInfo> &scanResultsInfo)
{
    if (!CheckReloadChipHdiService()) {
        WriteWifiScanApiFailHiSysEvent("HAL_GET_SCAN_INFOS", WifiScanFailReason::HDI_SERVICE_DIED);
        return false;
    }

    std::lock_guard<std::mutex> lock(mMutex);
    LOGD("GetScanInfos, ifaceName:%{public}s", ifaceName.c_str());
    auto iter = mIWifiStaIfaces.find(ifaceName);
    if (iter == mIWifiStaIfaces.end()) {
        LOGE("GetScanInfos, not find iface info");
        return false;
    }

    sptr<IChipIface> &iface = iter->second;
    CHECK_NULL_AND_RETURN(iface, false);
    int32_t ret = iface->GetScanInfos(scanResultsInfo);
    if (ret != HDF_SUCCESS) {
        LOGE("GetScanInfos, call GetScanInfos failed! ret:%{public}d", ret);
        WriteWifiScanApiFailHiSysEvent("HAL_GET_SCAN_INFOS", WifiScanFailReason::HDI_GET_SCAN_INFOS_FAIL);
        return false;
    }

    LOGI("GetScanInfos success, scan info size:%{public}d", static_cast<int>(scanResultsInfo.size()));
    return true;   
}

bool HalDeviceManager::GetConnectSignalInfo(const std::string &ifaceName, SignalPollResult &signalPollResult)
{
    if (!CheckReloadChipHdiService()) {
        return false;
    }

    std::lock_guard<std::mutex> lock(mMutex);
    LOGD("GetConnectSignalInfo, ifaceName:%{public}s", ifaceName.c_str());
    auto iter = mIWifiStaIfaces.find(ifaceName);
    if (iter == mIWifiStaIfaces.end()) {
        LOGE("GetConnectSignalInfo, not find iface info");
        return false;
    }

    sptr<IChipIface> &iface = iter->second;
    CHECK_NULL_AND_RETURN(iface, false);
    int32_t ret = iface->GetSignalPollInfo(signalPollResult);
    if (ret != HDF_SUCCESS) {
        LOGE("GetConnectSignalInfo, call GetSignalPollInfo failed! ret:%{public}d", ret);
        return false;
    }

    LOGD("GetConnectSignalInfo success");
    return true;
}

bool HalDeviceManager::SetPmMode(const std::string &ifaceName, int mode)
{
    if (!CheckReloadChipHdiService()) {
        return false;
    }

    std::lock_guard<std::mutex> lock(mMutex);
    LOGI("SetPmMode, ifaceName:%{public}s, mode:%{public}d", ifaceName.c_str(), mode);
    auto iter = mIWifiStaIfaces.find(ifaceName);
    if (iter == mIWifiStaIfaces.end()) {
        LOGE("SetPmMode, not find iface info");
        return false;
    }

    sptr<IChipIface> &iface = iter->second;
    CHECK_NULL_AND_RETURN(iface, false);
    int32_t ret = iface->EnablePowerMode(mode);
    if (ret != HDF_SUCCESS) {
        LOGE("SetPmMode, call EnablePowerMode failed! ret:%{public}d", ret);
        return false;
    }

    LOGI("SetPmMode success");
    return true;
}

bool HalDeviceManager::SetDpiMarkRule(const std::string &ifaceName, int uid, int protocol, int enable)
{
    if (!CheckReloadChipHdiService()) {
        return false;
    }

    std::lock_guard<std::mutex> lock(mMutex);
    LOGI("SetDpiMarkRule, ifaceName:%{public}s, uid:%{public}d, protocol:%{public}d, enable:%{public}d",
        ifaceName.c_str(), uid, protocol, enable);
    auto iter = mIWifiStaIfaces.find(ifaceName);
    if (iter == mIWifiStaIfaces.end()) {
        LOGE("SetDpiMarkRule, not find iface info");
        return false;
    }

    sptr<IChipIface> &iface = iter->second;
    CHECK_NULL_AND_RETURN(iface, false);
    int32_t ret = iface->SetDpiMarkRule(uid, protocol, enable);
    if (ret != HDF_SUCCESS) {
        LOGE("SetDpiMarkRule, call SetDpiMarkRule failed! ret:%{public}d", ret);
        return false;
    }

    LOGI("SetDpiMarkRule success");
    return true;
}

bool HalDeviceManager::SetStaMacAddress(const std::string &ifaceName, const std::string &mac)
{
    if (!CheckReloadChipHdiService()) {
        return false;
    }

    std::lock_guard<std::mutex> lock(mMutex);
    LOGI("SetStaMacAddress, ifaceName:%{public}s", ifaceName.c_str());
    auto iter = mIWifiStaIfaces.find(ifaceName);
    if (iter == mIWifiStaIfaces.end()) {
        LOGE("SetStaMacAddress, not find iface info");
        return false;
    }

    sptr<IChipIface> &iface = iter->second;
    CHECK_NULL_AND_RETURN(iface, false);
    if (iface->SetIfaceState(false) != HDF_SUCCESS) {
        LOGE("SetStaMacAddress, set network down fail");
        return false;
    }
    int32_t ret = iface->SetMacAddress(mac);
    if (ret != HDF_SUCCESS) {
        LOGE("SetStaMacAddress, call SetMacAddress failed! ret:%{public}d", ret);
    }
    if (iface->SetIfaceState(true) != HDF_SUCCESS) {
        LOGE("SetStaMacAddress, set network up fail");
        return false;
    }

    LOGI("SetStaMacAddress success");
    return true;
}

IChipIface *HalDeviceManager::FindIface(const std::string &ifaceName)
{
    if (ifaceName.empty()) {
        LOGE("find iface is empty");
        return nullptr;
    }
    auto iter = mIWifiStaIfaces.find(ifaceName);
    if (iter != mIWifiStaIfaces.end()) {
        LOGE("find sta iface info");
        return iter->second;
    }
    iter = mIWifiApIfaces.find(ifaceName);
    if (iter != mIWifiApIfaces.end()) {
        LOGE("find ap iface info");
        return iter->second;
    }
    iter = mIWifiP2pIfaces.find(ifaceName);
    if (iter != mIWifiP2pIfaces.end()) {
        LOGE("find p2p iface info");
        return iter->second;
    }
    return nullptr;
}

bool HalDeviceManager::SetNetworkUpDown(const std::string &ifaceName, bool upDown)
{
    std::lock_guard<std::mutex> lock(mMutex);
    IChipIface *iface = FindIface(ifaceName);
    if (iface == nullptr) {
        return false;
    }
    if (iface->SetIfaceState(upDown) != HDF_SUCCESS) {
        return false;
    }
    return true;
}

bool HalDeviceManager::GetChipsetCategory(const std::string &ifaceName, uint32_t &chipsetCategory)
{
    if (!CheckReloadChipHdiService()) {
        return false;
    }

    std::lock_guard<std::mutex> lock(mMutex);
    LOGD("GetChipsetCategory, ifaceName:%{public}s", ifaceName.c_str());
    sptr<IConcreteChip> chip = nullptr;
    if (!GetChip(ifaceName, IfaceType::STA, chip)) {
        LOGE("GetChipsetCategory, get chip failed");
        return false;
    }

    CHECK_NULL_AND_RETURN(chip, false);
    int32_t ret = chip->GetChipCaps(chipsetCategory);
    if (ret != HDF_SUCCESS) {
        LOGE("GetChipsetCategory, call GetChipCaps failed! ret:%{public}d", ret);
        return false;
    }
    LOGD("GetChipsetCategory success");
    return true;
}

bool HalDeviceManager::GetChipsetWifiFeatrureCapability(const std::string &ifaceName, int &chipsetFeatrureCapability)
{
    if (!CheckReloadChipHdiService()) {
        return false;
    }

    std::lock_guard<std::mutex> lock(mMutex);
    LOGI("GetChipsetWifiFeatrureCapability, ifaceName:%{public}s", ifaceName.c_str());
    auto iter = mIWifiStaIfaces.find(ifaceName);
    if (iter == mIWifiStaIfaces.end()) {
        LOGE("GetChipsetWifiFeatrureCapability, not find iface info");
        return false;
    }

    sptr<IChipIface> &iface = iter->second;
    CHECK_NULL_AND_RETURN(iface, false);
    uint32_t capabilities = 0;
    int32_t ret = iface->GetIfaceCap(capabilities);
    if (ret != HDF_SUCCESS) {
        LOGE("GetChipsetWifiFeatrureCapability, call GetIfaceCap failed! ret:%{public}d", ret);
        return false;
    }
    chipsetFeatrureCapability = capabilities;
    LOGI("GetChipsetWifiFeatrureCapability success");
    return true;
}

bool HalDeviceManager::GetFrequenciesByBand(const std::string &ifaceName, int32_t band, std::vector<int> &frequencies)
{
    if (!CheckReloadChipHdiService()) {
        return false;
    }

    std::lock_guard<std::mutex> lock(mMutex);
    LOGI("GetFrequenciesByBand, ifaceName:%{public}s, band:%{public}d", ifaceName.c_str(), band);
    auto iter = FindIface(ifaceName);
    if (iter != nullptr) {
        std::vector<uint32_t> uifrequencies;
        int32_t ret = iter->GetSupportFreqs(band, uifrequencies);
        if (ret != HDF_SUCCESS) {
            LOGE("GetFrequenciesByBand, call GetSupportFreqs failed! ret:%{public}d", ret);
            return false;
        }
        for (auto item : uifrequencies) {
            frequencies.emplace_back(item);
        }
        return true;
    }
    LOGI("GetFrequenciesByBand failed");
    return false;
}

bool HalDeviceManager::SetPowerModel(const std::string &ifaceName, int model)
{
    if (!CheckReloadChipHdiService()) {
        return false;
    }

    std::lock_guard<std::mutex> lock(mMutex);
    LOGI("SetPowerModel, ifaceName:%{public}s, model:%{public}d", ifaceName.c_str(), model);
    auto iter = mIWifiApIfaces.find(ifaceName);
    if (iter == mIWifiApIfaces.end()) {
        LOGE("SetPowerModel, not find iface info");
        return false;
    }

    sptr<IChipIface> &iface = iter->second;
    CHECK_NULL_AND_RETURN(iface, false);
    int32_t ret = iface->SetPowerMode(model);
    if (ret != HDF_SUCCESS) {
        LOGE("SetPowerModel, call SetPowerMode failed! ret:%{public}d", ret);
        return false;
    }

    LOGI("SetPowerModel success");
    return true;
}

bool HalDeviceManager::SetTxPower(int power)
{
    if (!CheckReloadChipHdiService()) {
        return false;
    }

    std::lock_guard<std::mutex> lock(mMutex);
    int32_t staResult = IfaceSetTxPower(WifiConfigCenter::GetInstance().GetStaIfaceName(),
                                        mIWifiStaIfaces, power);
    int32_t p2pResult = IfaceSetTxPower(WifiConfigCenter::GetInstance().GetP2pIfaceName(),
                                        mIWifiP2pIfaces, power);
    int32_t apResult = IfaceSetTxPower(WifiConfigCenter::GetInstance().GetApIfaceName(),
                                       mIWifiApIfaces, power);
    LOGI("SetTxPower, result:sta:%{public}d, p2p:%{public}d, ap:%{public}d",
        staResult, p2pResult, apResult);
    if (staResult == HDF_SUCCESS || p2pResult == HDF_SUCCESS || apResult == HDF_SUCCESS) {
        LOGE("SetTxPower success");
        return true;
    }
    return false;
}

int32_t HalDeviceManager::IfaceSetTxPower(
    const std::string &ifaceName, const std::map<std::string, sptr<IChipIface>> &mWifiIfaces, int power)
{
    int32_t result = HDF_FAILURE;
    auto iter = mWifiIfaces.find(ifaceName);
    if (iter != mWifiIfaces.end()) {
        const sptr<IChipIface> &iface = iter->second;
        CHECK_NULL_AND_RETURN(iface, false);
        int32_t result = iface->SetTxPower(power);
        if (result != HDF_SUCCESS) {
            LOGE("SetTxPower, call SetTxPower failed! Result:%{public}d", result);
        }
        return result;
    }
    LOGI("can not find iface:%{public}s", ifaceName.c_str());
    return result;
}
bool HalDeviceManager::GetPowerModel(const std::string &ifaceName, int &model)
{
    if (!CheckReloadChipHdiService()) {
        return false;
    }

    std::lock_guard<std::mutex> lock(mMutex);
    LOGI("GetPowerModel, ifaceName:%{public}s", ifaceName.c_str());
    auto iter = mIWifiApIfaces.find(ifaceName);
    if (iter == mIWifiApIfaces.end()) {
        LOGE("GetPowerModel, not find iface info");
        return false;
    }

    sptr<IChipIface> &iface = iter->second;
    CHECK_NULL_AND_RETURN(iface, false);
    int32_t ret = iface->GetPowerMode(model);
    if (ret != HDF_SUCCESS) {
        LOGE("GetPowerModel, call GetPowerMode failed! ret:%{public}d", ret);
        return false;
    }

    LOGI("GetPowerModel success");
    return true;
}

bool HalDeviceManager::SetWifiCountryCode(const std::string &ifaceName, const std::string &code)
{
    if (!CheckReloadChipHdiService()) {
        return false;
    }

    std::lock_guard<std::mutex> lock(mMutex);
    LOGI("SetWifiCountryCode, ifaceName:%{public}s", ifaceName.c_str());
    auto staIter = mIWifiStaIfaces.find(ifaceName);
    if (staIter != mIWifiStaIfaces.end()) {
        sptr<IChipIface> &iface = staIter->second;
        CHECK_NULL_AND_RETURN(iface, false);
        int32_t ret = iface->SetCountryCode(code);
        if (ret != HDF_SUCCESS) {
            LOGE("SetWifiCountryCode, call SetCountryCode failed! ret:%{public}d", ret);
            return false;
        }
        LOGI("Sta setWifiCountryCode success");
        return true;
    }

    auto apIter = mIWifiApIfaces.find(ifaceName);
    if (apIter != mIWifiApIfaces.end()) {
        sptr<IChipIface> &iface = apIter->second;
        CHECK_NULL_AND_RETURN(iface, false);
        int32_t ret = iface->SetCountryCode(code);
        if (ret != HDF_SUCCESS) {
            LOGE("SetWifiCountryCode, call SetCountryCode failed! ret:%{public}d", ret);
            return false;
        }
        LOGI("Ap setWifiCountryCode success");
        return true;
    }
    LOGE("SetWifiCountryCode, not find iface info");
    return false;
}

bool HalDeviceManager::SetApMacAddress(const std::string &ifaceName, const std::string &mac)
{
    if (!CheckReloadChipHdiService()) {
        return false;
    }

    std::lock_guard<std::mutex> lock(mMutex);
    LOGI("SetApMacAddress, ifaceName:%{public}s", ifaceName.c_str());
    auto iter = mIWifiApIfaces.find(ifaceName);
    if (iter == mIWifiApIfaces.end()) {
        LOGE("SetApMacAddress, not find iface info");
        return false;
    }

    sptr<IChipIface> &iface = iter->second;
    CHECK_NULL_AND_RETURN(iface, false);
    if (iface->SetIfaceState(false) != HDF_SUCCESS) {
        LOGE("SetStaMacAddress, set network down fail");
        return false;
    }
    int32_t ret = iface->SetMacAddress(mac);
    if (ret != HDF_SUCCESS) {
        LOGE("SetApMacAddress, call SetMacAddress failed! ret:%{public}d", ret);
    }
    if (iface->SetIfaceState(true) != HDF_SUCCESS) {
        LOGE("SetStaMacAddress, set network up fail");
        return false;
    }
    LOGI("SetApMacAddress success");
    return true;
}

bool HalDeviceManager::SendCmdToDriver(const std::string &ifaceName, const std::string &interfaceName,
    int cmd, const std::string &param, std::string &result)
{
    if (!CheckReloadChipHdiService()) {
        return false;
    }
    std::lock_guard<std::mutex> lock(mMutex);
    LOGI("SendCmdToDriver, ifaceName:%{public}s, cmd:%{public}d", ifaceName.c_str(), cmd);
    sptr<IChipIface> iface = nullptr;
    if (auto iter = mIWifiP2pIfaces.find(ifaceName); iter != mIWifiP2pIfaces.end()) {
        iface = iter->second;
    } else if (auto iter = mIWifiApIfaces.find(ifaceName); iter != mIWifiApIfaces.end()) {
        iface = iter->second;
    } else {
        LOGE("SendCmdToDriver, not find iface info");
        return false;
    }
    CHECK_NULL_AND_RETURN(iface, false);

    std::vector<int8_t> paramBuf;
    for (auto c : param) {
        int8_t cc = c;
        paramBuf.push_back(cc);
    }
    std::vector<int8_t> resultBuf;
    int32_t ret = iface->SendCmdToDriver(interfaceName, cmd, paramBuf, resultBuf);
    if (ret != HDF_SUCCESS) {
        LOGE("SendCmdToDriver, call SendCmdToDriver failed! ret:%{public}d", ret);
    }
    if (!resultBuf.empty()) {
        result.assign(resultBuf.begin(), resultBuf.end());
    }
    LOGI("SendCmdToDriver success");
    return true;
}

std::string HalDeviceManager::MakeMacFilterString(const std::vector<std::string> &blockList)
{
    if (blockList.empty()) {
        return "MAC_MODE=0,MAC_CNT=0";
    }
    int macCount = static_cast<int>(blockList.size());
    std::string macs = "MAC_MODE=1,MAC_CNT=" + std::to_string(macCount);
    for (auto mac : blockList) {
        mac.erase(std::remove(mac.begin(), mac.end(), ':'), mac.end());
        macs.append(",MAC=").append(mac);
    }
    return macs;
}

bool HalDeviceManager::SetBlockList(const std::string &ifaceName, const std::string &interfaceName,
    const std::vector<std::string> &blockList)
{
    const int setMacFilterCmd = 100;
    std::string macFilterStr = MakeMacFilterString(blockList);
    std::string result;
    return SendCmdToDriver(ifaceName, interfaceName, setMacFilterCmd, macFilterStr, result);
}

bool HalDeviceManager::DisAssociateSta(const std::string &ifaceName, const std::string &interfaceName,
    std::string mac)
{
    const int disAssociateStaCmd = 101;
    mac.erase(std::remove(mac.begin(), mac.end(), ':'), mac.end());
    std::string result;
    return SendCmdToDriver(ifaceName, interfaceName, disAssociateStaCmd, mac, result);
}

bool HalDeviceManager::SetMaxConnectNum(const std::string &ifaceName, int32_t channel, int32_t maxConn)
{
    if (maxConn > MAX_CONNECT_DEFAULT) {
        LOGW("SetMaxConnectNum maxConn is over MAX_CONNECT_DEFAULT, maxConn is %{public}d", maxConn);
        maxConn = MAX_CONNECT_DEFAULT;
    }
    std::string param = std::to_string(channel) + '.' + std::to_string(maxConn);
    LOGI("SetMaxConnectNum param is %{public}s", param.c_str());
    std::string result;
    return SendCmdToDriver(ifaceName, ifaceName, CMD_SET_MAX_CONNECT, param, result);
}

bool HalDeviceManager::SetP2pHighPerf(const std::string &ifaceName, bool isEnable)
{
    std::string param = std::to_string(static_cast<int>(isEnable));
    LOGI("SetP2pHighPerf param is %{public}s", param.c_str());
    std::string result;
    return SendCmdToDriver(ifaceName, ifaceName, CMD_SET_P2P_HIGH_PERF, param, result);
}

void HalDeviceManager::ResetHalDeviceManagerInfo(bool isRemoteDied)
{
    std::lock_guard<std::mutex> lock(mMutex);
    if (isRemoteDied) {
        WifiP2PHalInterface::GetInstance().StopP2p();
        WifiStaHalInterface::GetInstance().StopWifi();
        WifiApHalInterface::GetInstance().StopAp();
    }
    if (!g_chipControllerCallback) {
        g_chipControllerCallback = nullptr;
    }
    if (!g_chipIfaceCallback) {
        g_chipIfaceCallback = nullptr;
    }
    if (!g_IWifi) {
        g_IWifi = nullptr;
    }
    mInterfaceInfoCache.clear();
    mIWifiStaIfaces.clear();
    mIWifiApIfaces.clear();
    mIWifiP2pIfaces.clear();
    if (g_chipHdiServiceDiedCb && isRemoteDied) {
        g_chipHdiServiceDiedCb();
    }
    return;
}

bool HalDeviceManager::CheckReloadChipHdiService()
{
    if (!g_chipHdiServiceDied) {
        if (!CheckChipHdiStarted()) {
            LOGE("chip hdi is not started");
            return false;
        }
        return true;
    }

    if (!StartChipHdi()) {
        LOGE("reload chip hdi service failed");
        return false;
    }

    g_chipHdiServiceDied = false;
    LOGI("reload chip hdi service success");
    return true;
}

bool HalDeviceManager::CheckChipHdiStarted()
{
    std::lock_guard<std::mutex> lock(mMutex);
    bool isStarted = false;
    CHECK_NULL_AND_RETURN(g_IWifi, false);
    int32_t ret = g_IWifi->IsInit(isStarted);
    if (ret != HDF_SUCCESS) {
        LOGE("CheckChipHdiStarted, call IsInit failed! ret:%{public}d", ret);
        return false;
    }

    LOGD("CheckChipHdiStarted, isStarted:%{public}d", isStarted);
    if (!isStarted) {
        ret = g_IWifi->Init();
        if (ret != HDF_SUCCESS) {
            LOGE("CheckChipHdiStarted, call Init failed! ret:%{public}d", ret);
            return false;
        }
    }
    return true;
}

bool HalDeviceManager::GetIfaceName(sptr<IChipIface> &iface, std::string &ifaceName)
{
    CHECK_NULL_AND_RETURN(iface, false);
    int32_t ret = iface->GetIfaceName(ifaceName);
    if (ret != HDF_SUCCESS) {
        LOGE("GetIfaceName, call GetIfaceName failed! ret:%{public}d", ret);
        return false;
    }

    LOGI("GetIfaceName, ifaceName:%{public}s", ifaceName.c_str());
    return true;
}

bool HalDeviceManager::GetIfaceType(sptr<IChipIface> &iface, IfaceType &ifaceType)
{
    CHECK_NULL_AND_RETURN(iface, false);
    int32_t ret = iface->GetIfaceType(ifaceType);
    if (ret != HDF_SUCCESS) {
        LOGE("GetIfaceType, call GetIfaceType failed! ret:%{public}d", ret);
        return false;
    }

    LOGI("GetIfaceType, ifaceType:%{public}d", static_cast<int>(ifaceType));
    return true;
}

void HalDeviceManager::GetP2pIfaceInfo(WifiChipInfo &wifiChipInfo)
{
    CHECK_NULL_AND_RETURN_NULL(wifiChipInfo.chip);
    WifiIfaceInfo wifiIfaceInfo;
    std::vector<std::string> ifnames;
    std::vector<WifiIfaceInfo> ifaceInfo;

    int32_t ret = wifiChipInfo.chip->GetP2pServiceIfNames(ifnames);
    if (ret == HDF_SUCCESS) {
        for (uint32_t i = 0; i < ifnames.size(); ++i) {
            wifiIfaceInfo.Clear();
            ret = wifiChipInfo.chip->GetP2pService(ifnames[i], wifiIfaceInfo.iface);
            if (ret != HDF_SUCCESS) {
                LOGE("GetIfaceType, call GetP2pService failed! ret:%{public}d", ret);
                break;
            }
            wifiIfaceInfo.name = ifnames[i];
            ifaceInfo.emplace_back(wifiIfaceInfo);
        }
    } else {
        LOGE("GetIfaceType, call GetP2pServiceIfNames failed! ret:%{public}d", ret);
    }
    wifiChipInfo.ifaces[IfaceType::P2P] = ifaceInfo;
    return;
}

void HalDeviceManager::GetApIfaceInfo(WifiChipInfo &wifiChipInfo)
{
    CHECK_NULL_AND_RETURN_NULL(wifiChipInfo.chip);
    WifiIfaceInfo wifiIfaceInfo;
    std::vector<std::string> ifnames;
    std::vector<WifiIfaceInfo> ifaceInfo;

    int32_t ret = wifiChipInfo.chip->GetApServiceIfNames(ifnames);
    if (ret == HDF_SUCCESS) {
        for (uint32_t i = 0; i < ifnames.size(); ++i) {
            wifiIfaceInfo.Clear();
            ret = wifiChipInfo.chip->GetApService(ifnames[i], wifiIfaceInfo.iface);
            if (ret != HDF_SUCCESS) {
                LOGE("GetApIfaceInfo, call GetApService failed! ret:%{public}d", ret);
                break;
            }
            wifiIfaceInfo.name = ifnames[i];
            ifaceInfo.emplace_back(wifiIfaceInfo);
        }
    } else {
        LOGE("GetApIfaceInfo, call GetApServiceIfNames failed! ret:%{public}d", ret);
    }
    wifiChipInfo.ifaces[IfaceType::AP] = ifaceInfo;
    return;
}

void HalDeviceManager::GetStaIfaceInfo(WifiChipInfo &wifiChipInfo)
{
    CHECK_NULL_AND_RETURN_NULL(wifiChipInfo.chip);
    WifiIfaceInfo wifiIfaceInfo;
    std::vector<std::string> ifnames;
    std::vector<WifiIfaceInfo> ifaceInfo;

    int32_t ret = wifiChipInfo.chip->GetStaServiceIfNames(ifnames);
    if (ret == HDF_SUCCESS) {
        for (uint32_t i = 0; i < ifnames.size(); ++i) {
            wifiIfaceInfo.Clear();
            ret = wifiChipInfo.chip->GetStaService(ifnames[i], wifiIfaceInfo.iface);
            if (ret != HDF_SUCCESS) {
                LOGE("GetStaIfaceInfo, call GetStaService failed! ret:%{public}d", ret);
                break;
            }
            wifiIfaceInfo.name = ifnames[i];
            ifaceInfo.emplace_back(wifiIfaceInfo);
        }
    } else {
        LOGE("GetStaIfaceInfo, call GetStaServiceIfNames failed! ret:%{public}d", ret);
    }
    wifiChipInfo.ifaces[IfaceType::STA] = ifaceInfo;
    return;
}

bool HalDeviceManager::GetIfaceInfo(WifiChipInfo &wifiChipInfo)
{
    GetStaIfaceInfo(wifiChipInfo);
    GetApIfaceInfo(wifiChipInfo);
    GetP2pIfaceInfo(wifiChipInfo);
    return true;
}

bool HalDeviceManager::GetChipInfo(uint32_t chipId, WifiChipInfo &wifiChipInfo)
{
    CHECK_NULL_AND_RETURN(g_IWifi, false);
    int32_t ret = g_IWifi->GetChipService(chipId, wifiChipInfo.chip);
    if (ret != HDF_SUCCESS) {
        LOGE("GetChipInfo, call GetChipService failed! ret:%{public}d", ret);
        return false;
    }

    CHECK_NULL_AND_RETURN(wifiChipInfo.chip, false);
    ret = wifiChipInfo.chip->GetChipModes(wifiChipInfo.availableModes);
    if (ret != HDF_SUCCESS) {
        LOGE("GetChipInfo, call GetChipModes failed! ret:%{public}d", ret);
        return false;
    }

    ret = wifiChipInfo.chip->GetCurrentMode(wifiChipInfo.currentModeId);
    if (ret == HDF_SUCCESS) {
        LOGI("GetChipInfo, GetCurrentMode:%{public}d", wifiChipInfo.currentModeId);
        wifiChipInfo.currentModeIdValid = true;
    } else if (ret == HDF_ERR_INVALID_PARAM) {
        LOGI("GetChipInfo, currentModeId not available");
    } else {
        LOGE("GetChipInfo, call GetCurrentMode failed! ret:%{public}d", ret);
        return false;
    }

    if (!GetIfaceInfo(wifiChipInfo)) {
        LOGE("GetChipInfo, GetIfaceInfo failed!");
        return false;
    }

    return true;
}

bool HalDeviceManager::GetAllChipInfo(std::vector<WifiChipInfo> &wifiChipInfos)
{
    LOGI("GetAllChipInfo start");
    std::vector<uint32_t> chipIds;
    CHECK_NULL_AND_RETURN(g_IWifi, false);
    int32_t ret = g_IWifi->GetAvailableChips(chipIds);
    if (ret != HDF_SUCCESS) {
        LOGE("GetAllChipInfo, call GetAvailableChips failed! ret:%{public}d", ret);
        return false;
    }

    if (chipIds.empty()) {
        LOGE("GetAllChipInfo, chipIds is empty!");
        return false;
    }

    for (uint32_t i = 0; i < chipIds.size(); ++i) {
        WifiChipInfo wifiChipInfo;
        if (GetChipInfo(chipIds[i], wifiChipInfo)) {
            wifiChipInfo.chipId = chipIds[i];
            wifiChipInfos.emplace_back(wifiChipInfo);
        }
    }

    LOGI("GetAllChipInfo end");
    return true;
}

bool HalDeviceManager::ValidateInterfaceCache(std::vector<WifiChipInfo> &wifiChipInfos)
{
    if (mInterfaceInfoCache.empty()) {
        LOGI("ValidateInterfaceCache, mInterfaceInfoCache is empty!");
        return true;
    }

    for (auto &interfaceInfo : mInterfaceInfoCache) {
        WifiChipInfo matchingChipInfo;
        for (auto &chipInfo : wifiChipInfos) {
            if (chipInfo.chipId == interfaceInfo.second.chipId) {
                matchingChipInfo = chipInfo;
                break;
            }
        }

        if (matchingChipInfo.chip == nullptr) {
            LOGE("ValidateInterfaceCache, chipInfo not found!");
            return false;
        }

        std::vector<WifiIfaceInfo> &ifaceInfos = matchingChipInfo.ifaces[interfaceInfo.second.type];
        if (ifaceInfos.empty()) {
            LOGE("ValidateInterfaceCache, invalid type!");
            return false;
        }

        bool matchFound = false;
        for (auto &ifaceInfo : ifaceInfos) {
            if (ifaceInfo.name == interfaceInfo.second.name) {
                matchFound = true;
                break;
            }
        }

        if (!matchFound) {
            LOGE("ValidateInterfaceCache, ifaceInfo not found!");
            return false;
        }
    }

    LOGI("ValidateInterfaceCache, verify ok!");
    return true;
}

void HalDeviceManager::SelectInterfacesToDelete(int excessInterfaces, IfaceType requestedIfaceType,
    IfaceType existingIfaceType, std::vector<WifiIfaceInfo> &existingIface,
    std::vector<WifiIfaceInfo> &interfacesToBeRemovedFirst)
{
    bool lookupError = false;
    std::vector<WifiIfaceInfo> ifacesToDelete;
    for (int i = existingIface.size() - 1; i >= 0; i--) {
        WifiIfaceInfo info = existingIface[i];
        IfaceType ifaceType = IFACE_TYPE_DEFAULT;
        GetIfaceType(info.iface, ifaceType);
        auto iter = mInterfaceInfoCache.find(std::pair<std::string, IfaceType>(info.name, ifaceType));
        if (iter == mInterfaceInfoCache.end()) {
            LOGE("SelectInterfacesToDelete, can't find cache interface info! info name:%{public}s", info.name.c_str());
            lookupError = true;
            break;
        }

        if (AllowedToBeDeleteIfaceTypeForRequestedType(requestedIfaceType, existingIfaceType)) {
            ifacesToDelete.emplace_back(info);
        }
    }

    if (lookupError) {
        LOGE("SelectInterfacesToDelete, falling back to arbitrary selection");
        for (int i = 0; i < excessInterfaces; ++i) {
            interfacesToBeRemovedFirst.emplace_back(existingIface[i]);
        }
    } else {
        int numIfacesToDelete = std::min(excessInterfaces, static_cast<int>(ifacesToDelete.size()));
        for (int i = 0; i < numIfacesToDelete; ++i) {
            interfacesToBeRemovedFirst.emplace_back(ifacesToDelete[i]);
        }
    }

    return;
}

bool HalDeviceManager::AllowedToBeDeleteIfaceTypeForRequestedType(IfaceType requestedIfaceType,
    IfaceType existingIfaceType)
{
    LOGI("AllowedToBeDeleteIfaceTypeForRequestedType, requestedIfaceType:%{public}d, existingIfaceType:%{public}d",
        requestedIfaceType, existingIfaceType);
    if (requestedIfaceType == existingIfaceType) {
        LOGI("AllowedToBeDeleteIfaceTypeForRequestedType, not allowed to delete");
        return false;
    }

    LOGI("AllowedToBeDeleteIfaceTypeForRequestedType, allowed to delete");
    return true;
}

bool HalDeviceManager::CreateTheNeedChangeChipModeIfaceData(WifiChipInfo &wifiChipInfo, IfaceType createIfaceType,
    UsableMode &chipMode, IfaceCreationData &ifaceCreationData)
{
    for (auto type : IFACE_TYPES_BY_PRIORITY) {
        if (!wifiChipInfo.ifaces[type].empty()) {
            if (!AllowedToBeDeleteIfaceTypeForRequestedType(createIfaceType, type)) {
                LOGE("CreateTheNeedChangeChipModeIfaceData, chip mode need change, not allowed to delete");
                return false;
            }
        }
    }
    
    ifaceCreationData.chipInfo = wifiChipInfo;
    ifaceCreationData.chipModeId = chipMode.modeId;
    LOGI("CreateTheNeedChangeChipModeIfaceData, chip mode need change, create a new iface data");
    return true;
}

bool HalDeviceManager::CanIfaceComboSupportRequest(WifiChipInfo &wifiChipInfo, UsableMode &chipMode,
    std::vector<int> &chipIfaceCombo, IfaceType createIfaceType, IfaceCreationData &ifaceCreationData)
{
    if (chipIfaceCombo[createIfaceType] == 0) {
        LOGE("CanIfaceComboSupportRequest, request type not support by combo");
        return false;
    }

    bool isChipModeChangeProposed = wifiChipInfo.currentModeIdValid && wifiChipInfo.currentModeId != chipMode.modeId;
    if (isChipModeChangeProposed) {
        return CreateTheNeedChangeChipModeIfaceData(wifiChipInfo, createIfaceType, chipMode, ifaceCreationData);
    }

    for (auto type : IFACE_TYPES_BY_PRIORITY) {
        int tooManyInterfaces = static_cast<int>(wifiChipInfo.ifaces[type].size()) - chipIfaceCombo[type];
        if (createIfaceType == type) {
            tooManyInterfaces += 1;
        }

        if (tooManyInterfaces > 0) {
            if (wifiChipInfo.ifaces[type].empty()) {
                LOGE("CanIfaceComboSupportRequest, existing ifaces is empty");
                return false;
            }

            if (!AllowedToBeDeleteIfaceTypeForRequestedType(createIfaceType, type)) {
                LOGE("CanIfaceComboSupportRequest, not allowed to delete");
                return false;
            }

            SelectInterfacesToDelete(tooManyInterfaces, createIfaceType, type, wifiChipInfo.ifaces[type],
                ifaceCreationData.interfacesToBeRemovedFirst);
        }
    }

    ifaceCreationData.chipInfo = wifiChipInfo;
    ifaceCreationData.chipModeId = chipMode.modeId;
    LOGI("CanIfaceComboSupportRequest, create a new iface data");
    return true;
}

void HalDeviceManager::ExpandIfaceCombos(ComboIface &chipIfaceCombo,
    std::vector<std::vector<int>> &expandedIfaceCombos)
{
    int numOfCombos = 1;
    for (auto &limit : chipIfaceCombo.limits) {
        for (uint32_t i = 0; i < limit.ifaceNum; ++i) {
            numOfCombos *= limit.types.size();
        }
    }

    expandedIfaceCombos.resize(numOfCombos);
    for (uint32_t i = 0; i < expandedIfaceCombos.size(); ++i) {
        expandedIfaceCombos[i].resize(IFACE_TYPES_BY_PRIORITY.size(), 0);
    }

    int span = numOfCombos;
    for (auto &limit : chipIfaceCombo.limits) {
        for (uint32_t i = 0; i < limit.ifaceNum; ++i) {
            span /= limit.types.size();
            for (int k = 0; k < numOfCombos; ++k) {
                int ifaceType = limit.types.at((k / span) % limit.types.size());
                expandedIfaceCombos[k][ifaceType]++;
            }
        }
    }

    return;
}

bool HalDeviceManager::CompareIfaceCreationData(IfaceCreationData &data1, IfaceCreationData &data2)
{
    if (data1.isEmpty()) {
        return false;
    } else if (data2.isEmpty()) {
        return true;
    }

    for (auto type : IFACE_TYPES_BY_PRIORITY) {
        int numIfacesToDelete1 = 0;
        if (data1.chipInfo.currentModeIdValid && data1.chipInfo.currentModeId != data1.chipModeId) {
            numIfacesToDelete1 = data1.chipInfo.ifaces[type].size();
        } else {
            numIfacesToDelete1 = data1.interfacesToBeRemovedFirst.size();
        }

        int numIfacesToDelete2 = 0;
        if (data2.chipInfo.currentModeIdValid && data2.chipInfo.currentModeId != data2.chipModeId) {
            numIfacesToDelete2 = data2.chipInfo.ifaces[type].size();
        } else {
            numIfacesToDelete2 = data2.interfacesToBeRemovedFirst.size();
        }

        if (numIfacesToDelete1 < numIfacesToDelete2) {
            LOGI("CompareIfaceCreationData, data1 < data2");
            return true;
        }
    }

    return false;
}

bool HalDeviceManager::ExecuteChipReconfiguration(IfaceCreationData &ifaceCreationData,
    IfaceType createIfaceType, sptr<IChipIface> &iface)
{
    if (ifaceCreationData.chipInfo.chip == nullptr) {
        LOGE("ExecuteChipReconfiguration, chip is nullptr");
        return false;
    }

    bool isModeConfigNeeded = !ifaceCreationData.chipInfo.currentModeIdValid
        || ifaceCreationData.chipInfo.currentModeId != ifaceCreationData.chipModeId;
    if (isModeConfigNeeded) {
        for (auto &ifaceInfos : ifaceCreationData.chipInfo.ifaces) {
            for (auto &ifaceInfo : ifaceInfos.second) {
                RemoveIface(ifaceInfo.iface, true, createIfaceType);
            }
        }

        int32_t ret = ifaceCreationData.chipInfo.chip->SetChipMode(ifaceCreationData.chipModeId);
        if (ret != HDF_SUCCESS) {
            LOGE("ExecuteChipReconfiguration, call SetChipMode failed! ret:%{public}d", ret);
            return false;
        }
    } else {
        for (auto &ifaceInfo : ifaceCreationData.interfacesToBeRemovedFirst) {
            RemoveIface(ifaceInfo.iface, true, createIfaceType);
        }
    }

    int32_t ret = HDF_FAILURE;
    switch (createIfaceType) {
        case IfaceType::STA :
            ret = ifaceCreationData.chipInfo.chip->CreateStaService(iface);
            break;
        case IfaceType::AP :
            ret = ifaceCreationData.chipInfo.chip->CreateApService(iface);
            break;
        case IfaceType::P2P :
            ret = ifaceCreationData.chipInfo.chip->CreateP2pService(iface);
            break;
        default:
            LOGE("ExecuteChipReconfiguration, invalid createIfaceType:%{public}d", static_cast<int>(createIfaceType));
            break;
    }

    if (ret != HDF_SUCCESS) {
        LOGE("ExecuteChipReconfiguration, create iface failed! ret:%{public}d, createIfaceType:%{public}d",
            ret, static_cast<int>(createIfaceType));
        return false;
    }

    return true;
}

void HalDeviceManager::FindBestIfaceCreationProposal(std::vector<std::vector<int>> &expandedIfaceCombos,
    WifiChipInfo &chipInfo, UsableMode &chipMode, IfaceType createIfaceType,
    IfaceCreationData &bestIfaceCreationProposal)
{
    for (auto &expandedIfaceCombo : expandedIfaceCombos) {
        IfaceCreationData currentProposal;
        CanIfaceComboSupportRequest(chipInfo, chipMode, expandedIfaceCombo, createIfaceType, currentProposal);
        if (CompareIfaceCreationData(currentProposal, bestIfaceCreationProposal)) {
            bestIfaceCreationProposal = currentProposal;
        }
    }
    return;
}

bool HalDeviceManager::CreateIfaceIfPossible(std::vector<WifiChipInfo> &wifiChipInfos, IfaceType createIfaceType,
    const IfaceDestoryCallback &ifaceDestoryCallback, std::string &ifaceName, sptr<IChipIface> &iface)
{
    IfaceCreationData bestIfaceCreationProposal;
    for (auto &chipInfo : wifiChipInfos) {
        for (auto &chipMode : chipInfo.availableModes) {
            for (auto &chipIfaceCombo : chipMode.usableCombo) {
                std::vector<std::vector<int>> expandedIfaceCombos;
                ExpandIfaceCombos(chipIfaceCombo, expandedIfaceCombos);
                FindBestIfaceCreationProposal(expandedIfaceCombos, chipInfo, chipMode, createIfaceType,
                    bestIfaceCreationProposal);
            }
        }
    }

    if (bestIfaceCreationProposal.isEmpty()) {
        LOGE("CreateIfaceIfPossible, best iface creation data is empty");
        return false;
    }

    if (!ExecuteChipReconfiguration(bestIfaceCreationProposal, createIfaceType, iface)) {
        LOGE("CreateIfaceIfPossible, excute chip reconfiguration failed");
        return false;
    }

    if (!GetIfaceName(iface, ifaceName)) {
        LOGE("CreateIfaceIfPossible, get iface name failed");
        return false;
    }

    InterfaceCacheEntry cacheEntry;
    cacheEntry.chip = bestIfaceCreationProposal.chipInfo.chip;
    cacheEntry.chipId = bestIfaceCreationProposal.chipInfo.chipId;
    cacheEntry.name = ifaceName;
    cacheEntry.type = createIfaceType;
    cacheEntry.ifaceDestoryCallback.emplace_back(ifaceDestoryCallback);
    mInterfaceInfoCache[std::pair<std::string, IfaceType>(cacheEntry.name, cacheEntry.type)] = cacheEntry;
    return true;
}

bool HalDeviceManager::CreateIface(IfaceType createIfaceType, const IfaceDestoryCallback &ifaceDestoryCallback,
    std::string &ifaceName, sptr<IChipIface> &iface)
{
    std::vector<WifiChipInfo> wifiChipInfos;
    if (!GetAllChipInfo(wifiChipInfos)) {
        LOGE("CreateIface, get all chip info failed");
        return false;
    }

    if (!ValidateInterfaceCache(wifiChipInfos)) {
        LOGE("CreateIface, verify interface cache failed");
        return false;
    }

    if (!CreateIfaceIfPossible(wifiChipInfos, createIfaceType, ifaceDestoryCallback, ifaceName, iface)) {
        LOGE("CreateIface, create iface failed");
        return false;
    }

    LOGI("CreateIface, create iface success, ifaceName:%{public}s", ifaceName.c_str());
    return true;
}

void HalDeviceManager::DispatchIfaceDestoryCallback(std::string &removeIfaceName, IfaceType removeIfaceType,
    bool isCallback, IfaceType createIfaceType)
{
    LOGI("DispatchIfaceDestoryCallback, removeIfaceName:%{public}s, removeIfaceType:%{public}d, isCallback:%{public}d,"
        " createIfaceType:%{public}d", removeIfaceName.c_str(), removeIfaceType, isCallback, createIfaceType);
    switch (removeIfaceType) {
        case IfaceType::STA :
            if (mIWifiStaIfaces.find(removeIfaceName) != mIWifiStaIfaces.end()) {
                mIWifiStaIfaces.erase(removeIfaceName);
            }
            if (isCallback) {
                WifiP2PHalInterface::GetInstance().StopP2p();
                WifiStaHalInterface::GetInstance().StopWifi();
            }
            break;
        case IfaceType::AP :
            if (mIWifiApIfaces.find(removeIfaceName) != mIWifiApIfaces.end()) {
                mIWifiApIfaces.erase(removeIfaceName);
            }
            if (isCallback) {
                WifiApHalInterface::GetInstance().StopAp();
            }
            break;
        case IfaceType::P2P :
            if (mIWifiP2pIfaces.find(removeIfaceName) != mIWifiP2pIfaces.end()) {
                mIWifiP2pIfaces.erase(removeIfaceName);
            }
            break;
        default:
            LOGE("DispatchIfaceDestoryCallback, invalid removeIfaceType:%{public}d", static_cast<int>(removeIfaceType));
            break;
    }

    auto iter = mInterfaceInfoCache.find(std::pair<std::string, IfaceType>(removeIfaceName, removeIfaceType));
    if (iter != mInterfaceInfoCache.end()) {
        for (auto &callback : iter->second.ifaceDestoryCallback) {
            if (isCallback && callback) {
                callback(removeIfaceName, static_cast<int>(createIfaceType));
            }
        }
        mInterfaceInfoCache.erase(iter);
    }

    return;
}

bool HalDeviceManager::GetChip(const std::string &removeIfaceName, IfaceType removeIfaceType, sptr<IConcreteChip> &chip)
{
    auto iter = mInterfaceInfoCache.find(std::pair<std::string, IfaceType>(removeIfaceName, removeIfaceType));
    if (iter == mInterfaceInfoCache.end()) {
        LOGE("GetChip, not find interface cache info");
        return false;
    }

    chip = iter->second.chip;
    return true;
}

bool HalDeviceManager::RemoveIface(sptr<IChipIface> &iface, bool isCallback, IfaceType createIfaceType)
{
    std::string ifaceName;
    if (!GetIfaceName(iface, ifaceName)) {
        LOGE("RemoveIface, get iface name failed");
        return false;
    }

    IfaceType ifaceType = IFACE_TYPE_DEFAULT;
    if (!GetIfaceType(iface, ifaceType)) {
        LOGI("RemoveIface, get iface type failed");
        return false;
    }

    sptr<IConcreteChip> chip = nullptr;
    if (!GetChip(ifaceName, ifaceType, chip)) {
        LOGE("RemoveIface, get chip failed");
        return false;
    }

    CHECK_NULL_AND_RETURN(chip, false);
    int32_t ret = HDF_FAILURE;
    switch (ifaceType) {
        case IfaceType::STA:
            if (ifaceName == "wlan0") {
                LOGE("RemoveIface, IfaceType::STA wlan0");
                if (iface && g_chipIfaceCallback) {
                    iface->UnRegisterChipIfaceCallBack(g_chipIfaceCallback);
                }
                g_rssiReportCallback = nullptr;
                g_netlinkReportCallback = nullptr;
            }
            ret = chip->RemoveStaService(ifaceName);
            break;
        case IfaceType::AP :
            ret = chip->RemoveApService(ifaceName);
            break;
        case IfaceType::P2P :
            ret = chip->RemoveP2pService(ifaceName);
            break;
        default:
            LOGE("RemoveIface, invalid ifaceType:%{public}d", static_cast<int>(ifaceType));
            break;
    }

    if (ret != HDF_SUCCESS) {
        LOGE("RemoveIface, remove iface failed ret:%{public}d, ifaceType:%{public}d", ret, static_cast<int>(ifaceType));
        return false;
    }

    DispatchIfaceDestoryCallback(ifaceName, ifaceType, isCallback, createIfaceType);
    LOGI("RemoveIface success");
    return true;
}

void HalDeviceManager::AddChipHdiDeathRecipient()
{
    struct HDIServiceManager *serviceMgr = HDIServiceManagerGet();
    if (serviceMgr == nullptr) {
        LOGE("%{public}s: failed to get HDIServiceManager", __func__);
        return;
    }

    g_chipHdiService = serviceMgr->GetService(serviceMgr, CHIP_SERVICE_NAME);
    HDIServiceManagerRelease(serviceMgr);
    if (g_chipHdiService == nullptr) {
        LOGE("%{public}s: failed to get HdfRemoteService", __func__);
        return;
    }

    static HdfDeathRecipient recipient = {
        .OnRemoteDied = [](HdfDeathRecipient *recipient, HdfRemoteService *service) {
            LOGI("Chip Hdi service died!");
            g_chipHdiServiceDied = true;
            ResetHalDeviceManagerInfo(true);
            RemoveChipHdiDeathRecipient();
            LOGI("Chip Hdi service died process success!");
            return;
        }
    };

    HdfRemoteServiceAddDeathRecipient(g_chipHdiService, &recipient);
    LOGI("Chip Hdi service add death recipient success");
    return;
}

void HalDeviceManager::RemoveChipHdiDeathRecipient()
{
    std::lock_guard<std::mutex> lock(mMutex);
    if (g_chipHdiService) {
        HdfRemoteServiceRemoveDeathRecipient(g_chipHdiService, nullptr);
        g_chipHdiService = nullptr;
    }
    return;
}

void HalDeviceManager::RegisterChipHdiDeathCallback(OnChipServiceDied cb)
{
    std::lock_guard<std::mutex> lock(mMutex);
    g_chipHdiServiceDiedCb = cb;
}

int32_t ChipIfaceCallback::OnScanResultsCallback(uint32_t event)
{
    LOGD("OnScanResultsCallback, event:%{public}d", event);
    OHOS::Wifi::WifiSupplicantHalInterface::GetInstance().NotifyScanResultEvent(event);
    return 0;
}

int32_t ChipIfaceCallback::OnRssiReport(int32_t index, int32_t c0Rssi, int32_t c1Rssi)
{
    LOGI("OnRssiReport, index:%{public}d c0Rssi:%{public}d c1Rssi:%{public}d", index, c0Rssi, c1Rssi);

    if (g_rssiReportCallback) {
        g_rssiReportCallback(index, c0Rssi);
    }
    return 0;
}

int32_t ChipIfaceCallback::OnWifiNetlinkMessage(uint32_t type, const std::vector<uint8_t>& recvMsg)
{
    LOGI("OnWifiNetlinkMessage, type:%{public}d", type);

    if (g_netlinkReportCallback) {
        g_netlinkReportCallback(type, recvMsg);
    }
    return 0;
}

}  // namespace Wifi
}  // namespace OHOS
#endif