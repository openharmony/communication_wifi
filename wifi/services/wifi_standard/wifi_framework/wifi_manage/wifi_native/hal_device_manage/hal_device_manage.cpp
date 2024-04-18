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

#include "hal_device_manage.h"
#include "wifi_log.h"
#include "wifi_sta_hal_interface.h"
#include "wifi_p2p_hal_interface.h"
#include "wifi_ap_hal_interface.h"
#include "servmgr_hdi.h"
#include "hdf_remote_service.h"

#undef LOG_TAG
#define LOG_TAG "HalDeviceManager"

namespace OHOS {
namespace Wifi {
constexpr const char *CHIP_SERVICE_NAME = "chip_interface_service";
std::atomic_bool HalDeviceManager::g_chipHdiServiceDied = false;
std::mutex HalDeviceManager::mMutex;
static HdfRemoteService *g_chipHdiService = nullptr;

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
    StopChipHdi();
    ResetHalDeviceManagerInfo();
}

bool HalDeviceManager::StartChipHdi()
{
    std::lock_guard<std::mutex> lock(mMutex);
    LOGI("StartChipHdi start...");
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

bool HalDeviceManager::CreateStaIface(const IfaceDestoryCallback &ifaceDestoryCallback, std::string &ifaceName)
{
    if (!CheckReloadChipHdiService()) {
        return false;
    }

    std::lock_guard<std::mutex> lock(mMutex);
    sptr<IChipIface> iface = nullptr;
    if (!CreateIface(IfaceType::STA, ifaceDestoryCallback, ifaceName, iface)) {
        LOGE("CreateStaIface failed");
        return false;
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

bool HalDeviceManager::RemoveStaIface(std::string &ifaceName)
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

bool HalDeviceManager::RemoveApIface(std::string &ifaceName)
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

bool HalDeviceManager::RemoveP2pIface(std::string &ifaceName)
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

void HalDeviceManager::ResetHalDeviceManagerInfo()
{
    std::lock_guard<std::mutex> lock(mMutex);
    g_chipControllerCallback = nullptr;
    g_IWifi = nullptr;
    mInterfaceInfoCache.clear();
    mIWifiStaIfaces.clear();
    mIWifiApIfaces.clear();
    mIWifiP2pIfaces.clear();
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

    ResetHalDeviceManagerInfo();
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

    LOGI("CheckChipHdiStarted, isStarted:%{public}d", isStarted);
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
        for (int i = 0; i < ifnames.size(); ++i) {
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
        for (int i = 0; i < ifnames.size(); ++i) {
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
        for (int i = 0; i < ifnames.size(); ++i) {
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

    for (int i = 0; i < chipIds.size(); ++i) {
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
        int tooManyInterfaces = wifiChipInfo.ifaces[type].size() - chipIfaceCombo[type];
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
        for (int i = 0; i < limit.ifaceNum; ++i) {
            numOfCombos *= limit.types.size();
        }
    }

    expandedIfaceCombos.resize(numOfCombos);
    for (int i = 0; i < expandedIfaceCombos.size(); ++i) {
        expandedIfaceCombos[i].resize(IFACE_TYPES_BY_PRIORITY.size(), 0);
    }

    int span = numOfCombos;
    for (auto &limit : chipIfaceCombo.limits) {
        for (int i = 0; i < limit.ifaceNum; ++i) {
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
            WifiP2PHalInterface::GetInstance().StopP2p();
            WifiStaHalInterface::GetInstance().StopWifi();
            WifiStaHalInterface::GetInstance().StopWifiHdi();
            break;
        case IfaceType::AP :
            if (mIWifiApIfaces.find(removeIfaceName) != mIWifiApIfaces.end()) {
                mIWifiApIfaces.erase(removeIfaceName);
            }
            WifiApHalInterface::GetInstance().StopAp();
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

bool HalDeviceManager::GetChip(std::string &removeIfaceName, IfaceType removeIfaceType, sptr<IConcreteChip> &chip)
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
        LOGE("RemoveIface, get iface type failed");
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
        case IfaceType::STA :
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
            RemoveChipHdiDeathRecipient();
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

}  // namespace Wifi
}  // namespace OHOS
#endif