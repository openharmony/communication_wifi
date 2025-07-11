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

#include "kits/c/wifi_p2p.h"
#include "kits/c/wifi_hid2d.h"
#include "wifi_logger.h"
#include "inner_api/wifi_p2p.h"
#include "wifi_c_utils.h"
#include "wifi_common_util.h"
#include "wifi_sa_event.h"
constexpr int INVALID_VALUE = -1;
#define STR_END '\0'

DEFINE_WIFILOG_LABEL("WifiCP2P");
std::shared_ptr<OHOS::Wifi::WifiP2p> wifiP2pPtr = OHOS::Wifi::WifiP2p::GetInstance(WIFI_P2P_ABILITY_ID);

NO_SANITIZE("cfi") WifiErrorCode EnableP2p()
{
    CHECK_PTR_RETURN(wifiP2pPtr, ERROR_WIFI_NOT_AVAILABLE);
    EventManager::GetInstance().Init();
    return GetCErrorCode(wifiP2pPtr->EnableP2p());
}

NO_SANITIZE("cfi") WifiErrorCode DisableP2p()
{
    CHECK_PTR_RETURN(wifiP2pPtr, ERROR_WIFI_NOT_AVAILABLE);
    return GetCErrorCode(wifiP2pPtr->DisableP2p());
}

NO_SANITIZE("cfi") WifiErrorCode GetP2pEnableStatus(P2pState* state)
{
    CHECK_PTR_RETURN(state, ERROR_WIFI_INVALID_ARGS);
    CHECK_PTR_RETURN(wifiP2pPtr, ERROR_WIFI_NOT_AVAILABLE);

    int p2pEnableStatus = INVALID_VALUE;
    OHOS::Wifi::ErrCode ret = wifiP2pPtr->GetP2pEnableStatus(p2pEnableStatus);
    *state = P2pState(p2pEnableStatus);
    return GetCErrorCode(ret);
}

NO_SANITIZE("cfi") WifiErrorCode DiscoverDevices()
{
    CHECK_PTR_RETURN(wifiP2pPtr, ERROR_WIFI_NOT_AVAILABLE);
    return GetCErrorCode(wifiP2pPtr->DiscoverDevices());
}

NO_SANITIZE("cfi") WifiErrorCode StopDiscoverDevices()
{
    CHECK_PTR_RETURN(wifiP2pPtr, ERROR_WIFI_NOT_AVAILABLE);
    return GetCErrorCode(wifiP2pPtr->StopDiscoverDevices());
}

NO_SANITIZE("cfi") WifiErrorCode DiscoverServices()
{
    CHECK_PTR_RETURN(wifiP2pPtr, ERROR_WIFI_NOT_AVAILABLE);
    return GetCErrorCode(wifiP2pPtr->DiscoverServices());
}

NO_SANITIZE("cfi") WifiErrorCode StopDiscoverServices()
{
    CHECK_PTR_RETURN(wifiP2pPtr, ERROR_WIFI_NOT_AVAILABLE);
    return GetCErrorCode(wifiP2pPtr->StopDiscoverServices());
}

NO_SANITIZE("cfi") WifiErrorCode StartP2pListen(int period, int interval)
{
    CHECK_PTR_RETURN(wifiP2pPtr, ERROR_WIFI_NOT_AVAILABLE);
    return GetCErrorCode(wifiP2pPtr->StartP2pListen(period, interval));
}

NO_SANITIZE("cfi") WifiErrorCode StopP2pListen()
{
    CHECK_PTR_RETURN(wifiP2pPtr, ERROR_WIFI_NOT_AVAILABLE);
    return GetCErrorCode(wifiP2pPtr->StopP2pListen());
}

static void ConvertConfigCToCpp(const WifiP2pConfig* config, OHOS::Wifi::WifiP2pConfig& cppConfig)
{
    CHECK_PTR_RETURN_VOID(config);
    cppConfig.SetDeviceAddress(OHOS::Wifi::MacArrayToStr(config->devAddr));
    cppConfig.SetDeviceAddressType(config->bssidType);
    cppConfig.SetGoBand(OHOS::Wifi::GroupOwnerBand(static_cast<int>(config->goBand)));
    cppConfig.SetNetId(config->netId);
    cppConfig.SetPassphrase(config->passphrase);
    cppConfig.SetGroupOwnerIntent(config->groupOwnerIntent);
    cppConfig.SetGroupName(config->groupName);
}

NO_SANITIZE("cfi") WifiErrorCode CreateGroup(const WifiP2pConfig* config)
{
    CHECK_PTR_RETURN(wifiP2pPtr, ERROR_WIFI_NOT_AVAILABLE);
    CHECK_PTR_RETURN(config, ERROR_WIFI_INVALID_ARGS);
    OHOS::Wifi::WifiP2pConfig cppConfig;
    ConvertConfigCToCpp(config, cppConfig);
    return GetCErrorCode(wifiP2pPtr->CreateGroup(cppConfig));
}

NO_SANITIZE("cfi") WifiErrorCode RemoveGroup()
{
    CHECK_PTR_RETURN(wifiP2pPtr, ERROR_WIFI_NOT_AVAILABLE);
    return GetCErrorCode(wifiP2pPtr->RemoveGroup());
}

static void ConvertP2PDeviceCToCpp(const WifiP2pDevice& p2pDevice, OHOS::Wifi::WifiP2pDevice& cppDevice)
{
    cppDevice.SetDeviceName(p2pDevice.deviceName);
    cppDevice.SetDeviceAddress(OHOS::Wifi::MacArrayToStr(p2pDevice.devAddr));
    cppDevice.SetDeviceAddressType(p2pDevice.bssidType);
    cppDevice.SetPrimaryDeviceType(p2pDevice.primaryDeviceType);
    cppDevice.SetSecondaryDeviceType(p2pDevice.secondaryDeviceType);
    cppDevice.SetP2pDeviceStatus(OHOS::Wifi::P2pDeviceStatus(static_cast<int>(p2pDevice.status)));

    OHOS::Wifi::WifiP2pWfdInfo wfdInfo;
    wfdInfo.SetWfdEnabled((bool)p2pDevice.wfdInfo.wfdEnabled);
    wfdInfo.SetDeviceInfo(p2pDevice.wfdInfo.deviceInfo);
    wfdInfo.SetCtrlPort(p2pDevice.wfdInfo.ctrlPort);
    wfdInfo.SetMaxThroughput(p2pDevice.wfdInfo.maxThroughput);
    cppDevice.SetWfdInfo(wfdInfo);

    cppDevice.SetWpsConfigMethod(p2pDevice.supportWpsConfigMethods);
    cppDevice.SetDeviceCapabilitys(p2pDevice.deviceCapabilitys);
    cppDevice.SetGroupCapabilitys(p2pDevice.groupCapabilitys);
}

static void ConvertGroupInfoCToCpp(const WifiP2pGroupInfo* group, OHOS::Wifi::WifiP2pGroupInfo& cppGroup)
{
    CHECK_PTR_RETURN_VOID(group);
    OHOS::Wifi::WifiP2pDevice owner;
    ConvertP2PDeviceCToCpp(group->owner, owner);
    cppGroup.SetOwner(owner);
    cppGroup.SetIsGroupOwner((bool)group->isP2pGroupOwner);
    cppGroup.SetPassphrase(group->passphrase);
    cppGroup.SetInterface(group->interface);
    cppGroup.SetGroupName(group->groupName);
    cppGroup.SetNetworkId(group->networkId);
    cppGroup.SetFrequency(group->frequency);
    cppGroup.SetIsPersistent((bool)group->isP2pPersistent);
    cppGroup.SetP2pGroupStatus(OHOS::Wifi::P2pGroupStatus(static_cast<int>(group->groupStatus)));
    std::vector<OHOS::Wifi::WifiP2pDevice> clientDevices;
    for (int i = 0; i != group->clientDevicesSize && i < MAX_DEVICES_NUM; ++i) {
        OHOS::Wifi::WifiP2pDevice p2pDevice;
        ConvertP2PDeviceCToCpp(group->clientDevices[i], p2pDevice);
        clientDevices.emplace_back(p2pDevice);
    }
    cppGroup.SetClientDevices(clientDevices);
    cppGroup.SetGoIpAddress(group->goIpAddress);
}

NO_SANITIZE("cfi") WifiErrorCode DeleteGroup(const WifiP2pGroupInfo* group)
{
    CHECK_PTR_RETURN(wifiP2pPtr, ERROR_WIFI_NOT_AVAILABLE);
    CHECK_PTR_RETURN(group, ERROR_WIFI_INVALID_ARGS);
    OHOS::Wifi::WifiP2pGroupInfo groupInfo;
    ConvertGroupInfoCToCpp(group, groupInfo);
    return GetCErrorCode(wifiP2pPtr->DeleteGroup(groupInfo));
}

NO_SANITIZE("cfi") WifiErrorCode P2pConnect(const WifiP2pConfig* config)
{
    CHECK_PTR_RETURN(wifiP2pPtr, ERROR_WIFI_NOT_AVAILABLE);
    CHECK_PTR_RETURN(config, ERROR_WIFI_INVALID_ARGS);
    OHOS::Wifi::WifiP2pConfig deviceConfig;
    ConvertConfigCToCpp(config, deviceConfig);
    return GetCErrorCode(wifiP2pPtr->P2pConnect(deviceConfig));
}

NO_SANITIZE("cfi") WifiErrorCode P2pCancelConnect()
{
    CHECK_PTR_RETURN(wifiP2pPtr, ERROR_WIFI_NOT_AVAILABLE);
    return GetCErrorCode(wifiP2pPtr->P2pCancelConnect());
}

static OHOS::Wifi::ErrCode ConvertP2PDeviceCppToC(const OHOS::Wifi::WifiP2pDevice& cppDevice, WifiP2pDevice* p2pDevice)
{
    CHECK_PTR_RETURN(p2pDevice, OHOS::Wifi::WIFI_OPT_INVALID_PARAM);
    size_t nameLen = cppDevice.GetDeviceName().size();
    if (static_cast<unsigned int>(nameLen + 1) >= P2P_NAME_LENGTH) {
        WIFI_LOGE("device name len is invalid! nameLen=%{public}zu", nameLen);
        if (memcpy_s(p2pDevice->deviceName, P2P_NAME_LENGTH,
            cppDevice.GetDeviceName().c_str(), P2P_NAME_LENGTH) != EOK) {
            WIFI_LOGE("memcpy_s device name failed!");
            return OHOS::Wifi::WIFI_OPT_FAILED;
        }
    } else {
        if (memcpy_s(p2pDevice->deviceName, P2P_NAME_LENGTH,
            cppDevice.GetDeviceName().c_str(), nameLen + 1) != EOK) {
            WIFI_LOGE("memcpy_s device name failed!");
            return OHOS::Wifi::WIFI_OPT_FAILED;
        }
    }
    if (OHOS::Wifi::MacStrToArray(cppDevice.GetDeviceAddress(), p2pDevice->devAddr) != EOK) {
        WIFI_LOGE("Mac str to array failed!");
        return OHOS::Wifi::WIFI_OPT_FAILED;
    }
    if (OHOS::Wifi::MacStrToArray(cppDevice.GetRandomDeviceAddress(), p2pDevice->randomDevAddr) != EOK) {
        WIFI_LOGI("randomDevAddr Mac str to array failed!");
    }
    p2pDevice->bssidType = cppDevice.GetDeviceAddressType();
    if (memcpy_s(p2pDevice->primaryDeviceType, DEVICE_TYPE_LENGTH,
        cppDevice.GetPrimaryDeviceType().c_str(), cppDevice.GetPrimaryDeviceType().size() + 1) != EOK) {
        WIFI_LOGE("memcpy_s primary device type failed!");
        return OHOS::Wifi::WIFI_OPT_FAILED;
    }
    if (memcpy_s(p2pDevice->secondaryDeviceType, DEVICE_TYPE_LENGTH,
        cppDevice.GetSecondaryDeviceType().c_str(), cppDevice.GetSecondaryDeviceType().size() + 1) != EOK) {
        WIFI_LOGE("memcpy_s secondary device type failed!");
        return OHOS::Wifi::WIFI_OPT_FAILED;
    }

    p2pDevice->status = P2pDeviceStatus(static_cast<int>(cppDevice.GetP2pDeviceStatus()));
    p2pDevice->wfdInfo.wfdEnabled = cppDevice.GetWfdInfo().GetWfdEnabled();
    p2pDevice->wfdInfo.deviceInfo = cppDevice.GetWfdInfo().GetDeviceInfo();
    p2pDevice->wfdInfo.ctrlPort = cppDevice.GetWfdInfo().GetCtrlPort();
    p2pDevice->wfdInfo.maxThroughput = cppDevice.GetWfdInfo().GetMaxThroughput();
    p2pDevice->supportWpsConfigMethods = cppDevice.GetWpsConfigMethod();
    p2pDevice->deviceCapabilitys = cppDevice.GetDeviceCapabilitys();
    p2pDevice->groupCapabilitys = cppDevice.GetGroupCapabilitys();
    return OHOS::Wifi::WIFI_OPT_SUCCESS;
}

static OHOS::Wifi::ErrCode ConvertGroupInfoCppToC(const OHOS::Wifi::WifiP2pGroupInfo& cppGroup, WifiP2pGroupInfo* group)
{
    CHECK_PTR_RETURN(group, OHOS::Wifi::WIFI_OPT_INVALID_PARAM);
    if (ConvertP2PDeviceCppToC(cppGroup.GetOwner(), &group->owner) != OHOS::Wifi::WIFI_OPT_SUCCESS) {
        return OHOS::Wifi::WIFI_OPT_FAILED;
    }
    group->isP2pGroupOwner = cppGroup.IsGroupOwner();
    if (cppGroup.GetPassphrase().size() >= PASSPHRASE_LENGTH) {
        WIFI_LOGE("passwork len is invaild");
        if (memcpy_s(group->passphrase, PASSPHRASE_LENGTH,
            cppGroup.GetPassphrase().c_str(), PASSPHRASE_LENGTH) != EOK) {
            WIFI_LOGE("memcpy_s passphrase failed!");
            return OHOS::Wifi::WIFI_OPT_FAILED;
        }
    } else {
        if (memcpy_s(group->passphrase, PASSPHRASE_LENGTH,
            cppGroup.GetPassphrase().c_str(), cppGroup.GetPassphrase().size()) != EOK) {
            WIFI_LOGE("memcpy_s passphrase failed!");
            return OHOS::Wifi::WIFI_OPT_FAILED;
        }
        group->passphrase[cppGroup.GetPassphrase().size()] = STR_END;
    }
    if (memcpy_s(group->interface, INTERFACE_LENGTH,
        cppGroup.GetInterface().c_str(), cppGroup.GetInterface().size() + 1) != EOK) {
        WIFI_LOGE("memcpy_s interface failed!");
        return OHOS::Wifi::WIFI_OPT_FAILED;
    }
    if (memcpy_s(group->groupName, P2P_NAME_LENGTH,
        cppGroup.GetGroupName().c_str(), cppGroup.GetGroupName().size() + 1) != EOK) {
        WIFI_LOGE("memcpy_s group name failed!");
        return OHOS::Wifi::WIFI_OPT_FAILED;
    }
    group->networkId = cppGroup.GetNetworkId();
    group->frequency = cppGroup.GetFrequency();
    group->isP2pPersistent = cppGroup.IsPersistent();
    group->groupStatus = P2pGroupStatus(static_cast<int>(cppGroup.GetP2pGroupStatus()));
    const std::vector<OHOS::Wifi::WifiP2pDevice>& vecDevices = cppGroup.GetClientDevices();
    for (size_t i = 0; i != vecDevices.size() && i < MAX_DEVICES_NUM; ++i) {
        if (ConvertP2PDeviceCppToC(vecDevices[i], &group->clientDevices[i]) != OHOS::Wifi::WIFI_OPT_SUCCESS) {
            WIFI_LOGE("convert p2p device failed!");
            return OHOS::Wifi::WIFI_OPT_FAILED;
        }
    }
    group->clientDevicesSize = (int)vecDevices.size();
    if (memcpy_s(group->goIpAddress, IP_ADDR_STR_LEN,
        cppGroup.GetGoIpAddress().c_str(), cppGroup.GetGoIpAddress().size() + 1) != EOK) {
        WIFI_LOGE("memcpy_s interface failed!");
        return OHOS::Wifi::WIFI_OPT_FAILED;
    }
    return OHOS::Wifi::WIFI_OPT_SUCCESS;
}

NO_SANITIZE("cfi") WifiErrorCode GetCurrentGroup(WifiP2pGroupInfo* groupInfo)
{
    CHECK_PTR_RETURN(wifiP2pPtr, ERROR_WIFI_NOT_AVAILABLE);
    CHECK_PTR_RETURN(groupInfo, ERROR_WIFI_INVALID_ARGS);
    OHOS::Wifi::WifiP2pGroupInfo cppGroupInfo;
    OHOS::Wifi::ErrCode ret = wifiP2pPtr->GetCurrentGroup(cppGroupInfo);
    if (ret == OHOS::Wifi::WIFI_OPT_FAILED) {
        WIFI_LOGE("P2P_GROUP_AVAILABLE failed!");
        return ERROR_P2P_GROUP_NOT_AVAILABLE;
    }
    if (ret != OHOS::Wifi::WIFI_OPT_SUCCESS) {
        WIFI_LOGE("get current group info failed!");
        return ERROR_WIFI_NOT_AVAILABLE;
    }
    return GetCErrorCode(ConvertGroupInfoCppToC(cppGroupInfo, groupInfo));
}

NO_SANITIZE("cfi") WifiErrorCode GetP2pConnectedStatus(int* status)
{
    CHECK_PTR_RETURN(wifiP2pPtr, ERROR_WIFI_NOT_AVAILABLE);
    CHECK_PTR_RETURN(status, ERROR_WIFI_INVALID_ARGS);
    int p2pStatus = -1;
    OHOS::Wifi::ErrCode ret = wifiP2pPtr->GetP2pConnectedStatus(p2pStatus);
    if (ret != OHOS::Wifi::WIFI_OPT_SUCCESS) {
        WIFI_LOGE("get p2p status failed!");
    }
    *status = p2pStatus;
    return GetCErrorCode(ret);
}

NO_SANITIZE("cfi") WifiErrorCode QueryP2pLocalDevice(WifiP2pDevice* deviceInfo)
{
    CHECK_PTR_RETURN(wifiP2pPtr, ERROR_WIFI_NOT_AVAILABLE);
    CHECK_PTR_RETURN(deviceInfo, ERROR_WIFI_INVALID_ARGS);
    OHOS::Wifi::WifiP2pDevice cppDeviceInfo;
    OHOS::Wifi::ErrCode ret = wifiP2pPtr->QueryP2pLocalDevice(cppDeviceInfo);
    if (ret != OHOS::Wifi::WIFI_OPT_SUCCESS) {
        WIFI_LOGE("QueryP2pLocalDevice return failed!");
    }
    return GetCErrorCode(ConvertP2PDeviceCppToC(cppDeviceInfo, deviceInfo));
}

NO_SANITIZE("cfi") WifiErrorCode QueryP2pDevices(WifiP2pDevice* clientDevices, int size, int* retSize)
{
    CHECK_PTR_RETURN(wifiP2pPtr, ERROR_WIFI_NOT_AVAILABLE);
    CHECK_PTR_RETURN(clientDevices, ERROR_WIFI_INVALID_ARGS);
    CHECK_PTR_RETURN(retSize, ERROR_WIFI_INVALID_ARGS);
    std::vector<OHOS::Wifi::WifiP2pDevice> vecDevices;
    OHOS::Wifi::ErrCode ret = wifiP2pPtr->QueryP2pDevices(vecDevices);
    if (ret != OHOS::Wifi::WIFI_OPT_SUCCESS) {
        WIFI_LOGE("query p2p devices failed!");
        return ERROR_WIFI_UNKNOWN;
    }

    for (int i = 0; i != (int)vecDevices.size() && i < size; ++i) {
        if (ConvertP2PDeviceCppToC(vecDevices[i], clientDevices++) != OHOS::Wifi::WIFI_OPT_SUCCESS) {
            WIFI_LOGE("convert p2p device failed!");
            return ERROR_WIFI_UNKNOWN;
        }
    }
    *retSize = std::min(size, (int)vecDevices.size());
    return WIFI_SUCCESS;
}

NO_SANITIZE("cfi") WifiErrorCode QueryP2pGroups(WifiP2pGroupInfo* groupInfo, int size)
{
    CHECK_PTR_RETURN(wifiP2pPtr, ERROR_WIFI_NOT_AVAILABLE);
    CHECK_PTR_RETURN(groupInfo, ERROR_WIFI_INVALID_ARGS);
    std::vector<OHOS::Wifi::WifiP2pGroupInfo> groups;
    OHOS::Wifi::ErrCode ret = wifiP2pPtr->QueryP2pGroups(groups);
    if (ret != OHOS::Wifi::WIFI_OPT_SUCCESS) {
        WIFI_LOGE("query p2p devices failed!");
        return ERROR_WIFI_UNKNOWN;
    }

    for (int i = 0; i != (int)groups.size() && i < size; ++i) {
        ret = ConvertGroupInfoCppToC(groups[i], groupInfo++);
        if (ret != OHOS::Wifi::WIFI_OPT_SUCCESS) {
            WIFI_LOGE("convert group info failed!");
            return ERROR_WIFI_UNKNOWN;
        }
    }
    return WIFI_SUCCESS;
}

void WifiP2pCEventCallback::OnP2pStateChanged(int state)
{
    WIFI_LOGI("received state changed event: %{public}d", state);
    std::unique_lock<std::mutex> lock(p2pCallbackMutex);
    if (stateChangeCb) {
        stateChangeCb(P2pState(state));
    }
}

void WifiP2pCEventCallback::OnP2pPersistentGroupsChanged(void)
{
    WIFI_LOGI("received group changed event");
    std::unique_lock<std::mutex> lock(p2pCallbackMutex);
    if (groupChangeCb) {
        groupChangeCb();
    }
}

void WifiP2pCEventCallback::OnP2pThisDeviceChanged(const OHOS::Wifi::WifiP2pDevice &device)
{
    WIFI_LOGI("%{public}s, received this device changed event", __func__);
}

void WifiP2pCEventCallback::OnP2pPeersChanged(const std::vector<OHOS::Wifi::WifiP2pDevice> &devices)
{
    WIFI_LOGI("received peers changed event: %{public}d", (int)devices.size());
    WifiP2pDevice *devicePtr = nullptr;
    if (!devices.empty()) {
        devicePtr = new (std::nothrow) WifiP2pDevice[(int)devices.size()];
        if (devicePtr == nullptr) {
            WIFI_LOGE("new WifiP2pDevice failed!");
            return;
        }
        WifiP2pDevice *p = devicePtr;
        for (auto& each : devices) {
            if (ConvertP2PDeviceCppToC(each, p++) != OHOS::Wifi::WIFI_OPT_SUCCESS) {
                WIFI_LOGE("peers changed convert p2p device failed!");
                delete[] devicePtr;
                return;
            }
        }
    }

    {
        std::unique_lock<std::mutex> lock(p2pCallbackMutex);
        if (peersChangeCb) {
            peersChangeCb(devicePtr, (int)devices.size());
        }
    }

    if (devicePtr) {
        delete[] devicePtr;
        devicePtr = nullptr;
    }
}

void WifiP2pCEventCallback::OnP2pPrivatePeersChanged(const std::string &priWfdInfo)
{
    WIFI_LOGI("%{public}s, received p2p Private Peer changed event", __func__);
    char* wfdInfo  = const_cast<char*>(priWfdInfo.c_str());
    std::unique_lock<std::mutex> lock(p2pCallbackMutex);
    if (privatepeerChangeCb) {
        privatepeerChangeCb(wfdInfo);
    }
}

void WifiP2pCEventCallback::OnP2pServicesChanged(const std::vector<OHOS::Wifi::WifiP2pServiceInfo> &srvInfo)
{
    WIFI_LOGI("%{public}s, received p2p services changed event", __func__);
}

void WifiP2pCEventCallback::OnP2pConnectionChanged(const OHOS::Wifi::WifiP2pLinkedInfo &info)
{
    WIFI_LOGI("received connection changed event");
    std::unique_lock<std::mutex> lock(p2pCallbackMutex);
    if (connectionChangeCb) {
        connectionChangeCb(ConvertP2pLinkedInfo(info));
    }
}

void WifiP2pCEventCallback::OnP2pDiscoveryChanged(bool isChange)
{
    WIFI_LOGI("%{public}s, received p2p discovery changed event", __func__);
}

void WifiP2pCEventCallback::OnP2pActionResult(OHOS::Wifi::P2pActionCallback action, OHOS::Wifi::ErrCode code)
{
    WIFI_LOGI("%{public}s, received p2p action results event", __func__);
}

void WifiP2pCEventCallback::OnConfigChanged(OHOS::Wifi::CfgType type, char* data, int dataLen)
{
    WIFI_LOGI("received config change event: %{public}d", static_cast<int>(type));
    std::unique_lock<std::mutex> lock(p2pCallbackMutex);
    if (cfgChangeCallback) {
        cfgChangeCallback(CfgType(type), data, dataLen);
    }
}

void WifiP2pCEventCallback::OnP2pGcJoinGroup(const OHOS::Wifi::GcInfo &info)
{
    WIFI_LOGI("%{public}s, received p2p gcJoin event", __func__);
}

void WifiP2pCEventCallback::OnP2pGcLeaveGroup(const OHOS::Wifi::GcInfo &info)
{
    WIFI_LOGI("%{public}s, received p2p gcLeave event", __func__);
}

void WifiP2pCEventCallback::OnP2pChrErrCodeReport(const int errCode)
{
    WIFI_LOGI("%{public}s, received p2p chr errCode event, %{public}d", __func__, errCode);
    std::unique_lock<std::mutex> lock(p2pCallbackMutex);
    if (p2pChrErrCodeReportCb) {
        p2pChrErrCodeReportCb(errCode);
    }
}

OHOS::sptr<OHOS::IRemoteObject> WifiP2pCEventCallback::AsObject()
{
    return nullptr;
}

WifiP2pLinkedInfo WifiP2pCEventCallback::ConvertP2pLinkedInfo(const OHOS::Wifi::WifiP2pLinkedInfo& linkedInfo)
{
    WifiP2pLinkedInfo info;
    info.connectState = P2pConnectionState(static_cast<int>(linkedInfo.GetConnectState()));
    info.isP2pGroupOwner = linkedInfo.IsGroupOwner();
    OHOS::Wifi::MacStrToArray(linkedInfo.GetGroupOwnerAddress(), info.groupOwnerAddress);
    return info;
}

OHOS::sptr<WifiP2pCEventCallback> sptrCallback =
    OHOS::sptr<WifiP2pCEventCallback>(new (std::nothrow) WifiP2pCEventCallback());

NO_SANITIZE("cfi") WifiErrorCode RegisterP2pStateChangedCallback(const P2pStateChangedCallback callback)
{
    CHECK_PTR_RETURN(callback, ERROR_WIFI_INVALID_ARGS);
    CHECK_PTR_RETURN(wifiP2pPtr, ERROR_WIFI_NOT_AVAILABLE);
    CHECK_PTR_RETURN(sptrCallback, ERROR_WIFI_NOT_AVAILABLE);
    EventManager::GetInstance().Init();
    sptrCallback->stateChangeCb = callback;
    std::vector<std::string> event = {EVENT_P2P_STATE_CHANGE};
    wifiP2pPtr->RegisterCallBack(sptrCallback, event);
    EventManager::GetInstance().SetP2PCallbackEvent(sptrCallback, EVENT_P2P_STATE_CHANGE);
    return WIFI_SUCCESS;
}

NO_SANITIZE("cfi")
WifiErrorCode RegisterP2pPersistentGroupsChangedCallback(const P2pPersistentGroupsChangedCallback callback)
{
    CHECK_PTR_RETURN(callback, ERROR_WIFI_INVALID_ARGS);
    CHECK_PTR_RETURN(wifiP2pPtr, ERROR_WIFI_NOT_AVAILABLE);
    CHECK_PTR_RETURN(sptrCallback, ERROR_WIFI_NOT_AVAILABLE);
    EventManager::GetInstance().Init();
    sptrCallback->groupChangeCb = callback;
    std::vector<std::string> event = {EVENT_P2P_PERSISTENT_GROUP_CHANGE};
    wifiP2pPtr->RegisterCallBack(sptrCallback, event);
    EventManager::GetInstance().SetP2PCallbackEvent(sptrCallback, EVENT_P2P_PERSISTENT_GROUP_CHANGE);
    return WIFI_SUCCESS;
}

NO_SANITIZE("cfi") WifiErrorCode RegisterP2pConnectionChangedCallback(const P2pConnectionChangedCallback callback)
{
    CHECK_PTR_RETURN(callback, ERROR_WIFI_INVALID_ARGS);
    CHECK_PTR_RETURN(wifiP2pPtr, ERROR_WIFI_NOT_AVAILABLE);
    CHECK_PTR_RETURN(sptrCallback, ERROR_WIFI_NOT_AVAILABLE);
    EventManager::GetInstance().Init();
    sptrCallback->connectionChangeCb = callback;
    std::vector<std::string> event = {EVENT_P2P_CONN_STATE_CHANGE};
    wifiP2pPtr->RegisterCallBack(sptrCallback, event);
    EventManager::GetInstance().SetP2PCallbackEvent(sptrCallback, EVENT_P2P_CONN_STATE_CHANGE);
    return WIFI_SUCCESS;
}

NO_SANITIZE("cfi") WifiErrorCode RegisterP2pPeersChangedCallback(const P2pPeersChangedCallback callback)
{
    CHECK_PTR_RETURN(callback, ERROR_WIFI_INVALID_ARGS);
    CHECK_PTR_RETURN(wifiP2pPtr, ERROR_WIFI_NOT_AVAILABLE);
    CHECK_PTR_RETURN(sptrCallback, ERROR_WIFI_NOT_AVAILABLE);
    EventManager::GetInstance().Init();
    sptrCallback->peersChangeCb = callback;
    std::vector<std::string> event = {EVENT_P2P_PEER_DEVICE_CHANGE};
    wifiP2pPtr->RegisterCallBack(sptrCallback, event);
    EventManager::GetInstance().SetP2PCallbackEvent(sptrCallback, EVENT_P2P_PEER_DEVICE_CHANGE);
    return WIFI_SUCCESS;
}

NO_SANITIZE("cfi") WifiErrorCode RegisterP2pPrivatePeersChangedCallback(const P2pPrivatePeersChangedCallback callback)
{
    CHECK_PTR_RETURN(callback, ERROR_WIFI_INVALID_ARGS);
    CHECK_PTR_RETURN(wifiP2pPtr, ERROR_WIFI_NOT_AVAILABLE);
    CHECK_PTR_RETURN(sptrCallback, ERROR_WIFI_NOT_AVAILABLE);
    EventManager::GetInstance().Init();
    sptrCallback->privatepeerChangeCb = callback;
    std::vector<std::string> event = {EVENT_P2P_PRIVATE_PEER_DEVICE_CHANGE};
    wifiP2pPtr->RegisterCallBack(sptrCallback, event);
    EventManager::GetInstance().SetP2PCallbackEvent(sptrCallback, EVENT_P2P_PRIVATE_PEER_DEVICE_CHANGE);
    return WIFI_SUCCESS;
}

NO_SANITIZE("cfi") WifiErrorCode RegisterCfgChangCallback(const WifiCfgChangCallback callback)
{
    CHECK_PTR_RETURN(callback, ERROR_WIFI_INVALID_ARGS);
    CHECK_PTR_RETURN(wifiP2pPtr, ERROR_WIFI_NOT_AVAILABLE);
    CHECK_PTR_RETURN(sptrCallback, ERROR_WIFI_NOT_AVAILABLE);
    EventManager::GetInstance().Init();
    sptrCallback->cfgChangeCallback = callback;
    std::vector<std::string> event = {EVENT_P2P_CONFIG_CHANGE};
    wifiP2pPtr->RegisterCallBack(sptrCallback, event);
    EventManager::GetInstance().SetP2PCallbackEvent(sptrCallback, EVENT_P2P_CONFIG_CHANGE);
    return WIFI_SUCCESS;
}

NO_SANITIZE("cfi") WifiErrorCode UnregisterCfgChangCallback(void)
{
    CHECK_PTR_RETURN(sptrCallback, ERROR_WIFI_NOT_AVAILABLE);
    sptrCallback->cfgChangeCallback = nullptr;
    EventManager::GetInstance().RemoveP2PCallbackEvent(EVENT_P2P_CONFIG_CHANGE);
    return WIFI_SUCCESS;
}

NO_SANITIZE("cfi") WifiErrorCode RegisterP2pChrErrCodeReportCallback(const P2pChrErrCodeReportCallback callback)
{
    CHECK_PTR_RETURN(callback, ERROR_WIFI_INVALID_ARGS);
    CHECK_PTR_RETURN(wifiP2pPtr, ERROR_WIFI_NOT_AVAILABLE);
    CHECK_PTR_RETURN(sptrCallback, ERROR_WIFI_NOT_AVAILABLE);
    EventManager::GetInstance().Init();
    sptrCallback->p2pChrErrCodeReportCb = callback;
    std::vector<std::string> event = {EVENT_P2P_CHR_ERRCODE_REPORT};
    wifiP2pPtr->RegisterCallBack(sptrCallback, event);
    EventManager::GetInstance().SetP2PCallbackEvent(sptrCallback, EVENT_P2P_CHR_ERRCODE_REPORT);
    return WIFI_SUCCESS;
}

NO_SANITIZE("cfi") WifiErrorCode DiscoverPeers(int32_t channelid)
{
    CHECK_PTR_RETURN(wifiP2pPtr, ERROR_WIFI_NOT_AVAILABLE);
    return GetCErrorCode(wifiP2pPtr->DiscoverPeers(channelid));
}

NO_SANITIZE("cfi") WifiErrorCode DisableRandomMac(int setmode)
{
    CHECK_PTR_RETURN(wifiP2pPtr, ERROR_WIFI_NOT_AVAILABLE);
    return GetCErrorCode(wifiP2pPtr->DisableRandomMac(setmode));
}

NO_SANITIZE("cfi") WifiErrorCode CheckCanUseP2p()
{
    CHECK_PTR_RETURN(wifiP2pPtr, ERROR_WIFI_NOT_AVAILABLE);
    return GetCErrorCode(wifiP2pPtr->CheckCanUseP2p());
}

NO_SANITIZE("cfi") WifiErrorCode SetMiracastSinkConfig(const char* config)
{
    CHECK_PTR_RETURN(wifiP2pPtr, ERROR_WIFI_NOT_AVAILABLE);
    return GetCErrorCode(wifiP2pPtr->SetMiracastSinkConfig(config));
}