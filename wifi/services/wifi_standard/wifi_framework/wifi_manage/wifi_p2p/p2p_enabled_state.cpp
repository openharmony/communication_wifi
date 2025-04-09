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

#include "p2p_enabled_state.h"
#include <string>
#include "wifi_logger.h"
#include "wifi_p2p_hal_interface.h"
#include "wifi_settings.h"
#include "p2p_state_machine.h"
#include "wifi_logger.h"

DEFINE_WIFILOG_P2P_LABEL("P2pEnabledState");

namespace OHOS {
namespace Wifi {
const int CHANNEL_INDEX_OF_DISCOVER = 16;
const int TIMEOUT_MASK_OF_DISCOVER = 0x00FF;
const int DISCOVER_TIMEOUT_S = 120;
// miracast
const int CMD_TYPE_SET = 2;
const int DATA_TYPE_SET_LISTEN_MODE = 4;
const std::string ONEHOP_LISTEN_MODE = "1";

P2pEnabledState::P2pEnabledState(P2pStateMachine &stateMachine, WifiP2pGroupManager &groupMgr,
    WifiP2pDeviceManager &deviceMgr)
    : State("P2pEnabledState"),
      mProcessFunMap(),
      p2pStateMachine(stateMachine),
      groupManager(groupMgr),
      deviceManager(deviceMgr)
{}
void P2pEnabledState::GoInState()
{
    WIFI_LOGI("             GoInState");
    Init();
    constexpr int defaultPeriodTime = 500;
    constexpr int defaultIntervalTime = 1000;
    p2pStateMachine.BroadcastP2pConnectionChanged();
    if (P2pSettingsInitialization()) {
        p2pStateMachine.BroadcastP2pStatusChanged(P2pState::P2P_STATE_STARTED);
        P2pVendorConfig config;
        WifiSettings::GetInstance().GetP2pVendorConfig(config);
        if (config.GetIsAutoListen()) {
            WIFI_LOGI("Auto start P2P listen!");
            p2pStateMachine.SendMessage(
                static_cast<int>(P2P_STATE_MACHINE_CMD::CMD_START_LISTEN), defaultPeriodTime, defaultIntervalTime);
        }
    } else {
        WIFI_LOGE("P2pSettingsInitialization Failed, Start Disable P2P!");
        p2pStateMachine.SendMessage(static_cast<int>(P2P_STATE_MACHINE_CMD::CMD_P2P_DISABLE));
    }
}

void P2pEnabledState::GoOutState()
{
    WIFI_LOGI("             GoOutState");
}

void P2pEnabledState::Init()
{
    mProcessFunMap.insert(std::make_pair(P2P_STATE_MACHINE_CMD::CMD_P2P_DISABLE,
        [this](InternalMessagePtr msg) { return this->ProcessCmdDisable(msg); }));
    mProcessFunMap.insert(std::make_pair(P2P_STATE_MACHINE_CMD::CMD_START_LISTEN,
        [this](InternalMessagePtr msg) { return this->ProcessCmdStartListen(msg); }));
    mProcessFunMap.insert(std::make_pair(P2P_STATE_MACHINE_CMD::CMD_STOP_LISTEN,
        [this](InternalMessagePtr msg) { return this->ProcessCmdStopListen(msg); }));
    mProcessFunMap.insert(std::make_pair(P2P_STATE_MACHINE_CMD::CMD_DEVICE_DISCOVERS,
        [this](InternalMessagePtr msg) { return this->ProcessCmdDiscPeer(msg); }));
    mProcessFunMap.insert(std::make_pair(P2P_STATE_MACHINE_CMD::CMD_STOP_DEVICE_DISCOVERS,
        [this](InternalMessagePtr msg) { return this->ProcessCmdStopDiscPeer(msg); }));
    mProcessFunMap.insert(std::make_pair(P2P_STATE_MACHINE_CMD::P2P_EVENT_DEVICE_FOUND,
        [this](InternalMessagePtr msg) { return this->ProcessDeviceFoundEvt(msg); }));
    mProcessFunMap.insert(std::make_pair(P2P_STATE_MACHINE_CMD::P2P_EVENT_PRI_DEVICE_FOUND,
        [this](InternalMessagePtr msg) { return this->ProcessPriDeviceFoundEvt(msg); }));
    mProcessFunMap.insert(std::make_pair(P2P_STATE_MACHINE_CMD::P2P_EVENT_DEVICE_LOST,
        [this](InternalMessagePtr msg) { return this->ProcessDeviceLostEvt(msg); }));
    mProcessFunMap.insert(std::make_pair(P2P_STATE_MACHINE_CMD::P2P_EVENT_FIND_STOPPED,
        [this](InternalMessagePtr msg) { return this->ProcessFindStoppedEvt(msg); }));
    mProcessFunMap.insert(std::make_pair(P2P_STATE_MACHINE_CMD::CMD_DELETE_GROUP,
        [this](InternalMessagePtr msg) { return this->ProcessCmdDeleteGroup(msg); }));
    mProcessFunMap.insert(std::make_pair(P2P_STATE_MACHINE_CMD::CMD_PUT_LOCAL_SERVICE,
        [this](InternalMessagePtr msg) { return this->ProcessCmdAddLocalService(msg); }));
    mProcessFunMap.insert(std::make_pair(P2P_STATE_MACHINE_CMD::CMD_DEL_LOCAL_SERVICE,
        [this](InternalMessagePtr msg) { return this->ProcessCmdDelLocalService(msg); }));
    mProcessFunMap.insert(std::make_pair(P2P_STATE_MACHINE_CMD::CMD_DISCOVER_SERVICES,
        [this](InternalMessagePtr msg) { return this->ProcessCmdDiscServices(msg); }));
    mProcessFunMap.insert(std::make_pair(P2P_STATE_MACHINE_CMD::CMD_STOP_DISCOVER_SERVICES,
        [this](InternalMessagePtr msg) { return this->ProcessCmdStopDiscServices(msg); }));
    mProcessFunMap.insert(std::make_pair(P2P_STATE_MACHINE_CMD::CMD_REQUEST_SERVICE,
        [this](InternalMessagePtr msg) { return this->ProcessCmdRequestService(msg); }));
    mProcessFunMap.insert(std::make_pair(P2P_STATE_MACHINE_CMD::P2P_EVENT_SERV_DISC_REQ,
        [this](InternalMessagePtr msg) { return this->ProcessServiceDiscReqEvt(msg); }));
    mProcessFunMap.insert(std::make_pair(P2P_STATE_MACHINE_CMD::P2P_EVENT_SERV_DISC_RESP,
        [this](InternalMessagePtr msg) { return this->ProcessServiceDiscRspEvt(msg); }));
    mProcessFunMap.insert(std::make_pair(P2P_STATE_MACHINE_CMD::EXCEPTION_TIMED_OUT,
        [this](InternalMessagePtr msg) { return this->ProcessExceptionTimeOut(msg); }));
    mProcessFunMap.insert(std::make_pair(P2P_STATE_MACHINE_CMD::CMD_SET_DEVICE_NAME,
        [this](InternalMessagePtr msg) { return this->ProcessCmdSetDeviceName(msg); }));
    mProcessFunMap.insert(std::make_pair(P2P_STATE_MACHINE_CMD::CMD_SET_WFD_INFO,
        [this](InternalMessagePtr msg) { return this->ProcessCmdSetWfdInfo(msg); }));
    mProcessFunMap.insert(std::make_pair(P2P_STATE_MACHINE_CMD::CMD_CANCEL_CONNECT,
        [this](InternalMessagePtr msg) { return this->ProcessCmdCancelConnect(msg); }));
    mProcessFunMap.insert(std::make_pair(P2P_STATE_MACHINE_CMD::P2P_CONNECT_FAILED,
        [this](InternalMessagePtr msg) { return this->ProcessCmdConnectFailed(msg); }));
    mProcessFunMap.insert(std::make_pair(P2P_STATE_MACHINE_CMD::CMD_DISCOVER_PEERS,
        [this](InternalMessagePtr msg) { return this->ProcessCmdDiscoverPeers(msg); }));
    InitProcessMsg();
}

void P2pEnabledState::InitProcessMsg()
{
    mProcessFunMap.insert(std::make_pair(P2P_STATE_MACHINE_CMD::CMD_INCREASE_SHARE_LINK,
        [this](InternalMessagePtr msg) { return this->ProcessCmdIncreaseSharedLink(msg); }));
    mProcessFunMap.insert(std::make_pair(P2P_STATE_MACHINE_CMD::CMD_DECREASE_SHARE_LINK,
        [this](InternalMessagePtr msg) { return this->ProcessCmdDecreaseSharedLink(msg); }));
    mProcessFunMap.insert(std::make_pair(P2P_STATE_MACHINE_CMD::P2P_EVENT_CHR_REPORT,
        [this](InternalMessagePtr msg) { return this->ProcessChrReport(msg); }));
    mProcessFunMap.insert(std::make_pair(P2P_STATE_MACHINE_CMD::CMD_SET_MIRACAST_SINK_CONFIG,
        [this](InternalMessagePtr msg) { return this->ProcessSetMiracastSinkConfig(msg); }));
}

bool P2pEnabledState::ProcessCmdDisable(InternalMessagePtr msg) const
{
    WIFI_LOGI("P2P ProcessCmdDisable recv CMD: %{public}d", msg->GetMessageName());
    p2pStateMachine.BroadcastP2pStatusChanged(P2pState::P2P_STATE_CLOSING);
    p2pStateMachine.BroadcastP2pDiscoveryChanged(false);
    WifiP2PHalInterface::GetInstance().StopP2p();
    p2pStateMachine.SwitchState(&p2pStateMachine.p2pDisablingState);
    return EXECUTED;
}
bool P2pEnabledState::ProcessCmdStartListen(InternalMessagePtr msg) const
{
    p2pStateMachine.StopTimer(static_cast<int>(P2P_STATE_MACHINE_CMD::P2P_REMOVE_DEVICE));

    if (WifiP2PHalInterface::GetInstance().P2pFlush()) {
        WIFI_LOGW("Unexpected results in p2p flush.");
    }

    constexpr int defaultOpClass = 81;
    constexpr int defaultChannel = 6;
    if (WifiP2PHalInterface::GetInstance().SetListenChannel(defaultChannel, defaultOpClass)) {
        WIFI_LOGI("p2p set listen channel failed. channel:%{public}d, opclass:%{public}d", defaultChannel,
            defaultOpClass);
        p2pStateMachine.BroadcastActionResult(P2pActionCallback::StartP2pListen, WIFI_OPT_FAILED);
        return EXECUTED;
    }

    size_t period = static_cast<size_t>(msg->GetParam1());
    size_t interval = static_cast<size_t>(msg->GetParam2());
    if (WifiP2PHalInterface::GetInstance().P2pConfigureListen(true, period, interval)) {
        WIFI_LOGE("p2p configure to start listen failed.");
        p2pStateMachine.BroadcastActionResult(P2pActionCallback::StartP2pListen, WIFI_OPT_FAILED);
    } else {
        WIFI_LOGI("p2p configure to start listen successful.");
        p2pStateMachine.BroadcastActionResult(P2pActionCallback::StartP2pListen, WIFI_OPT_SUCCESS);
    }
    return EXECUTED;
}
bool P2pEnabledState::ProcessCmdStopListen(InternalMessagePtr msg) const
{
    WIFI_LOGI("P2P ProcessCmdStopListen recv CMD: %{public}d", msg->GetMessageName());
    if (WifiP2PHalInterface::GetInstance().P2pConfigureListen(false, 0, 0)) {
        WIFI_LOGE("p2p configure to stop listen failed.");
        p2pStateMachine.BroadcastActionResult(P2pActionCallback::StopP2pListen, WIFI_OPT_FAILED);
    } else {
        WIFI_LOGI("p2p configure to stop listen successful.");
        p2pStateMachine.BroadcastActionResult(P2pActionCallback::StopP2pListen, WIFI_OPT_SUCCESS);
    }

    if (!WifiP2PHalInterface::GetInstance().P2pFlush()) {
        WIFI_LOGW("Unexpected results in p2p flush.");
    }
    return EXECUTED;
}
bool P2pEnabledState::ProcessCmdDiscPeer(InternalMessagePtr msg) const
{
    p2pStateMachine.StopTimer(static_cast<int>(P2P_STATE_MACHINE_CMD::P2P_REMOVE_DEVICE));
    WIFI_LOGI("P2P ProcessCmdDiscPeer recv CMD: %{public}d", msg->GetMessageName());
    p2pStateMachine.HandlerDiscoverPeers();
    return EXECUTED;
}
bool P2pEnabledState::ProcessCmdStopDiscPeer(InternalMessagePtr msg) const
{
    WIFI_LOGI("P2P ProcessCmdStopDiscPeer recv CMD: %{public}d", msg->GetMessageName());
    WifiErrorNo retCode = WifiP2PHalInterface::GetInstance().P2pStopFind();
    if (retCode == WifiErrorNo::WIFI_HAL_OPT_OK) {
        p2pStateMachine.BroadcastActionResult(P2pActionCallback::StopDiscoverDevices, ErrCode::WIFI_OPT_SUCCESS);
    } else {
        p2pStateMachine.BroadcastActionResult(P2pActionCallback::StopDiscoverDevices, ErrCode::WIFI_OPT_FAILED);
    }
    return EXECUTED;
}
bool P2pEnabledState::ProcessDeviceFoundEvt(InternalMessagePtr msg) const
{
    WIFI_LOGI("p2p_enabled_state recv P2P_EVENT_DEVICE_FOUND");
    WifiP2pDevice device;
    if (!msg->GetMessageObj(device)) {
        WIFI_LOGE("Failed to obtain device information.");
        return EXECUTED;
    }

    if (deviceManager.GetThisDevice() == device) {
        return EXECUTED;
    }
    WIFI_LOGI("ProcessDeviceFoundEvt, address:%{private}s, addressType:%{public}d",
        device.GetDeviceAddress().c_str(), device.GetDeviceAddressType());
    deviceManager.UpdateDeviceSupplicantInf(device);
    p2pStateMachine.BroadcastP2pPeersChanged();
    return EXECUTED;
}
bool P2pEnabledState::ProcessPriDeviceFoundEvt(InternalMessagePtr msg) const
{
    WIFI_LOGI("p2p_enabled_state recv P2P_EVENT_PRI_DEVICE_FOUND");
    std::string privateInfo;
    if (!msg->GetMessageObj(privateInfo)) {
        WIFI_LOGE("Failed to obtain device information.");
        return EXECUTED;
    }
    p2pStateMachine.BroadcastP2pPrivatePeersChanged(privateInfo);
    return EXECUTED;
}
bool P2pEnabledState::ProcessDeviceLostEvt(InternalMessagePtr msg) const
{
    WIFI_LOGI("p2p_enabled_state recv P2P_EVENT_DEVICE_LOST");
    WifiP2pDevice device;
    if (!msg->GetMessageObj(device)) {
        WIFI_LOGE("Failed to obtain device information.");
        return EXECUTED;
    }
    WIFI_LOGI("ProcessDeviceLostEvt, address:%{private}s, addressType:%{public}d",
        device.GetDeviceAddress().c_str(), device.GetDeviceAddressType());
    if (deviceManager.RemoveDevice(device.GetDeviceAddress())) {
        p2pStateMachine.BroadcastP2pPeersChanged();
    }

    if (p2pStateMachine.serviceManager.DelServicesFormAddress(device.GetDeviceAddress())) {
        p2pStateMachine.BroadcastP2pServicesChanged();
    }

    if (p2pStateMachine.serviceManager.RemoveServiceResponse(device.GetDeviceAddress())) {
        WIFI_LOGI("device: %{private}s , Delete a response record.", device.GetDeviceAddress().c_str());
    }
    return EXECUTED;
}
bool P2pEnabledState::ProcessFindStoppedEvt(InternalMessagePtr msg) const
{
    WIFI_LOGI("P2P ProcessFindStoppedEvt recv event: %{public}d", msg->GetMessageName());
    p2pStateMachine.BroadcastP2pDiscoveryChanged(false);
    return EXECUTED;
}
bool P2pEnabledState::ProcessCmdDeleteGroup(InternalMessagePtr msg) const
{
    p2pStateMachine.DelayMessage(msg);
    p2pStateMachine.SwitchState(&p2pStateMachine.p2pGroupOperatingState);
    return EXECUTED;
}

bool P2pEnabledState::ExecuteStateMsg(InternalMessagePtr msg)
{
    if (msg == nullptr) {
        WIFI_LOGE("fatal error!");
        return NOT_EXECUTED;
    }
    int msgName = msg->GetMessageName();
    auto iter = mProcessFunMap.find(static_cast<P2P_STATE_MACHINE_CMD>(msgName));
    if (iter == mProcessFunMap.end()) {
        return NOT_EXECUTED;
    }
    if ((iter->second)(msg)) {
        return EXECUTED;
    } else {
        return NOT_EXECUTED;
    }
}

bool P2pEnabledState::P2pConfigInitialization()
{
    bool result = true;

    p2pStateMachine.InitializeThisDevice();
    const std::string &deviceName = deviceManager.GetThisDevice().GetDeviceName();
    const std::string ssidPostfixName = std::string("-") + deviceName;

    WifiErrorNo retCode = WifiP2PHalInterface::GetInstance().SetP2pDeviceName(deviceName);
    if (retCode == WifiErrorNo::WIFI_HAL_OPT_FAILED) {
        WIFI_LOGE("Failed to set the device name.");
        result = false;
    }

    retCode = WifiP2PHalInterface::GetInstance().SetP2pSsidPostfix(ssidPostfixName);
    if (retCode == WifiErrorNo::WIFI_HAL_OPT_FAILED) {
        WIFI_LOGE("Failed to set the SSID prefix");
    }

    std::string primaryDeviceType = deviceManager.GetThisDevice().GetPrimaryDeviceType();
    if (!primaryDeviceType.empty()) {
        retCode = WifiP2PHalInterface::GetInstance().SetP2pDeviceType(primaryDeviceType);
        if (retCode == WifiErrorNo::WIFI_HAL_OPT_FAILED) {
            WIFI_LOGE("Failed to set the device type.");
            result = false;
        }
    } else {
        WIFI_LOGE("Primary device type is empty!!!");
    }

    std::string secDeviceType = deviceManager.GetThisDevice().GetSecondaryDeviceType();
    if (!secDeviceType.empty()) {
        retCode = WifiP2PHalInterface::GetInstance().SetP2pSecondaryDeviceType(secDeviceType);
        if (retCode == WifiErrorNo::WIFI_HAL_OPT_FAILED) {
            WIFI_LOGE("Failed to set the secondary device type.");
        }
    }

    P2pConfigInitExt(result);

    if (!p2pStateMachine.groupManager.GetGroups().empty()) {
        p2pStateMachine.UpdateGroupInfoToWpa();
        std::vector<WifiP2pGroupInfo> groups;
        WifiSettings::GetInstance().SetWifiP2pGroupInfo(groups);
        WifiSettings::GetInstance().SyncWifiP2pGroupInfoConfig();
    }
    return result;
}

void P2pEnabledState::P2pConfigInitExt(bool &result)
{
    WifiErrorNo retCode = WifiP2PHalInterface::GetInstance().SetP2pConfigMethods(
        std::string("virtual_push_button physical_display keypad"));
    if (retCode == WifiErrorNo::WIFI_HAL_OPT_FAILED) {
        WIFI_LOGE("Failed to set the wps config methods.");
        result = false;
    }

    retCode = WifiP2PHalInterface::GetInstance().SetPersistentReconnect(1);
    if (retCode == WifiErrorNo::WIFI_HAL_OPT_FAILED) {
        WIFI_LOGE("Failed to set persistent reconnect.");
        result = false;
    }

    std::string deviceAddr;
    WifiP2PHalInterface::GetInstance().GetDeviceAddress(deviceAddr);
    if (retCode == WifiErrorNo::WIFI_HAL_OPT_FAILED) {
        WIFI_LOGE("Failed to obtain the device address.");
        result = false;
    }
    deviceManager.GetThisDevice().SetDeviceAddress(deviceAddr);
}

bool P2pEnabledState::P2pSettingsInitialization()
{
    WIFI_LOGI("Start P2pSettingsInitialization");

    bool result = P2pConfigInitialization();
    p2pStateMachine.UpdateOwnDevice(P2pDeviceStatus::PDS_AVAILABLE);

    WifiErrorNo retCode = WifiP2PHalInterface::GetInstance().P2pFlush();
    if (retCode == WifiErrorNo::WIFI_HAL_OPT_FAILED) {
        WIFI_LOGE("Failed to flush p2p.");
        result = false;
    }

    retCode = WifiP2PHalInterface::GetInstance().FlushService();
    if (retCode == WifiErrorNo::WIFI_HAL_OPT_FAILED) {
        WIFI_LOGE("Failed to flush p2p service.");
        result = false;
    }

    WIFI_LOGI("service discovery external is default.");
    retCode = WifiP2PHalInterface::GetInstance().SetServiceDiscoveryExternal(false);
    if (retCode == WifiErrorNo::WIFI_HAL_OPT_FAILED) {
        WIFI_LOGE("Failed to set service discovery external.");
        result = false;
    }

    p2pStateMachine.UpdateGroupManager();
    p2pStateMachine.UpdatePersistentGroups();
    return result;
}

bool P2pEnabledState::ProcessCmdAddLocalService(InternalMessagePtr msg) const
{
    WIFI_LOGI("p2p_enabled_state recv CMD_PUT_LOCAL_SERVICE");
    WifiP2pServiceInfo service;
    if (!msg->GetMessageObj(service)) {
        WIFI_LOGE("Failed to obtain WifiP2pServiceInfo information.");
        return EXECUTED;
    }
    if (!p2pStateMachine.serviceManager.AddLocalService(service)) {
        p2pStateMachine.BroadcastActionResult(P2pActionCallback::PutLocalP2pService, ErrCode::WIFI_OPT_FAILED);
        return EXECUTED;
    }
    WifiErrorNo retCode = WifiP2PHalInterface::GetInstance().P2pServiceAdd(service);
    if (retCode != WifiErrorNo::WIFI_HAL_OPT_OK) {
        p2pStateMachine.serviceManager.RemoveLocalService(service);
        p2pStateMachine.BroadcastActionResult(P2pActionCallback::PutLocalP2pService, ErrCode::WIFI_OPT_FAILED);
    } else {
        p2pStateMachine.BroadcastActionResult(P2pActionCallback::PutLocalP2pService, ErrCode::WIFI_OPT_SUCCESS);
    }
    return EXECUTED;
}
bool P2pEnabledState::ProcessCmdDelLocalService(InternalMessagePtr msg) const
{
    WIFI_LOGI("recv CMD: %{public}d", msg->GetMessageName());
    WifiP2pServiceInfo service;
    if (!msg->GetMessageObj(service)) {
        WIFI_LOGE("Failed to obtain WifiP2pServiceInfo information.");
        return EXECUTED;
    }
    p2pStateMachine.serviceManager.RemoveLocalService(service);

    WifiErrorNo retCode = WifiP2PHalInterface::GetInstance().P2pServiceRemove(service);
    if (retCode == WifiErrorNo::WIFI_HAL_OPT_OK) {
        p2pStateMachine.BroadcastActionResult(P2pActionCallback::DeleteLocalP2pService, ErrCode::WIFI_OPT_SUCCESS);
    } else {
        p2pStateMachine.BroadcastActionResult(P2pActionCallback::DeleteLocalP2pService, ErrCode::WIFI_OPT_FAILED);
    }
    return EXECUTED;
}

bool P2pEnabledState::ProcessCmdDiscServices(InternalMessagePtr msg) const
{
    WIFI_LOGI("P2P ProcessCmdDiscServices recv CMD: %{public}d", msg->GetMessageName());
    p2pStateMachine.CancelSupplicantSrvDiscReq();
    std::string reqId;
    WifiP2pServiceRequest request;
    WifiP2pDevice device;
    device.SetDeviceAddress(std::string("00:00:00:00:00:00"));
    request.SetProtocolType(P2pServicerProtocolType::SERVICE_TYPE_ALL);
    request.SetTransactionId(p2pStateMachine.serviceManager.GetTransId());

    p2pStateMachine.StopTimer(static_cast<int>(P2P_STATE_MACHINE_CMD::P2P_REMOVE_DEVICE));
    WifiErrorNo retCode =
        WifiP2PHalInterface::GetInstance().ReqServiceDiscovery(device.GetDeviceAddress(), request.GetTlv(), reqId);
    if (WifiErrorNo::WIFI_HAL_OPT_OK != retCode) {
        WIFI_LOGI("Failed to schedule the P2P service discovery request.");
        p2pStateMachine.BroadcastActionResult(P2pActionCallback::DiscoverServices, ErrCode::WIFI_OPT_FAILED);
        return EXECUTED;
    }
    p2pStateMachine.serviceManager.SetQueryId(reqId);

    retCode = WifiP2PHalInterface::GetInstance().P2pFind(DISC_TIMEOUT_S);
    if (retCode != WifiErrorNo::WIFI_HAL_OPT_OK) {
        WIFI_LOGE("call P2pFind failed, ErrorCode: %{public}d", static_cast<int>(retCode));
        p2pStateMachine.BroadcastActionResult(P2pActionCallback::DiscoverServices, ErrCode::WIFI_OPT_FAILED);
        return EXECUTED;
    }

    WIFI_LOGI("CMD_DISCOVER_SERVICES successful.");
    p2pStateMachine.BroadcastActionResult(P2pActionCallback::DiscoverServices, ErrCode::WIFI_OPT_SUCCESS);
    p2pStateMachine.BroadcastP2pDiscoveryChanged(true);
    return EXECUTED;
}

bool P2pEnabledState::ProcessCmdStopDiscServices(InternalMessagePtr msg) const
{
    WIFI_LOGI("P2P ProcessCmdStopDiscServices recv CMD: %{public}d", msg->GetMessageName());
    WifiErrorNo retCode = WifiP2PHalInterface::GetInstance().P2pStopFind();
    if (retCode == WifiErrorNo::WIFI_HAL_OPT_OK) {
        p2pStateMachine.BroadcastActionResult(P2pActionCallback::StopDiscoverServices, ErrCode::WIFI_OPT_SUCCESS);
    } else {
        p2pStateMachine.BroadcastActionResult(P2pActionCallback::StopDiscoverServices, ErrCode::WIFI_OPT_FAILED);
    }
    return EXECUTED;
}

bool P2pEnabledState::ProcessCmdRequestService(InternalMessagePtr msg) const
{
    std::pair<WifiP2pDevice, WifiP2pServiceRequest> info;
    if (!msg->GetMessageObj(info)) {
        WIFI_LOGE("Failed to obtain WifiP2pServiceRequest information.");
        return EXECUTED;
    }
    const WifiP2pDevice &device = info.first;
    const WifiP2pServiceRequest &request = info.second;

    p2pStateMachine.CancelSupplicantSrvDiscReq();

    std::string reqId;
    WifiErrorNo retCode =
        WifiP2PHalInterface::GetInstance().ReqServiceDiscovery(device.GetDeviceAddress(), request.GetTlv(), reqId);
    if (WifiErrorNo::WIFI_HAL_OPT_OK != retCode) {
        WIFI_LOGI("Failed to schedule the P2P service discovery request.");
        p2pStateMachine.BroadcastActionResult(P2pActionCallback::RequestService, ErrCode::WIFI_OPT_FAILED);
        return EXECUTED;
    }
    p2pStateMachine.serviceManager.SetQueryId(reqId);

    retCode = WifiP2PHalInterface::GetInstance().P2pFind(DISC_TIMEOUT_S);
    if (retCode != WifiErrorNo::WIFI_HAL_OPT_OK) {
        WIFI_LOGE("call P2pFind failed, ErrorCode: %{public}d", static_cast<int>(retCode));
        p2pStateMachine.BroadcastActionResult(P2pActionCallback::RequestService, ErrCode::WIFI_OPT_FAILED);
        return EXECUTED;
    }

    p2pStateMachine.BroadcastActionResult(P2pActionCallback::RequestService, ErrCode::WIFI_OPT_SUCCESS);
    return EXECUTED;
}

bool P2pEnabledState::ProcessServiceDiscReqEvt(InternalMessagePtr msg) const
{
    WIFI_LOGI("p2p_enabled_state recv P2P_EVENT_SERV_DISC_REQ");
    WifiP2pServiceRequestList reqList;
    if (!msg->GetMessageObj(reqList)) {
        WIFI_LOGE("Failed to obtain WifiP2pServiceRequestList information.");
        return EXECUTED;
    }

    const std::string deviceAddress = reqList.GetDevice().GetDeviceAddress();
    int dialogToken = reqList.GetDialogToken();
    if (p2pStateMachine.serviceManager.IsRecordedRequest(deviceAddress, dialogToken)) {
        return EXECUTED;
    } else {
        p2pStateMachine.serviceManager.AddRequestRecord(deviceAddress, dialogToken);
    }

    WifiP2pServiceResponseList respList = p2pStateMachine.serviceManager.ProcessServiceRequestList(reqList);
    if (respList.GetServiceResponseList().size() > 0) {
        if (WifiErrorNo::WIFI_HAL_OPT_OK != WifiP2PHalInterface::GetInstance().RespServiceDiscovery(
            respList.GetDevice(), respList.GetFrequency(), respList.GetDialogToken(), respList.GetTlvs())) {
            WIFI_LOGE("Failed to reply to the service response. deviceAddress: %{private}s, frequency "
                "%{public}d,dialogToken %{public}d",
                respList.GetDevice().GetDeviceAddress().c_str(), respList.GetFrequency(), respList.GetDialogToken());
        }
    } else {
        WIFI_LOGI("p2p service:Failed to reply to the message.");
    }

    std::any info = deviceAddress;
    p2pStateMachine.MessageExecutedLater(static_cast<int>(P2P_STATE_MACHINE_CMD::REMOVE_SERVICE_REQUEST_RECORD),
        dialogToken,
        0,
        info,
        REMOVE_SERVICE_REQUEST_RECORD);

    return EXECUTED;
}

bool P2pEnabledState::ProcessServiceDiscRspEvt(InternalMessagePtr msg) const
{
    WIFI_LOGI("p2p_enabled_state recv P2P_EVENT_SERV_DISC_RESP");
    WifiP2pServiceResponseList respList;
    if (!msg->GetMessageObj(respList)) {
        WIFI_LOGE("Failed to obtain WifiP2pServiceResponseList information.");
        return EXECUTED;
    }

    const std::vector<WifiP2pServiceResponse> list = respList.GetServiceResponseList();

    WifiP2pDevice dev = deviceManager.GetDevices(respList.GetDevice().GetDeviceAddress());
    for (auto iter = list.begin(); iter != list.end(); ++iter) {
        p2pStateMachine.HandleP2pServiceResp(*iter, dev);
    }
    return EXECUTED;
}
bool P2pEnabledState::ProcessExceptionTimeOut(InternalMessagePtr msg) const
{
    WIFI_LOGI("recv exception timeout event: %{public}d", msg->GetMessageName());
    p2pStateMachine.SwitchState(&p2pStateMachine.p2pIdleState);
    return EXECUTED;
}

bool P2pEnabledState::ProcessCmdSetDeviceName(InternalMessagePtr msg) const
{
    WIFI_LOGI("p2p_enabled_state CMD: set device name.");
    std::string deviceName;
    if (!msg->GetMessageObj(deviceName)) {
        LOGE("Failed to obtain string information.");
        return EXECUTED;
    }

    WifiErrorNo retCode = WifiP2PHalInterface::GetInstance().SetP2pDeviceName(deviceName);
    if (retCode == WifiErrorNo::WIFI_HAL_OPT_FAILED) {
        WIFI_LOGE("Failed to set the device name.");
        p2pStateMachine.BroadcastActionResult(P2pActionCallback::P2pSetDeviceName, WIFI_OPT_FAILED);
        return EXECUTED;
    } else {
        WIFI_LOGE("Successfully set the device name.");
        deviceManager.GetThisDevice().SetDeviceName(deviceName);
        p2pStateMachine.BroadcastThisDeviceChanaged(deviceManager.GetThisDevice());
        p2pStateMachine.BroadcastActionResult(P2pActionCallback::P2pSetDeviceName, WIFI_OPT_SUCCESS);
    }

    const std::string ssidPostfixName = std::string("-") + deviceName;
    retCode = WifiP2PHalInterface::GetInstance().SetP2pSsidPostfix(ssidPostfixName);
    if (retCode == WifiErrorNo::WIFI_HAL_OPT_FAILED) {
        WIFI_LOGE("Failed to set the SSID prefix");
    }
    return EXECUTED;
}
bool P2pEnabledState::ProcessCmdSetWfdInfo(InternalMessagePtr msg) const
{
    WIFI_LOGI("P2P ProcessCmdSetWfdInfo recv CMD: %{public}d", msg->GetMessageName());
    WifiP2pWfdInfo wfdInfo;
    if (!msg->GetMessageObj(wfdInfo)) {
        WIFI_LOGE("Failed to obtain wfd information.");
        return EXECUTED;
    }

    std::string subelement;
    wfdInfo.GetDeviceInfoElement(subelement);
    subelement = "0 " + subelement;
    if (WifiP2PHalInterface::GetInstance().SetWfdDeviceConfig(subelement) != WifiErrorNo::WIFI_HAL_OPT_OK) {
        WIFI_LOGE("Failed to set wfd config:%{public}s.", subelement.c_str());
        return EXECUTED;
    }
    if (WifiP2PHalInterface::GetInstance().SetWfdEnable(wfdInfo.GetWfdEnabled()) != WifiErrorNo::WIFI_HAL_OPT_OK) {
        WIFI_LOGE("Set wifidisplay enabled failed.");
        return EXECUTED;
    }
    return EXECUTED;
}

bool P2pEnabledState::ProcessCmdCancelConnect(InternalMessagePtr msg) const
{
    WIFI_LOGI("P2P ProcessCmdCancelConnect recv CMD: %{public}d", msg->GetMessageName());
    p2pStateMachine.BroadcastActionResult(P2pActionCallback::P2pCancelConnect, ErrCode::WIFI_OPT_FAILED);
    return EXECUTED;
}
bool P2pEnabledState::ProcessCmdConnectFailed(InternalMessagePtr msg) const
{
    WIFI_LOGI("P2P ProcessCmdConnectFailed recv CMD: %{public}d", msg->GetMessageName());
    constexpr int connectFailed = 2;
    constexpr int connectTimeout = 15;
    WifiP2pDevice device;
    if (!msg->GetMessageObj(device)) {
        WIFI_LOGE("Failed to obtain device information.");
        return EXECUTED;
    }
    if (msg->GetParam1() == connectFailed || msg->GetParam1() == connectTimeout) {
        WIFI_LOGD("P2P ProcessCmdConnectFailed: filed reason = %{public}d", msg->GetParam1());
        p2pStateMachine.RemoveGroupByDevice(device);
    }
    return EXECUTED;
}

static int AddScanChannelInTimeout(uint32_t channelid, uint32_t timeout)
{
    int ret = (channelid << CHANNEL_INDEX_OF_DISCOVER) + (timeout & TIMEOUT_MASK_OF_DISCOVER);
    WIFI_LOGD("AddScanChannelInTimeout result = %{public}d", ret);
    return ret;
}

bool P2pEnabledState::ProcessCmdDiscoverPeers(InternalMessagePtr msg) const
{
    WIFI_LOGI("P2P ProcessCmdDiscoverPeers recv CMD: %{public}d", msg->GetMessageName());
    const int channelid = msg->GetParam1();
    WifiP2PHalInterface::GetInstance().DeliverP2pData(CMD_TYPE_SET, DATA_TYPE_SET_LISTEN_MODE, ONEHOP_LISTEN_MODE);
    p2pStateMachine.CancelSupplicantSrvDiscReq();
    int ret = AddScanChannelInTimeout(channelid, DISCOVER_TIMEOUT_S);
    int retCode = WifiP2PHalInterface::GetInstance().P2pFind(ret);
    if (retCode != WifiErrorNo::WIFI_HAL_OPT_OK) {
        WIFI_LOGE("call ProcessCmdDiscoverPeers failed, ErrorCode: %{public}d", static_cast<int>(retCode));
        WifiP2PHalInterface::GetInstance().P2pStopFind();
        return NOT_EXECUTED;
    } else {
        p2pStateMachine.BroadcastActionResult(P2pActionCallback::DiscoverPeers, ErrCode::WIFI_OPT_SUCCESS);
        p2pStateMachine.BroadcastP2pDiscoveryChanged(true);
        return EXECUTED;
    }
    return EXECUTED;
}

bool P2pEnabledState::ProcessCmdIncreaseSharedLink(InternalMessagePtr msg) const
{
    int callingUid = msg->GetParam1();
    WIFI_LOGI("Uid %{public}d increaseSharedLink", callingUid);
    SharedLinkManager::IncreaseSharedLink(callingUid);
    return EXECUTED;
}

bool P2pEnabledState::ProcessCmdDecreaseSharedLink(InternalMessagePtr msg) const
{
    int callingUid = msg->GetParam1();
    WIFI_LOGI("Uid %{public}d decreaseSharedLink", callingUid);
    SharedLinkManager::DecreaseSharedLink(callingUid);
    if (SharedLinkManager::GetSharedLinkCount() == 0) {
        p2pStateMachine.SendMessage(static_cast<int>(P2P_STATE_MACHINE_CMD::CMD_REMOVE_GROUP));
    }
    return EXECUTED;
}

bool P2pEnabledState::ProcessChrReport(InternalMessagePtr msg) const
{
    int errCode = msg->GetParam1();
    WIFI_LOGI("P2pEnabledState receive chr error code %{public}d", errCode);
    WifiP2pDevice device = deviceManager.GetThisDevice();
    device.SetChrErrCode(static_cast<P2pChrEvent>(errCode));
    p2pStateMachine.BroadcastThisDeviceChanaged(device);
    return EXECUTED;
}

bool P2pEnabledState::ProcessSetMiracastSinkConfig(InternalMessagePtr msg) const
{
    WIFI_LOGI("P2pEnabledState receive set sink config");
    std::string config;
    if (!msg->GetMessageObj(config)) {
        WIFI_LOGE("Failed to obtain string information");
        return EXECUTED;
    }
    WifiP2PHalInterface::GetInstance().SetMiracastSinkConfig(config);
    return EXECUTED;
}
} // namespace Wifi
} // namespace OHOS
