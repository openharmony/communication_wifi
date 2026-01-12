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

#include "wifihotspotstub_fuzzer.h"
#include "wifi_fuzz_common_func.h"

#include <cstddef>
#include <cstdint>
#include <unistd.h>
#include "wifi_hotspot_stub.h"
#include "wifi_device_stub.h"
#include "wifi_device_service_impl.h"
#include "message_parcel.h"
#include "securec.h"
#include "define.h"
#include "wifi_manager_service_ipc_interface_code.h"
#include "wifi_hotspot_service_impl.h"
#include "wifi_hotspot_mgr_stub.h"
#include "wifi_hotspot_mgr_service_impl.h"
#include "wifi_log.h"
#include <mutex>
#include "wifi_config_center.h"
#include "wifi_settings.h"
#include "wifi_common_def.h"
#include "wifi_manager.h"
#include "wifi_net_agent.h"
#include <fuzzer/FuzzedDataProvider.h>

namespace OHOS {
namespace Wifi {
constexpr size_t U32_AT_SIZE_ZERO = 4;
constexpr int THREE = 8;
constexpr int TWO = 2;
const std::u16string FORMMGR_INTERFACE_TOKEN = u"ohos.wifi.IWifiHotspotService";
const std::u16string FORMMGR_INTERFACE_TOKEN_DEVICE = u"ohos.wifi.IWifiDeviceService";
const std::u16string FORMMGR_INTERFACE_TOKEN_HOSPOT_EX = u"ohos.wifi.IWifiHotspotMgr";
static bool g_isInsted = false;
static std::mutex g_instanceLock;
std::shared_ptr<WifiDeviceStub> pWifiDeviceStub = std::make_shared<WifiDeviceServiceImpl>();
std::shared_ptr<WifiHotspotStub> pWifiHotspotServiceImpl = std::make_shared<WifiHotspotServiceImpl>();
sptr<WifiHotspotMgrStub> pWifiHotspotMgrStub = WifiHotspotMgrServiceImpl::GetInstance();
static std::unique_ptr<WifiHotspotServiceImpl> mWifiHotspotServiceImpl = nullptr;
FuzzedDataProvider *FDP = nullptr;
static const int32_t NUM_BYTES = 1;
bool Init()
{
    if (!g_isInsted) {
        if (WifiConfigCenter::GetInstance().GetApMidState(0) != WifiOprMidState::RUNNING) {
            LOGE("Init setmidstate!");
            WifiConfigCenter::GetInstance().SetApMidState(WifiOprMidState::RUNNING, 0);
        }
        g_isInsted = true;
    }
    return true;
}

bool OnRemoteRequest(uint32_t code, MessageParcel &data)
{
    std::unique_lock<std::mutex> autoLock(g_instanceLock);
    if (!g_isInsted) {
        if (!Init()) {
            LOGE("OnRemoteRequest Init failed!");
            return false;
        }
    }
    MessageParcel reply;
    MessageOption option;
    pWifiHotspotServiceImpl->OnRemoteRequest(code, data, reply, option);
    return true;
}

void OnIsHotspotActiveFuzzTest()
{
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN)) {
        LOGE("WriteInterfaceToken failed!");
        return;
    }
    int32_t tmpInt = FDP->ConsumeIntegral<int32_t>();
    std::string tmpBuffer = FDP->ConsumeBytesAsString(NUM_BYTES);
    datas.WriteInt32(tmpInt);
    datas.WriteBuffer(tmpBuffer.c_str(), tmpBuffer.size());
    OnRemoteRequest(static_cast<uint32_t>(HotspotInterfaceCode::WIFI_SVR_CMD_IS_HOTSPOT_ACTIVE), datas);
}

void OnGetApStateWifiFuzzTest()
{
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN)) {
        LOGE("WriteInterfaceToken failed!");
        return;
    }
    int32_t tmpInt = FDP->ConsumeIntegral<int32_t>();
    std::string tmpBuffer = FDP->ConsumeBytesAsString(NUM_BYTES);
    datas.WriteInt32(tmpInt);
    datas.WriteBuffer(tmpBuffer.c_str(), tmpBuffer.size());
    OnRemoteRequest(static_cast<uint32_t>(HotspotInterfaceCode::WIFI_SVR_CMD_GETAPSTATE_WIFI), datas);
}

void OnGetHotspotConfigFuzzTest()
{
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN)) {
        LOGE("WriteInterfaceToken failed!");
        return;
    }
    int32_t tmpInt = FDP->ConsumeIntegral<int32_t>();
    std::string tmpBuffer = FDP->ConsumeBytesAsString(NUM_BYTES);
    datas.WriteInt32(tmpInt);
    datas.WriteBuffer(tmpBuffer.c_str(), tmpBuffer.size());
    OnRemoteRequest(static_cast<uint32_t>(HotspotInterfaceCode::WIFI_SVR_CMD_GET_HOTSPOT_CONFIG), datas);
}

void OnSetApConfigWifiFuzzTest()
{
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN)) {
        LOGE("WriteInterfaceToken failed!");
        return;
    }
    int32_t tmpInt = FDP->ConsumeIntegral<int32_t>();
    std::string tmpBuffer = FDP->ConsumeBytesAsString(NUM_BYTES);
    datas.WriteInt32(tmpInt);
    datas.WriteBuffer(tmpBuffer.c_str(), tmpBuffer.size());
    OnRemoteRequest(static_cast<uint32_t>(HotspotInterfaceCode::WIFI_SVR_CMD_SETAPCONFIG_WIFI), datas);
}

void OnGetStationListFuzzTest()
{
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN)) {
        LOGE("WriteInterfaceToken failed!");
        return;
    }
    int32_t tmpInt = FDP->ConsumeIntegral<int32_t>();
    std::string tmpBuffer = FDP->ConsumeBytesAsString(NUM_BYTES);
    datas.WriteInt32(tmpInt);
    datas.WriteBuffer(tmpBuffer.c_str(), tmpBuffer.size());
    OnRemoteRequest(static_cast<uint32_t>(HotspotInterfaceCode::WIFI_SVR_CMD_GET_STATION_LIST), datas);
}

void OnAddBlockListFuzzTest()
{
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN)) {
        LOGE("WriteInterfaceToken failed!");
        return;
    }
    int32_t tmpInt = FDP->ConsumeIntegral<int32_t>();
    std::string tmpBuffer = FDP->ConsumeBytesAsString(NUM_BYTES);
    datas.WriteInt32(tmpInt);
    datas.WriteBuffer(tmpBuffer.c_str(), tmpBuffer.size());
    OnRemoteRequest(static_cast<uint32_t>(HotspotInterfaceCode::WIFI_SVR_CMD_ADD_BLOCK_LIST), datas);
}

void OnDelBlockListFuzzTest()
{
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN)) {
        LOGE("WriteInterfaceToken failed!");
        return;
    }
    int32_t tmpInt = FDP->ConsumeIntegral<int32_t>();
    std::string tmpBuffer = FDP->ConsumeBytesAsString(NUM_BYTES);
    datas.WriteInt32(tmpInt);
    datas.WriteBuffer(tmpBuffer.c_str(), tmpBuffer.size());
    OnRemoteRequest(static_cast<uint32_t>(HotspotInterfaceCode::WIFI_SVR_CMD_DEL_BLOCK_LIST), datas);
}

void OnGetBlockListsFuzzTest()
{
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN)) {
        LOGE("WriteInterfaceToken failed!");
        return;
    }
    int32_t tmpInt = FDP->ConsumeIntegral<int32_t>();
    std::string tmpBuffer = FDP->ConsumeBytesAsString(NUM_BYTES);
    datas.WriteInt32(tmpInt);
    datas.WriteBuffer(tmpBuffer.c_str(), tmpBuffer.size());
    OnRemoteRequest(static_cast<uint32_t>(HotspotInterfaceCode::WIFI_SVR_CMD_GET_BLOCK_LISTS), datas);
}

void OnGetValidBandsFuzzTest()
{
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN)) {
        LOGE("WriteInterfaceToken failed!");
        return;
    }
    int32_t tmpInt = FDP->ConsumeIntegral<int32_t>();
    std::string tmpBuffer = FDP->ConsumeBytesAsString(NUM_BYTES);
    datas.WriteInt32(tmpInt);
    datas.WriteBuffer(tmpBuffer.c_str(), tmpBuffer.size());
    OnRemoteRequest(static_cast<uint32_t>(HotspotInterfaceCode::WIFI_SVR_CMD_GET_VALID_BANDS), datas);
}

void OnDisassociateStaFuzzTest()
{
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN)) {
        LOGE("WriteInterfaceToken failed!");
        return;
    }
    int32_t tmpInt = FDP->ConsumeIntegral<int32_t>();
    std::string tmpBuffer = FDP->ConsumeBytesAsString(NUM_BYTES);
    datas.WriteInt32(tmpInt);
    datas.WriteBuffer(tmpBuffer.c_str(), tmpBuffer.size());
    OnRemoteRequest(static_cast<uint32_t>(HotspotInterfaceCode::WIFI_SVR_CMD_DISCONNECT_STA), datas);
}

void OnGetValidChannelsFuzzTest()
{
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN)) {
        LOGE("WriteInterfaceToken failed!");
        return;
    }
    int32_t tmpInt = FDP->ConsumeIntegral<int32_t>();
    std::string tmpBuffer = FDP->ConsumeBytesAsString(NUM_BYTES);
    datas.WriteInt32(tmpInt);
    datas.WriteBuffer(tmpBuffer.c_str(), tmpBuffer.size());
    OnRemoteRequest(static_cast<uint32_t>(HotspotInterfaceCode::WIFI_SVR_CMD_GET_VALID_CHANNELS), datas);
}

void OnRegisterCallBackFuzzTest()
{
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN)) {
        LOGE("WriteInterfaceToken failed!");
        return;
    }
    int32_t tmpInt = FDP->ConsumeIntegral<int32_t>();
    std::string tmpBuffer = FDP->ConsumeBytesAsString(NUM_BYTES);
    datas.WriteInt32(tmpInt);
    datas.WriteBuffer(tmpBuffer.c_str(), tmpBuffer.size());
    OnRemoteRequest(static_cast<uint32_t>(HotspotInterfaceCode::WIFI_SVR_CMD_REGISTER_HOTSPOT_CALLBACK), datas);
}

void OnGetSupportedPowerModelFuzzTest()
{
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN)) {
        LOGE("WriteInterfaceToken failed!");
        return;
    }
    int32_t tmpInt = FDP->ConsumeIntegral<int32_t>();
    std::string tmpBuffer = FDP->ConsumeBytesAsString(NUM_BYTES);
    datas.WriteInt32(tmpInt);
    datas.WriteBuffer(tmpBuffer.c_str(), tmpBuffer.size());
    OnRemoteRequest(static_cast<uint32_t>(HotspotInterfaceCode::WIFI_SVR_CMD_GET_SUPPORTED_POWER_MODEL), datas);
}

void OnGetPowerModelFuzzTest()
{
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN)) {
        LOGE("WriteInterfaceToken failed!");
        return;
    }
    int32_t tmpInt = FDP->ConsumeIntegral<int32_t>();
    std::string tmpBuffer = FDP->ConsumeBytesAsString(NUM_BYTES);
    datas.WriteInt32(tmpInt);
    datas.WriteBuffer(tmpBuffer.c_str(), tmpBuffer.size());
    OnRemoteRequest(static_cast<uint32_t>(HotspotInterfaceCode::WIFI_SVR_CMD_GET_POWER_MODEL), datas);
}

void OnSetPowerModelFuzzTest()
{
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN)) {
        LOGE("WriteInterfaceToken failed!");
        return;
    }
    int32_t tmpInt = FDP->ConsumeIntegral<int32_t>();
    std::string tmpBuffer = FDP->ConsumeBytesAsString(NUM_BYTES);
    datas.WriteInt32(tmpInt);
    datas.WriteBuffer(tmpBuffer.c_str(), tmpBuffer.size());
    OnRemoteRequest(static_cast<uint32_t>(HotspotInterfaceCode::WIFI_SVR_CMD_SET_POWER_MODEL), datas);
}

void OnIsHotspotDualBandSupportedFuzzTest()
{
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN)) {
        LOGE("WriteInterfaceToken failed!");
        return;
    }
    int32_t tmpInt = FDP->ConsumeIntegral<int32_t>();
    std::string tmpBuffer = FDP->ConsumeBytesAsString(NUM_BYTES);
    datas.WriteInt32(tmpInt);
    datas.WriteBuffer(tmpBuffer.c_str(), tmpBuffer.size());
    OnRemoteRequest(static_cast<uint32_t>(HotspotInterfaceCode::WIFI_SVR_CMD_IS_HOTSPOT_DUAL_BAND_SUPPORTED), datas);
}

void OnIsOpenSoftApAllowedFuzzTest()
{
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN)) {
        LOGE("WriteInterfaceToken failed!");
        return;
    }
    int32_t tmpInt = FDP->ConsumeIntegral<int32_t>();
    std::string tmpBuffer = FDP->ConsumeBytesAsString(NUM_BYTES);
    datas.WriteInt32(tmpInt);
    datas.WriteBuffer(tmpBuffer.c_str(), tmpBuffer.size());
    OnRemoteRequest(static_cast<uint32_t>(HotspotInterfaceCode::WIFI_SVR_CMD_IS_HOTSPOT_SUPPORTED), datas);
}

void OnSetApIdleTimeoutFuzzTest()
{
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN)) {
        LOGE("WriteInterfaceToken failed!");
        return;
    }
    int32_t tmpInt = FDP->ConsumeIntegral<int32_t>();
    std::string tmpBuffer = FDP->ConsumeBytesAsString(NUM_BYTES);
    datas.WriteInt32(tmpInt);
    datas.WriteBuffer(tmpBuffer.c_str(), tmpBuffer.size());
    OnRemoteRequest(static_cast<uint32_t>(HotspotInterfaceCode::WIFI_SVR_CMD_SETTIMEOUT_AP), datas);
}

void OnGetApIfaceNameFuzzTest()
{
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN)) {
        LOGE("WriteInterfaceToken failed!");
        return;
    }
    int32_t tmpInt = FDP->ConsumeIntegral<int32_t>();
    std::string tmpBuffer = FDP->ConsumeBytesAsString(NUM_BYTES);
    datas.WriteInt32(tmpInt);
    datas.WriteBuffer(tmpBuffer.c_str(), tmpBuffer.size());
    OnRemoteRequest(static_cast<uint32_t>(HotspotInterfaceCode::WIFI_SVR_CMD_GET_IFACE_NAME), datas);
}

void OnEnableWifiApTest()
{
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN)) {
        LOGE("WriteInterfaceToken failed!");
        return;
    }
    int32_t tmpInt = FDP->ConsumeIntegral<int32_t>();
    std::string tmpBuffer = FDP->ConsumeBytesAsString(NUM_BYTES);
    datas.WriteInt32(tmpInt);
    datas.WriteBuffer(tmpBuffer.c_str(), tmpBuffer.size());
    OnRemoteRequest(static_cast<uint32_t>(HotspotInterfaceCode::WIFI_SVR_CMD_ENABLE_WIFI_AP), datas);
}

void OnDisableWifiApTest()
{
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN)) {
        LOGE("WriteInterfaceToken failed!");
        return;
    }
    int32_t tmpInt = FDP->ConsumeIntegral<int32_t>();
    std::string tmpBuffer = FDP->ConsumeBytesAsString(NUM_BYTES);
    datas.WriteInt32(tmpInt);
    datas.WriteBuffer(tmpBuffer.c_str(), tmpBuffer.size());
    OnRemoteRequest(static_cast<uint32_t>(HotspotInterfaceCode::WIFI_SVR_CMD_DISABLE_WIFI_AP), datas);
}

void OnEnableWifiFuzzTest()
{
    MessageParcel datas;
    datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN_DEVICE);
    int32_t tmpInt = FDP->ConsumeIntegral<int32_t>();
    std::string tmpBuffer = FDP->ConsumeBytesAsString(NUM_BYTES);
    datas.WriteInt32(tmpInt);
    datas.WriteBuffer(tmpBuffer.c_str(), tmpBuffer.size());
    MessageParcel reply;
    MessageOption option;
    pWifiDeviceStub->OnRemoteRequest(static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_ENABLE_WIFI),
        datas, reply, option);
}

void OnDisableWifiFuzzTest()
{
    MessageParcel datas;
    datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN_DEVICE);
    int32_t tmpInt = FDP->ConsumeIntegral<int32_t>();
    std::string tmpBuffer = FDP->ConsumeBytesAsString(NUM_BYTES);
    datas.WriteInt32(tmpInt);
    datas.WriteBuffer(tmpBuffer.c_str(), tmpBuffer.size());
    MessageParcel reply;
    MessageOption option;
    pWifiDeviceStub->OnRemoteRequest(static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_DISABLE_WIFI),
        datas, reply, option);
}

void OnGetSupportedFeaturesFuzzTest()
{
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN)) {
        LOGE("WriteInterfaceToken failed!");
        return;
    }
    int32_t tmpInt = FDP->ConsumeIntegral<int32_t>();
    std::string tmpBuffer = FDP->ConsumeBytesAsString(NUM_BYTES);
    datas.WriteInt32(tmpInt);
    datas.WriteBuffer(tmpBuffer.c_str(), tmpBuffer.size());
    OnRemoteRequest(static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_GET_SUPPORTED_FEATURES), datas);
}

bool DoSomethingHotSpotMgrStubTest()
{
    uint32_t code = static_cast<uint32_t>(HotspotInterfaceCode::WIFI_MGR_GET_HOTSPOT_SERVICE);
    MessageParcel datas;
    datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN_HOSPOT_EX);
    int32_t tmpInt = FDP->ConsumeIntegral<int32_t>();
    std::string tmpBuffer = FDP->ConsumeBytesAsString(NUM_BYTES);
    datas.WriteInt32(tmpInt);
    datas.WriteBuffer(tmpBuffer.c_str(), tmpBuffer.size());
    datas.RewindRead(0);
    MessageParcel reply;
    MessageOption option;
    pWifiHotspotMgrStub->OnRemoteRequest(code, datas, reply, option);
    return true;
}

void WifiHotspotServiceImplFuzzTest()
{
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN_HOSPOT_EX)) {
        LOGE("WriteInterfaceToken failed!");
        return;
    }

    int32_t randomInt = FDP->ConsumeIntegral<int32_t>();
    KeyMgmt type = static_cast<KeyMgmt>(randomInt % THREE);
    BandType newBand = static_cast<BandType>(randomInt % U32_AT_SIZE_ZERO);
    int32_t channelid = FDP->ConsumeIntegral<int32_t>();

    std::string primaryDeviceType = FDP->ConsumeBytesAsString(NUM_BYTES);
    std::string secondaryDeviceType = FDP->ConsumeBytesAsString(NUM_BYTES);

    std::vector<BandType> bandsFromCenter;
    bandsFromCenter.push_back(newBand);

    HotspotConfig config;
    StationInfo updateInfo;

    std::string deviceName = FDP->ConsumeBytesAsString(NUM_BYTES);
    std::string networkName = FDP->ConsumeBytesAsString(NUM_BYTES);
    std::string mDeviceAddress = FDP->ConsumeBytesAsString(NUM_BYTES);

    config.SetSsid(deviceName);
    config.SetPreSharedKey(networkName);
    config.SetSecurityType(type);
    config.SetBand(newBand);
    config.SetBandWidth(channelid);
    config.SetChannel(channelid);
    config.SetMaxConn(channelid);
    config.SetIpAddress(mDeviceAddress);

    updateInfo.deviceName = deviceName;
    updateInfo.bssid = networkName;
    updateInfo.ipAddr = mDeviceAddress;
    updateInfo.bssidType = FDP->ConsumeIntegral<int32_t>();

    mWifiHotspotServiceImpl->SetHotspotConfig(config);
    mWifiHotspotServiceImpl->TransRandomToRealMac(updateInfo, updateInfo);
    mWifiHotspotServiceImpl->ConfigInfoDump(primaryDeviceType);
    mWifiHotspotServiceImpl->StationsInfoDump(secondaryDeviceType);
    mWifiHotspotServiceImpl->SaBasicDump(secondaryDeviceType);
    mWifiHotspotServiceImpl->CfgCheckSsid(config);
    mWifiHotspotServiceImpl->CfgCheckPsk(config);
    mWifiHotspotServiceImpl->CfgCheckBand(config, bandsFromCenter);
    mWifiHotspotServiceImpl->CfgCheckIpAddress(secondaryDeviceType);
    mWifiHotspotServiceImpl->IsValidHotspotConfig(config, config, bandsFromCenter);
}

void WifiHotspotServiceImplFuzzTest02()
{
    HotspotConfigParcel parcelconfig;
    bool bActive = FDP->ConsumeBool();
    int state = FDP->ConsumeIntegral<int>();
    std::vector<StationInfoParcel> parcelResult;
    mWifiHotspotServiceImpl->IsHotspotActive(bActive);
    mWifiHotspotServiceImpl->GetHotspotState(state);
    mWifiHotspotServiceImpl->GetHotspotConfig(parcelconfig);
    HotspotConfigParcel parcelresult;
    mWifiHotspotServiceImpl->GetLocalOnlyHotspotConfig(parcelresult);
    mWifiHotspotServiceImpl->VerifyGetStationListPermission();
    mWifiHotspotServiceImpl->GetStationList(parcelResult);
    ServiceType type = static_cast<ServiceType>(FDP->ConsumeIntegral<int>() % TWO);
    mWifiHotspotServiceImpl->CheckCanEnableHotspot(type);
    mWifiHotspotServiceImpl->CheckOperHotspotSwitchPermission(type);
    ServiceTypeParcel parcelType{};
    mWifiHotspotServiceImpl->EnableHotspot(parcelType);
    mWifiHotspotServiceImpl->DisableHotspot(parcelType);
    mWifiHotspotServiceImpl->EnableLocalOnlyHotspot(parcelType);
    HotspotModeParcel parcelMode{};
    mWifiHotspotServiceImpl->GetHotspotMode(parcelMode);
}

void WifiHotspotServiceImplFuzzTest03()
{
    int64_t features = FDP->ConsumeIntegral<int64_t>();
    std::vector<BandTypeParcel> parcelBands;
    std::vector<int32_t> validchannels;
    std::vector<StationInfo> infos;
    const sptr<IRemoteObject> cbParcel;
    std::vector<std::string> event;
    BandTypeParcel parcelBand{};
    mWifiHotspotServiceImpl->GetValidBands(parcelBands);
    mWifiHotspotServiceImpl->GetValidChannels(parcelBand, validchannels);
    #ifdef SUPPORT_RANDOM_MAC_ADDR
    mWifiHotspotServiceImpl->ProcessMacAddressRandomization(infos);
    #endif
    std::vector<StationInfoParcel> parcelInfos;
    mWifiHotspotServiceImpl->GetBlockLists(parcelInfos);
    mWifiHotspotServiceImpl->IsApServiceRunning();
    mWifiHotspotServiceImpl->IsRptRunning();
    mWifiHotspotServiceImpl->RegisterCallBack(cbParcel, event);
    mWifiHotspotServiceImpl->GetSupportedFeatures(features);
}

void WifiHotspotServiceImplFuzzTest04()
{
    std::set<PowerModelParcel> parcelPowerModelSet;
    std::string result = FDP->ConsumeBytesAsString(NUM_BYTES);
    mWifiHotspotServiceImpl->GetSupportedPowerModel(parcelPowerModelSet);
    PowerModelParcel parcelModel;
    mWifiHotspotServiceImpl->GetPowerModel(parcelModel);
    mWifiHotspotServiceImpl->ConfigInfoDump(result);
    mWifiHotspotServiceImpl->StationsInfoDump(result);
}

void WifiHotspotServiceImplFuzzTest05()
{
    std::string result = FDP->ConsumeBytesAsString(NUM_BYTES);
    std::string ifaceName = FDP->ConsumeBytesAsString(NUM_BYTES);
    mWifiHotspotServiceImpl->SaBasicDump(result);
    mWifiHotspotServiceImpl->GetApIfaceName(ifaceName);
}


void WifiHotSpotStubFuzzTest()
{
    Init();
    OHOS::Wifi::OnIsHotspotActiveFuzzTest();
    OHOS::Wifi::OnGetApStateWifiFuzzTest();
    OHOS::Wifi::OnGetHotspotConfigFuzzTest();
    OHOS::Wifi::OnSetApConfigWifiFuzzTest();
    OHOS::Wifi::OnGetStationListFuzzTest();
    OHOS::Wifi::OnAddBlockListFuzzTest();
    OHOS::Wifi::OnDelBlockListFuzzTest();
    OHOS::Wifi::OnGetBlockListsFuzzTest();
    OHOS::Wifi::OnDisassociateStaFuzzTest();
    OHOS::Wifi::OnGetValidBandsFuzzTest();
    OHOS::Wifi::OnGetValidChannelsFuzzTest();
    OHOS::Wifi::OnRegisterCallBackFuzzTest();
    OHOS::Wifi::OnGetSupportedPowerModelFuzzTest();
    OHOS::Wifi::OnGetPowerModelFuzzTest();
    OHOS::Wifi::OnSetPowerModelFuzzTest();
    OHOS::Wifi::OnIsHotspotDualBandSupportedFuzzTest();
    OHOS::Wifi::OnIsOpenSoftApAllowedFuzzTest();
    OHOS::Wifi::OnSetApIdleTimeoutFuzzTest();
    OHOS::Wifi::OnGetApIfaceNameFuzzTest();
    OHOS::Wifi::OnGetSupportedFeaturesFuzzTest();
    OHOS::Wifi::WifiHotspotServiceImplFuzzTest();
    OHOS::Wifi::DoSomethingHotSpotMgrStubTest();
    OHOS::Wifi::WifiHotspotServiceImplFuzzTest02();
    OHOS::Wifi::WifiHotspotServiceImplFuzzTest03();
    OHOS::Wifi::WifiHotspotServiceImplFuzzTest04();
    OHOS::Wifi::WifiHotspotServiceImplFuzzTest05();
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    OHOS::Wifi::FDP = &fdp;
    OHOS::Wifi::WifiHotSpotStubFuzzTest();
    return 0;
}
}
}
