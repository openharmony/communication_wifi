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

namespace OHOS {
namespace Wifi {
constexpr size_t U32_AT_SIZE_ZERO = 4;
constexpr int THREE = 8;
const std::u16string FORMMGR_INTERFACE_TOKEN = u"ohos.wifi.IWifiHotspotService";
const std::u16string FORMMGR_INTERFACE_TOKEN_DEVICE = u"ohos.wifi.IWifiDeviceService";
const std::u16string FORMMGR_INTERFACE_TOKEN_HOSPOT_EX = u"ohos.wifi.IWifiHotspotMgr";
static bool g_isInsted = false;
static std::mutex g_instanceLock;
std::shared_ptr<WifiDeviceStub> pWifiDeviceStub = std::make_shared<WifiDeviceServiceImpl>();
std::shared_ptr<WifiHotspotStub> pWifiHotspotServiceImpl = std::make_shared<WifiHotspotServiceImpl>();
sptr<WifiHotspotMgrStub> pWifiHotspotMgrStub = WifiHotspotMgrServiceImpl::GetInstance();

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

void OnIsHotspotActiveFuzzTest(const uint8_t* data, size_t size)
{
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN)) {
        LOGE("WriteInterfaceToken failed!");
        return;
    }
    datas.WriteInt32(0);
    datas.WriteBuffer(data, size);
    OnRemoteRequest(static_cast<uint32_t>(HotspotInterfaceCode::WIFI_SVR_CMD_IS_HOTSPOT_ACTIVE), datas);
}

void OnGetApStateWifiFuzzTest(const uint8_t* data, size_t size)
{
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN)) {
        LOGE("WriteInterfaceToken failed!");
        return;
    }
    datas.WriteInt32(0);
    datas.WriteBuffer(data, size);
    OnRemoteRequest(static_cast<uint32_t>(HotspotInterfaceCode::WIFI_SVR_CMD_GETAPSTATE_WIFI), datas);
}

void OnGetHotspotConfigFuzzTest(const uint8_t* data, size_t size)
{
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN)) {
        LOGE("WriteInterfaceToken failed!");
        return;
    }
    datas.WriteInt32(0);
    datas.WriteBuffer(data, size);
    OnRemoteRequest(static_cast<uint32_t>(HotspotInterfaceCode::WIFI_SVR_CMD_GET_HOTSPOT_CONFIG), datas);
}

void OnSetApConfigWifiFuzzTest(const uint8_t* data, size_t size)
{
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN)) {
        LOGE("WriteInterfaceToken failed!");
        return;
    }
    datas.WriteInt32(0);
    datas.WriteBuffer(data, size);
    OnRemoteRequest(static_cast<uint32_t>(HotspotInterfaceCode::WIFI_SVR_CMD_SETAPCONFIG_WIFI), datas);
}

void OnGetStationListFuzzTest(const uint8_t* data, size_t size)
{
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN)) {
        LOGE("WriteInterfaceToken failed!");
        return;
    }
    datas.WriteInt32(0);
    datas.WriteBuffer(data, size);
    OnRemoteRequest(static_cast<uint32_t>(HotspotInterfaceCode::WIFI_SVR_CMD_GET_STATION_LIST), datas);
}

void OnAddBlockListFuzzTest(const uint8_t* data, size_t size)
{
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN)) {
        LOGE("WriteInterfaceToken failed!");
        return;
    }
    datas.WriteInt32(0);
    datas.WriteBuffer(data, size);
    OnRemoteRequest(static_cast<uint32_t>(HotspotInterfaceCode::WIFI_SVR_CMD_ADD_BLOCK_LIST), datas);
}

void OnDelBlockListFuzzTest(const uint8_t* data, size_t size)
{
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN)) {
        LOGE("WriteInterfaceToken failed!");
        return;
    }
    datas.WriteInt32(0);
    datas.WriteBuffer(data, size);
    OnRemoteRequest(static_cast<uint32_t>(HotspotInterfaceCode::WIFI_SVR_CMD_DEL_BLOCK_LIST), datas);
}

void OnGetBlockListsFuzzTest(const uint8_t* data, size_t size)
{
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN)) {
        LOGE("WriteInterfaceToken failed!");
        return;
    }
    datas.WriteInt32(0);
    datas.WriteBuffer(data, size);
    OnRemoteRequest(static_cast<uint32_t>(HotspotInterfaceCode::WIFI_SVR_CMD_GET_BLOCK_LISTS), datas);
}

void OnGetValidBandsFuzzTest(const uint8_t* data, size_t size)
{
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN)) {
        LOGE("WriteInterfaceToken failed!");
        return;
    }
    datas.WriteInt32(0);
    datas.WriteBuffer(data, size);
    OnRemoteRequest(static_cast<uint32_t>(HotspotInterfaceCode::WIFI_SVR_CMD_GET_VALID_BANDS), datas);
}

void OnDisassociateStaFuzzTest(const uint8_t* data, size_t size)
{
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN)) {
        LOGE("WriteInterfaceToken failed!");
        return;
    }
    datas.WriteInt32(0);
    datas.WriteBuffer(data, size);
    OnRemoteRequest(static_cast<uint32_t>(HotspotInterfaceCode::WIFI_SVR_CMD_DISCONNECT_STA), datas);
}

void OnGetValidChannelsFuzzTest(const uint8_t* data, size_t size)
{
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN)) {
        LOGE("WriteInterfaceToken failed!");
        return;
    }
    datas.WriteInt32(0);
    datas.WriteBuffer(data, size);
    OnRemoteRequest(static_cast<uint32_t>(HotspotInterfaceCode::WIFI_SVR_CMD_GET_VALID_CHANNELS), datas);
}

void OnRegisterCallBackFuzzTest(const uint8_t* data, size_t size)
{
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN)) {
        LOGE("WriteInterfaceToken failed!");
        return;
    }
    datas.WriteInt32(0);
    datas.WriteBuffer(data, size);
    OnRemoteRequest(static_cast<uint32_t>(HotspotInterfaceCode::WIFI_SVR_CMD_REGISTER_HOTSPOT_CALLBACK), datas);
}

void OnGetSupportedPowerModelFuzzTest(const uint8_t* data, size_t size)
{
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN)) {
        LOGE("WriteInterfaceToken failed!");
        return;
    }
    datas.WriteInt32(0);
    datas.WriteBuffer(data, size);
    OnRemoteRequest(static_cast<uint32_t>(HotspotInterfaceCode::WIFI_SVR_CMD_GET_SUPPORTED_POWER_MODEL), datas);
}

void OnGetPowerModelFuzzTest(const uint8_t* data, size_t size)
{
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN)) {
        LOGE("WriteInterfaceToken failed!");
        return;
    }
    datas.WriteInt32(0);
    datas.WriteBuffer(data, size);
    OnRemoteRequest(static_cast<uint32_t>(HotspotInterfaceCode::WIFI_SVR_CMD_GET_POWER_MODEL), datas);
}

void OnSetPowerModelFuzzTest(const uint8_t* data, size_t size)
{
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN)) {
        LOGE("WriteInterfaceToken failed!");
        return;
    }
    datas.WriteInt32(0);
    datas.WriteBuffer(data, size);
    OnRemoteRequest(static_cast<uint32_t>(HotspotInterfaceCode::WIFI_SVR_CMD_SET_POWER_MODEL), datas);
}

void OnIsHotspotDualBandSupportedFuzzTest(const uint8_t* data, size_t size)
{
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN)) {
        LOGE("WriteInterfaceToken failed!");
        return;
    }
    datas.WriteInt32(0);
    datas.WriteBuffer(data, size);
    OnRemoteRequest(static_cast<uint32_t>(HotspotInterfaceCode::WIFI_SVR_CMD_IS_HOTSPOT_DUAL_BAND_SUPPORTED), datas);
}

void OnIsOpenSoftApAllowedFuzzTest(const uint8_t* data, size_t size)
{
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN)) {
        LOGE("WriteInterfaceToken failed!");
        return;
    }
    datas.WriteInt32(0);
    datas.WriteBuffer(data, size);
    OnRemoteRequest(static_cast<uint32_t>(HotspotInterfaceCode::WIFI_SVR_CMD_IS_HOTSPOT_SUPPORTED), datas);
}

void OnSetApIdleTimeoutFuzzTest(const uint8_t* data, size_t size)
{
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN)) {
        LOGE("WriteInterfaceToken failed!");
        return;
    }
    datas.WriteInt32(0);
    datas.WriteBuffer(data, size);
    OnRemoteRequest(static_cast<uint32_t>(HotspotInterfaceCode::WIFI_SVR_CMD_SETTIMEOUT_AP), datas);
}

void OnGetApIfaceNameFuzzTest(const uint8_t* data, size_t size)
{
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN)) {
        LOGE("WriteInterfaceToken failed!");
        return;
    }
    datas.WriteInt32(0);
    datas.WriteBuffer(data, size);
    OnRemoteRequest(static_cast<uint32_t>(HotspotInterfaceCode::WIFI_SVR_CMD_GET_IFACE_NAME), datas);
}

void OnEnableWifiApTest(const uint8_t* data, size_t size)
{
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN)) {
        LOGE("WriteInterfaceToken failed!");
        return;
    }
    datas.WriteInt32(0);
    datas.WriteBuffer(data, size);
    OnRemoteRequest(static_cast<uint32_t>(HotspotInterfaceCode::WIFI_SVR_CMD_ENABLE_WIFI_AP), datas);
}

void OnDisableWifiApTest(const uint8_t* data, size_t size)
{
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN)) {
        LOGE("WriteInterfaceToken failed!");
        return;
    }
    datas.WriteInt32(0);
    datas.WriteBuffer(data, size);
    OnRemoteRequest(static_cast<uint32_t>(HotspotInterfaceCode::WIFI_SVR_CMD_DISABLE_WIFI_AP), datas);
}

void OnEnableWifiFuzzTest(const uint8_t* data, size_t size)
{
    MessageParcel datas;
    datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN_DEVICE);
    datas.WriteInt32(0);
    datas.WriteBuffer(data, size);
    MessageParcel reply;
    MessageOption option;
    pWifiDeviceStub->OnRemoteRequest(static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_ENABLE_WIFI),
        datas, reply, option);
}

void OnDisableWifiFuzzTest(const uint8_t* data, size_t size)
{
    MessageParcel datas;
    datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN_DEVICE);
    datas.WriteInt32(0);
    datas.WriteBuffer(data, size);
    MessageParcel reply;
    MessageOption option;
    pWifiDeviceStub->OnRemoteRequest(static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_DISABLE_WIFI),
        datas, reply, option);
}

void OnGetSupportedFeaturesFuzzTest(const uint8_t* data, size_t size)
{
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN)) {
        LOGE("WriteInterfaceToken failed!");
        return;
    }
    datas.WriteInt32(0);
    datas.WriteBuffer(data, size);
    OnRemoteRequest(static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_GET_SUPPORTED_FEATURES), datas);
}

bool DoSomethingHotSpotMgrStubTest(const uint8_t* data, size_t size)
{
    uint32_t code = static_cast<uint32_t>(HotspotInterfaceCode::WIFI_MGR_GET_HOTSPOT_SERVICE);
    MessageParcel datas;
    datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN_HOSPOT_EX);
    datas.WriteInt32(0);
    datas.WriteBuffer(data, size);
    datas.RewindRead(0);
    MessageParcel reply;
    MessageOption option;
    pWifiHotspotMgrStub->OnRemoteRequest(code, datas, reply, option);
    return true;
}

void WifiHotspotServiceImplFuzzTest(const uint8_t* data, size_t size)
{
    WifiHotspotServiceImpl mWifiHotspotServiceImpl;
    int index = 0;
    KeyMgmt type = static_cast<KeyMgmt>(static_cast<int>(data[0]) % THREE);
    BandType newBand = static_cast<BandType>(static_cast<int>(data[0]) % U32_AT_SIZE_ZERO);
    int channelid = static_cast<int32_t >(data[0]);
    std::string primaryDeviceType = std::string(reinterpret_cast<const char*>(data), size);
    std::string secondaryDeviceType = std::string(reinterpret_cast<const char*>(data), size);
    std::vector<BandType> bandsFromCenter;
    bandsFromCenter.push_back(newBand);
    ChannelsTable channInfoFromCenter;
    HotspotConfig config;
    StationInfo updateInfo;
    if (size >= U32_AT_SIZE_ZERO) {
        std::string deviceName = std::string(reinterpret_cast<const char*>(data), size);
        std::string networkName = std::string(reinterpret_cast<const char*>(data), size);
        std::string mDeviceAddress = std::string(reinterpret_cast<const char*>(data), size);
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
        updateInfo.bssidType = static_cast<int>(data[index++]);
    }
    mWifiHotspotServiceImpl.SetHotspotConfig(config);
    mWifiHotspotServiceImpl.TransRandomToRealMac(updateInfo, updateInfo);
    mWifiHotspotServiceImpl.ConfigInfoDump(primaryDeviceType);
    mWifiHotspotServiceImpl.StationsInfoDump(secondaryDeviceType);
    mWifiHotspotServiceImpl.SaBasicDump(secondaryDeviceType);
    mWifiHotspotServiceImpl.CfgCheckSsid(config);
    mWifiHotspotServiceImpl.CfgCheckPsk(config);
    mWifiHotspotServiceImpl.CfgCheckBand(config, bandsFromCenter);
    mWifiHotspotServiceImpl.CfgCheckIpAddress(secondaryDeviceType);
    mWifiHotspotServiceImpl.IsValidHotspotConfig(config, config, bandsFromCenter, channInfoFromCenter);
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size <= OHOS::Wifi::U32_AT_SIZE_ZERO)) {
        return 0;
    }
    Init();
    OHOS::Wifi::OnIsHotspotActiveFuzzTest(data, size);
    OHOS::Wifi::OnGetApStateWifiFuzzTest(data, size);
    OHOS::Wifi::OnGetHotspotConfigFuzzTest(data, size);
    OHOS::Wifi::OnSetApConfigWifiFuzzTest(data, size);
    OHOS::Wifi::OnGetStationListFuzzTest(data, size);
    OHOS::Wifi::OnAddBlockListFuzzTest(data, size);
    OHOS::Wifi::OnDelBlockListFuzzTest(data, size);
    OHOS::Wifi::OnGetBlockListsFuzzTest(data, size);
    OHOS::Wifi::OnDisassociateStaFuzzTest(data, size);
    OHOS::Wifi::OnGetValidBandsFuzzTest(data, size);
    OHOS::Wifi::OnGetValidChannelsFuzzTest(data, size);
    OHOS::Wifi::OnRegisterCallBackFuzzTest(data, size);
    OHOS::Wifi::OnGetSupportedPowerModelFuzzTest(data, size);
    OHOS::Wifi::OnGetPowerModelFuzzTest(data, size);
    OHOS::Wifi::OnSetPowerModelFuzzTest(data, size);
    OHOS::Wifi::OnIsHotspotDualBandSupportedFuzzTest(data, size);
    OHOS::Wifi::OnIsOpenSoftApAllowedFuzzTest(data, size);
    OHOS::Wifi::OnSetApIdleTimeoutFuzzTest(data, size);
    OHOS::Wifi::OnGetApIfaceNameFuzzTest(data, size);
    OHOS::Wifi::OnGetSupportedFeaturesFuzzTest(data, size);
    OHOS::Wifi::WifiHotspotServiceImplFuzzTest(data, size);
    OHOS::Wifi::DoSomethingHotSpotMgrStubTest(data, size);
    sleep(4);
    return 0;
}
}
}
