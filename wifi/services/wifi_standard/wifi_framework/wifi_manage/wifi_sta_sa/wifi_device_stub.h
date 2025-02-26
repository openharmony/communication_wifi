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

#ifndef OHOS_WIFI_DEVICE_STUB_H
#define OHOS_WIFI_DEVICE_STUB_H

#include <map>
#include "iremote_stub.h"
#include "i_wifi_device.h"
#include "i_wifi_device_callback.h"

namespace OHOS {
namespace Wifi {
class WifiDeviceStub : public IRemoteStub<IWifiDevice> {
public:
    WifiDeviceStub();
    explicit WifiDeviceStub(int instId);
    virtual ~WifiDeviceStub();

    using handleFunc = std::function<void(uint32_t, MessageParcel &, MessageParcel &)>;
    using HandleFuncMap = std::map<int, handleFunc>;

    virtual int OnRemoteRequest(
        uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) override;

private:
    void InitHandleMap();
    void InitHandleMapEx(void);
    void InitHandleMapEx2();
    void OnEnableWifi(uint32_t code, MessageParcel &data, MessageParcel &reply);
    void OnDisableWifi(uint32_t code, MessageParcel &data, MessageParcel &reply);
    void OnInitWifiProtect(uint32_t code, MessageParcel &data, MessageParcel &reply);
    void OnGetWifiProtectRef(uint32_t code, MessageParcel &data, MessageParcel &reply);
    void OnPutWifiProtectRef(uint32_t code, MessageParcel &data, MessageParcel &reply);
    void OnIsHeldWifiProtectRef(uint32_t code, MessageParcel &data, MessageParcel &reply);
    void OnAddDeviceConfig(uint32_t code, MessageParcel &data, MessageParcel &reply);
    void OnUpdateDeviceConfig(uint32_t code, MessageParcel &data, MessageParcel &reply);
    void OnRemoveDevice(uint32_t code, MessageParcel &data, MessageParcel &reply);
    void OnRemoveAllDevice(uint32_t code, MessageParcel &data, MessageParcel &reply);
    void OnGetDeviceConfigs(uint32_t code, MessageParcel &data, MessageParcel &reply);
    void OnGetChangeDeviceConfig(uint32_t code, MessageParcel &data, MessageParcel &reply);
    void OnEnableDeviceConfig(uint32_t code, MessageParcel &data, MessageParcel &reply);
    void OnDisableDeviceConfig(uint32_t code, MessageParcel &data, MessageParcel &reply);
    void OnAllowAutoConnect(uint32_t code, MessageParcel &data, MessageParcel &reply);
    void OnConnectTo(uint32_t code, MessageParcel &data, MessageParcel &reply);
    void OnConnect2To(uint32_t code, MessageParcel &data, MessageParcel &reply);
    void OnStartRoamToNetwork(uint32_t code, MessageParcel &data, MessageParcel &reply);
    void OnStartConnectToUserSelectNetwork(uint32_t code, MessageParcel &data, MessageParcel &reply);
    void OnReConnect(uint32_t code, MessageParcel &data, MessageParcel &reply);
    void OnReAssociate(uint32_t code, MessageParcel &data, MessageParcel &reply);
    void OnDisconnect(uint32_t code, MessageParcel &data, MessageParcel &reply);
    void OnStartWps(uint32_t code, MessageParcel &data, MessageParcel &reply);
    void OnCancelWps(uint32_t code, MessageParcel &data, MessageParcel &reply);
    void OnIsWifiActive(uint32_t code, MessageParcel &data, MessageParcel &reply);
    void OnIsMeteredHotspot(uint32_t code, MessageParcel &data, MessageParcel &reply);
    void OnGetWifiState(uint32_t code, MessageParcel &data, MessageParcel &reply);
    void OnGetLinkedInfo(uint32_t code, MessageParcel &data, MessageParcel &reply);
    void OnGetSignalPollInfoArray(uint32_t code, MessageParcel &data, MessageParcel &reply);
    void OnGetMultiLinkedInfo(uint32_t code, MessageParcel &data, MessageParcel &reply);
    void OnGetIpInfo(uint32_t code, MessageParcel &data, MessageParcel &reply);
    void OnGetIpV6Info(uint32_t code, MessageParcel &data, MessageParcel &reply);
    void OnSetCountryCode(uint32_t code, MessageParcel &data, MessageParcel &reply);
    void OnGetCountryCode(uint32_t code, MessageParcel &data, MessageParcel &reply);
    void OnRegisterCallBack(uint32_t code, MessageParcel &data, MessageParcel &reply);
    void OnGetSignalLevel(uint32_t code, MessageParcel &data, MessageParcel &reply);
    void OnGetSupportedFeatures(uint32_t code, MessageParcel &data, MessageParcel &reply);
    void OnGetDeviceMacAdd(uint32_t code, MessageParcel &data, MessageParcel &reply);
    void OnIsWifiConnected(uint32_t code, MessageParcel &data, MessageParcel &reply);
    void OnSetLowLatencyMode(uint32_t code, MessageParcel &data, MessageParcel &reply);
    void OnRemoveCandidateConfig(uint32_t code, MessageParcel &data, MessageParcel &reply);
    void OnIsBandTypeSupported(uint32_t code, MessageParcel &data, MessageParcel &reply);
    void OnGet5GHzChannelList(uint32_t code, MessageParcel &data, MessageParcel &reply);
    void OnStartPortalCertification(uint32_t code, MessageParcel &data, MessageParcel &reply);
    void OnGetDisconnectedReason(uint32_t code, MessageParcel &data, MessageParcel &reply);
    void OnSetFrozenApp(uint32_t code, MessageParcel& data, MessageParcel& reply);
    void OnResetAllFrozenApp(uint32_t code, MessageParcel& data, MessageParcel& reply);
    void OnDisableAutoJoin(uint32_t code, MessageParcel& data, MessageParcel& reply);
    void OnEnableAutoJoin(uint32_t code, MessageParcel& data, MessageParcel& reply);
    void OnFactoryReset(uint32_t code, MessageParcel &data, MessageParcel &reply);
    void OnReceiveNetworkControlInfo(uint32_t code, MessageParcel &data, MessageParcel &reply);
    void OnLimitSpeed(uint32_t code, MessageParcel &data, MessageParcel &reply);
    void OnEnableHiLinkHandshake(uint32_t code, MessageParcel &data, MessageParcel &reply);
    void OnEnableSemiWifi(uint32_t code, MessageParcel &data, MessageParcel &reply);
    void OnGetWifiDetailState(uint32_t code, MessageParcel &data, MessageParcel &reply);
    void OnSetSatelliteState(uint32_t code, MessageParcel &data, MessageParcel &reply);
    void OnSetLowTxPower(uint32_t code, MessageParcel &data, MessageParcel &reply);
    void OnSetTxPower(uint32_t code, MessageParcel &data, MessageParcel &reply);
    void OnGetDeviceConfig(uint32_t code, MessageParcel &data, MessageParcel &reply);
    void OnSetDpiMarkRule(uint32_t code, MessageParcel &data, MessageParcel &reply);
    void OnIsFeatureSupported(uint32_t code, MessageParcel &data, MessageParcel &reply);
    void OnUpdateNetworkLagInfo(uint32_t code, MessageParcel &data, MessageParcel &reply);
    void OnFetchWifiSignalInfoForVoWiFi(uint32_t code, MessageParcel &data, MessageParcel &reply);
    void OnIsSupportVoWifiDetect(uint32_t code, MessageParcel &data, MessageParcel &reply);
    void OnSetVoWifiDetectMode(uint32_t code, MessageParcel &data, MessageParcel &reply);
    void OnGetVoWifiDetectMode(uint32_t code, MessageParcel &data, MessageParcel &reply);
    void OnSetVoWifiDetectPeriod(uint32_t code, MessageParcel &data, MessageParcel &reply);
    void OnGetVoWifiDetectPeriod(uint32_t code, MessageParcel &data, MessageParcel &reply);

private:
    void ReadEapConfig(MessageParcel &data, WifiEapConfig &wifiEapConfig);
    void ReadWifiDeviceConfig(MessageParcel &data, WifiDeviceConfig &config);
    void ReadIpAddress(MessageParcel &data, WifiIpAddress &address);
    void WriteEapConfig(MessageParcel &reply, const WifiEapConfig &wifiEapConfig);
    void BigDataWriteEapConfig(const WifiEapConfig &wifiEapConfig, std::stringstream &bigDataStream);
    void WriteWifiDeviceConfig(MessageParcel &reply, const WifiDeviceConfig &config);
    void WriteIpAddress(MessageParcel &reply, const WifiIpAddress &address);
    void BigDataWriteIpAddress(const WifiIpAddress &address, std::stringstream &bigDataStream);
    void SendDeviceConfig(int32_t ashmemSize, std::vector<WifiDeviceConfig> &result, MessageParcel &reply);
    void WriteWifiLinkedInfo(MessageParcel &reply, const WifiLinkedInfo &wifiInfo);
    void SendMultiLinkedInfo(uint32_t contentSize, std::vector<WifiLinkedInfo> &result, MessageParcel &reply);

private:
    HandleFuncMap handleFuncMap;
    std::mutex deathRecipientMutex;
    sptr<IRemoteObject::DeathRecipient> deathRecipient_;
    bool mSingleCallback;

protected:
    int m_instId{0};
};
}  // namespace Wifi
}  // namespace OHOS
#endif
