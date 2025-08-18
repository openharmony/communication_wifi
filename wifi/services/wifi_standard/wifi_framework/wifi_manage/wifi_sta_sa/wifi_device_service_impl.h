/*
 * Copyright (C) 2021-2025 Huawei Device Co., Ltd.
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

#ifndef OHOS_WIFI_DEVICE_SERVICE_IMPL_H
#define OHOS_WIFI_DEVICE_SERVICE_IMPL_H

#include <mutex>
#include "wifi_errcode.h"
#include "wifi_msg.h"
#include "i_wifi_device_callback.h"
#ifdef OHOS_ARCH_LITE
#include "wifi_device_stub_lite.h"
#else
#include "system_ability.h"
#include "wifi_device_stub.h"
#include "iremote_object.h"
#include "bundle_constants.h"
#endif

namespace OHOS {
namespace Wifi {
#ifdef OHOS_ARCH_LITE
enum ServiceRunningState { STATE_NOT_START, STATE_RUNNING };
#endif

class WifiDeviceServiceImpl : public WifiDeviceStub {
public:
    WifiDeviceServiceImpl();
#ifdef OHOS_ARCH_LITE
    static std::shared_ptr<WifiDeviceServiceImpl> GetInstance();
    void OnStart();
    void OnStop();
#else
    explicit WifiDeviceServiceImpl(int instId);
    static ErrCode OnBackup(MessageParcel& data, MessageParcel& reply);
    static ErrCode OnRestore(MessageParcel& data, MessageParcel& reply);
#endif
    virtual ~WifiDeviceServiceImpl();

    ErrCode EnableWifi() override;

    ErrCode DisableWifi() override;

    ErrCode InitWifiProtect(const WifiProtectType &protectType, const std::string &protectName) override;

    ErrCode GetWifiProtectRef(const WifiProtectMode &protectMode, const std::string &protectName) override;

    ErrCode PutWifiProtectRef(const std::string &protectName) override;

    ErrCode IsHeldWifiProtectRef(const std::string &protectName, bool &isHoldProtect) override;

    ErrCode AddDeviceConfig(const WifiDeviceConfig &config, int &result, bool isCandidate) override;

    ErrCode UpdateDeviceConfig(const WifiDeviceConfig &config, int &result) override;

    ErrCode RemoveDevice(int networkId) override;

    ErrCode RemoveAllDevice() override;

    ErrCode SetTxPower(int power) override;

    ErrCode SetDpiMarkRule(const std::string &ifaceName, int uid, int protocol, int enable) override;

    ErrCode GetDeviceConfigs(std::vector<WifiDeviceConfig> &result, bool isCandidate) override;

    ErrCode EnableDeviceConfig(int networkId, bool attemptEnable) override;

    ErrCode DisableDeviceConfig(int networkId) override;

    ErrCode AllowAutoConnect(int32_t networkId, bool isAllowed) override;

    ErrCode ConnectToNetwork(int networkId, bool isCandidate) override;

    ErrCode ConnectToDevice(const WifiDeviceConfig &config) override;

    ErrCode StartRoamToNetwork(const int networkId, const std::string bssid, const bool isCandidate) override;

    ErrCode StartConnectToUserSelectNetwork(int networkId, std::string bssid, bool isCandidate) override;

    ErrCode IsConnected(bool &isConnected) override;

    ErrCode ReConnect() override;

    ErrCode ReAssociate(void) override;

    ErrCode Disconnect(void) override;

    ErrCode StartWps(const WpsConfig &config) override;

    ErrCode CancelWps(void) override;

    ErrCode IsWifiActive(bool &bActive) override;

    ErrCode GetWifiState(int &state) override;

    ErrCode IsMeteredHotspot(bool &bMeteredHotspot) override;

    ErrCode GetLinkedInfo(WifiLinkedInfo &info) override;

    ErrCode GetSignalPollInfoArray(std::vector<WifiSignalPollInfo> &wifiSignalPollInfos, int length) override;

    ErrCode GetMultiLinkedInfo(std::vector<WifiLinkedInfo> &mloLinkInfo) override;

    ErrCode GetDisconnectedReason(DisconnectedReason &reason) override;

    ErrCode GetIpInfo(IpInfo &info) override;

    ErrCode GetIpv6Info(IpV6Info &info) override;

    ErrCode SetCountryCode(const std::string &countryCode) override;

    ErrCode GetCountryCode(std::string &countryCode) override;

    ErrCode SetAppFrozen(std::set<int> pidList, bool isFrozen) override;

    ErrCode ResetAllFrozenApp() override;

    ErrCode DisableAutoJoin(const std::string &conditionName) override;

    ErrCode EnableAutoJoin(const std::string &conditionName) override;

    ErrCode RegisterAutoJoinCondition(const std::string &conditionName,
                                      const std::function<bool()> &autoJoinCondition) override;

    ErrCode DeregisterAutoJoinCondition(const std::string &conditionName) override;

    ErrCode RegisterFilterBuilder(const FilterTag &filterTag, const std::string &builderName,
                                  const FilterBuilder &filterBuilder) override;

    ErrCode DeregisterFilterBuilder(const FilterTag &filterTag, const std::string &builderName) override;

    ErrCode RegisterCommonBuilder(const TagType &tagType, const std::string &tagName,
                               const CommonBuilder &commonBuilder) override;

    ErrCode DeregisterCommonBuilder(const TagType &tagType, const std::string &tagName) override;

#ifdef OHOS_ARCH_LITE
    ErrCode RegisterCallBack(const std::shared_ptr<IWifiDeviceCallBack> &callback,
        const std::vector<std::string> &event) override;
#else
    ErrCode RegisterCallBack(const sptr<IWifiDeviceCallBack> &callback, const std::vector<std::string> &event) override;
#endif

    ErrCode GetSignalLevel(const int &rssi, const int &band, int &level) override;

    ErrCode GetSupportedFeatures(long &features) override;

    ErrCode IsFeatureSupported(long feature, bool &isSupported) override;

    ErrCode GetDeviceMacAddress(std::string &result) override;

    bool SetLowLatencyMode(bool enabled) override;

    ErrCode RemoveCandidateConfig(int networkId) override;

    ErrCode RemoveCandidateConfig(const WifiDeviceConfig &config) override;

    bool IsRemoteDied(void) override;

    ErrCode IsBandTypeSupported(int bandType, bool &supported) override;

    ErrCode Get5GHzChannelList(std::vector<int> &result) override;

    ErrCode StartPortalCertification() override;

    static void SaBasicDump(std::string& result);

    ErrCode GetChangeDeviceConfig(ConfigChange& value, WifiDeviceConfig &config) override;

    ErrCode FactoryReset() override;

    ErrCode StartWifiDetection() override;

    ErrCode ReceiveNetworkControlInfo(const WifiNetworkControlInfo& networkControlInfo) override;

    ErrCode LimitSpeed(const int controlId, const int limitMode) override;

    ErrCode SetLowTxPower(const WifiLowPowerParam wifiLowPowerParam) override;

    ErrCode EnableHiLinkHandshake(bool uiFlag, std::string &bssid, WifiDeviceConfig &deviceConfig) override;

    ErrCode EnableSemiWifi() override;

    ErrCode GetWifiDetailState(WifiDetailState &state) override;

    ErrCode SetSatelliteState(const int state) override;

    ErrCode GetDeviceConfig(const int &networkId, WifiDeviceConfig &config) override;

    ErrCode UpdateNetworkLagInfo(const NetworkLagType networkLagType, const NetworkLagInfo &networkLagInfo) override;

    ErrCode FetchWifiSignalInfoForVoWiFi(VoWifiSignalInfo &signalInfo) override;
 
    ErrCode IsSupportVoWifiDetect(bool &isSupported) override;
 
    ErrCode SetVoWifiDetectMode(WifiDetectConfInfo info) override;
 
    ErrCode GetVoWifiDetectMode(WifiDetectConfInfo &info) override;
 
    ErrCode SetVoWifiDetectPeriod(int period) override;
 
    ErrCode GetVoWifiDetectPeriod(int &period) override;

    ErrCode SetWifiRestrictedList(const std::vector<WifiRestrictedInfo> &wifiRestrictedInfoList) override;
private:
    bool Init();
    ErrCode CheckCanEnableWifi(void);
    ErrCode CheckCanAddDeviceConfig(const bool isCandidate);
    bool IsStaServiceRunning();
    bool IsScanServiceRunning();
    bool CheckConfigEap(const WifiDeviceConfig &config);
    bool CheckConfigPwd(const WifiDeviceConfig &config);
    bool CheckConfigWapi(const WifiDeviceConfig &config);
    ErrCode CheckCallingUid(int &uid);
    bool IsWifiBrokerProcess(int uid);
    ErrCode CheckRemoveCandidateConfig(void);
    void SetWifiConnectedMode(void);
    ErrCode HilinkGetMacAddress(WifiDeviceConfig &deviceConfig, std::string &currentMac);
#ifndef OHOS_ARCH_LITE
    bool InitWifiBrokerProcessInfo(const WifiDeviceConfig &config);
    ErrCode FactoryResetNotify();
#endif
    void ReplaceConfigWhenCandidateConnected(std::vector<WifiDeviceConfig> &result);
    void updateStaDeviceMacAddress(WifiDeviceConfig &config);
    int ProcessPermissionVerify(const std::string &appId, const std::string &packageName);
    void UpdateWifiLinkInfo(WifiLinkedInfo &info);
#ifdef DYNAMIC_UNLOAD_SA
    void StopUnloadStaTimer(void) override;
#endif
    bool IsDisableWifiProhibitedByEdm(void);

    private:
    static constexpr int MAX_PRESHAREDKEY_LEN = 63;
    static constexpr int MAX_HEX_LEN = 64;
    static constexpr int MIN_PSK_LEN = 8;
    static constexpr int MIN_SAE_LEN = 1;
    static constexpr int WEP_KEY_LEN1 = 5;
    static constexpr int WEP_KEY_LEN2 = 13;
    static constexpr int WEP_KEY_LEN3 = 16;

#ifdef OHOS_ARCH_LITE
    static std::mutex g_instanceLock;
    static std::shared_ptr<WifiDeviceServiceImpl> g_instance;
    ServiceRunningState mState;
#endif
};
}  // namespace Wifi
}  // namespace OHOS
#endif
