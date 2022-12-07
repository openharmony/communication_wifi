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

#ifndef OHOS_WIFI_DEVICE_SERVICE_IMPL_H
#define OHOS_WIFI_DEVICE_SERVICE_IMPL_H

#include "wifi_errcode.h"
#include "wifi_msg.h"
#include "i_wifi_device_callback.h"
#ifdef OHOS_ARCH_LITE
#include "wifi_device_stub_lite.h"
#else
#include "system_ability.h"
#include "wifi_device_stub.h"
#include "iremote_object.h"
#include "wifi_p2p_service_impl.h"
#include "common_event_manager.h"
#include "common_event_support.h"
#include "bundle_constants.h"
#include "timer.h"
#endif

namespace OHOS {
namespace Wifi {
#ifndef OHOS_ARCH_LITE
class AppEventSubscriber : public OHOS::EventFwk::CommonEventSubscriber {
public:
    explicit AppEventSubscriber(const OHOS::EventFwk::CommonEventSubscribeInfo &subscriberInfo)
        : CommonEventSubscriber(subscriberInfo) {}
    virtual ~AppEventSubscriber() {};
    virtual void OnReceiveEvent(const OHOS::EventFwk::CommonEventData &data) override;
};

class ScreenEventSubscriber : public OHOS::EventFwk::CommonEventSubscriber {
public:
    explicit ScreenEventSubscriber(const OHOS::EventFwk::CommonEventSubscribeInfo &subscriberInfo)
        : CommonEventSubscriber(subscriberInfo) {}
    virtual ~ScreenEventSubscriber() {};
    virtual void OnReceiveEvent(const OHOS::EventFwk::CommonEventData &data) override;
};

class ThermalLevelSubscriber : public OHOS::EventFwk::CommonEventSubscriber {
public:
    explicit ThermalLevelSubscriber(const OHOS::EventFwk::CommonEventSubscribeInfo &subscriberInfo)
        : CommonEventSubscriber(subscriberInfo) {}
    virtual ~ThermalLevelSubscriber() {};
    virtual void OnReceiveEvent(const OHOS::EventFwk::CommonEventData &data) override;
};
#endif
#ifdef OHOS_ARCH_LITE
enum ServiceRunningState {
    STATE_NOT_START,
    STATE_RUNNING
};

class WifiDeviceServiceImpl : public WifiDeviceStub {
#else

class WifiDeviceServiceImpl : public SystemAbility, public WifiDeviceStub {
DECLARE_SYSTEM_ABILITY(WifiDeviceServiceImpl);
#endif
public:
    WifiDeviceServiceImpl();
    virtual ~WifiDeviceServiceImpl();

#ifdef OHOS_ARCH_LITE
    static std::shared_ptr<WifiDeviceServiceImpl> GetInstance();

    void OnStart();
    void OnStop();
#else
    static sptr<WifiDeviceServiceImpl> GetInstance();

    void OnStart() override;
    void OnStop() override;
#endif

    ErrCode EnableWifi() override;

    ErrCode DisableWifi() override;

    ErrCode InitWifiProtect(const WifiProtectType &protectType, const std::string &protectName) override;

    ErrCode GetWifiProtectRef(const WifiProtectMode &protectMode, const std::string &protectName) override;

    ErrCode PutWifiProtectRef(const std::string &protectName) override;

    ErrCode AddDeviceConfig(const WifiDeviceConfig &config, int &result, bool isCandidate) override;

    ErrCode UpdateDeviceConfig(const WifiDeviceConfig &config, int &result) override;

    ErrCode RemoveDevice(int networkId) override;

    ErrCode RemoveAllDevice() override;

    ErrCode GetDeviceConfigs(std::vector<WifiDeviceConfig> &result, bool isCandidate) override;

    ErrCode EnableDeviceConfig(int networkId, bool attemptEnable) override;

    ErrCode DisableDeviceConfig(int networkId) override;

    ErrCode ConnectToNetwork(int networkId, bool isCandidate) override;

    ErrCode ConnectToDevice(const WifiDeviceConfig &config) override;

    ErrCode IsConnected(bool &isConnected) override;

    ErrCode ReConnect() override;

    ErrCode ReAssociate(void) override;

    ErrCode Disconnect(void) override;

    ErrCode StartWps(const WpsConfig &config) override;

    ErrCode CancelWps(void) override;

    ErrCode IsWifiActive(bool &bActive) override;

    ErrCode GetWifiState(int &state) override;

    ErrCode GetLinkedInfo(WifiLinkedInfo &info) override;

    ErrCode GetIpInfo(IpInfo &info) override;

    ErrCode SetCountryCode(const std::string &countryCode) override;

    ErrCode GetCountryCode(std::string &countryCode) override;

#ifdef OHOS_ARCH_LITE
    ErrCode RegisterCallBack(const std::shared_ptr<IWifiDeviceCallBack> &callback) override;
#else
    ErrCode RegisterCallBack(const sptr<IWifiDeviceCallBack> &callback) override;
#endif

    ErrCode GetSignalLevel(const int &rssi, const int &band, int &level) override;

    ErrCode GetSupportedFeatures(long &features) override;

    ErrCode GetDeviceMacAddress(std::string &result) override;

    bool SetLowLatencyMode(bool enabled) override;

    ErrCode RemoveCandidateConfig(int networkId) override;

    ErrCode RemoveCandidateConfig(const WifiDeviceConfig &config) override;

    bool IsRemoteDied(void) override;

#ifndef OHOS_ARCH_LITE
    int32_t Dump(int32_t fd, const std::vector<std::u16string>& args) override;
#endif

private:
    bool Init();
    ErrCode CheckCanEnableWifi(void);
    bool IsStaServiceRunning();
    bool IsScanServiceRunning();
    bool CheckConfigEap(const WifiDeviceConfig &config);
    bool CheckConfigPwd(const WifiDeviceConfig &config);
    ErrCode CheckCallingUid(int &uid);
    static void SaBasicDump(std::string& result);
    static void SigHandler(int sig);
    static bool IsProcessNeedToRestart();
    ErrCode CheckRemoveCandidateConfig(void);
#ifndef OHOS_ARCH_LITE
    void RegisterAppRemoved();
    void UnRegisterAppRemoved();
    void RegisterScreenEvent();
    void UnRegisterScreenEvent();
    void RegisterThermalLevel();
    void UnRegisterThermalLevel();
#endif

private:
    static constexpr int MAX_PRESHAREDKEY_LEN = 63;
    static constexpr int MAX_HEX_LEN = 64;
    static constexpr int MIN_PSK_LEN = 8;
    static constexpr int MIN_SAE_LEN = 1;
    static constexpr int WEP_KEY_LEN1 = 5;
    static constexpr int WEP_KEY_LEN2 = 13;
    static constexpr int WEP_KEY_LEN3 = 16;

#ifdef OHOS_ARCH_LITE
    static std::shared_ptr<WifiDeviceServiceImpl> g_instance;
#else
    static sptr<WifiDeviceServiceImpl> g_instance;
    std::shared_ptr<AppEventSubscriber> eventSubscriber_ = nullptr;
    std::shared_ptr<ScreenEventSubscriber> screenEventSubscriber_ = nullptr;
    std::shared_ptr<ThermalLevelSubscriber> thermalLevelSubscriber_ = nullptr;
    std::unique_ptr<Utils::Timer> lpTimer_ = nullptr;
    std::unique_ptr<Utils::Timer> lpScreenTimer_ = nullptr;
    std::unique_ptr<Utils::Timer> lpThermalTimer_ = nullptr;
#endif
    static std::mutex g_instanceLock;
    static bool isServiceStart;
    bool mPublishFlag;
    ServiceRunningState mState;
};
}  // namespace Wifi
}  // namespace OHOS
#endif
