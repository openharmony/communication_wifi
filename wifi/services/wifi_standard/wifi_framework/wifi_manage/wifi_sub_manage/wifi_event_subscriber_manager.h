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

#ifndef OHOS_WIFI_EVENT_SUBSCRIBER_MANAGER_H
#define OHOS_WIFI_EVENT_SUBSCRIBER_MANAGER_H

#ifndef OHOS_ARCH_LITE
#include <mutex>
#include <functional>
#include "wifi_errcode.h"
#include "wifi_internal_msg.h"
#include "wifi_system_ability_listerner.h"
#include "common_event_manager.h"
#include "wifi_event_handler.h"
#include "display_manager_lite.h"
#include "net_conn_client.h"
#include "net_conn_callback_stub.h"
#include "net_handle.h"
#include "net_all_capabilities.h"
#include "net_link_info.h"
namespace OHOS {
namespace Wifi {
#ifdef HAS_POWERMGR_PART
inline const std::string COMMON_EVENT_POWER_MANAGER_STATE_CHANGED = "usual.event.POWER_MANAGER_STATE_CHANGED";
#endif
const int CAST_ENGINE_SA_ID = 65546;
const int SHARE_SERVICE_ID = 2902;
const int MOUSE_CROSS_SERVICE_ID = 65569;
#ifdef SUPPORT_ClOUD_WIFI_ASSET
inline const std::string COMMON_EVENT_ASSETCLOUD_MANAGER_STATE_CHANGED = "usual.event.ASSET_SYNC_DATA_CHANGED_SA";
const int ASSETID = 6226;
#endif
#ifdef HAS_NETMANAGER_EVENT_PART
inline const std::string WIFI_EVENT_BG_CONTINUOUS_TASK_STATE = "ohos.event.notification.wifi.BGCTTASK_STATE";
#endif
class CesEventSubscriber : public OHOS::EventFwk::CommonEventSubscriber {
public:
    explicit CesEventSubscriber(const OHOS::EventFwk::CommonEventSubscribeInfo &subscriberInfo);
    virtual ~CesEventSubscriber();
    void OnReceiveEvent(const OHOS::EventFwk::CommonEventData &eventData) override;
    void OnReceiveStandbyEvent(const OHOS::EventFwk::CommonEventData &eventData);
    void OnReceiveScreenEvent(const OHOS::EventFwk::CommonEventData &eventData);
    void OnReceiveAirplaneEvent(const OHOS::EventFwk::CommonEventData &eventData);
    void OnReceiveBatteryEvent(const OHOS::EventFwk::CommonEventData &eventData);
    void OnReceiveAppEvent(const OHOS::EventFwk::CommonEventData &eventData);
    void OnReceiveThermalEvent(const OHOS::EventFwk::CommonEventData &eventData);
    void OnReceiveNotificationEvent(const OHOS::EventFwk::CommonEventData &eventData);
    void OnReceiveUserUnlockedEvent(const OHOS::EventFwk::CommonEventData &eventData);
private:
    bool lastSleepState = false;
};

class NotificationEventSubscriber : public OHOS::EventFwk::CommonEventSubscriber {
public:
    explicit NotificationEventSubscriber(const OHOS::EventFwk::CommonEventSubscribeInfo &subscriberInfo);
    virtual ~NotificationEventSubscriber();
    void OnReceiveEvent(const OHOS::EventFwk::CommonEventData &eventData) override;
    void OnReceiveWlanKeepConnected(const OHOS::EventFwk::CommonEventData &eventData);
private:
    void OnReceiveNotificationEvent(int notificationId);
    void OnReceiveDialogAcceptEvent(int dialogType);
    void OnReceiveDialogRejectEvent(int dialogType);
};

#ifdef HAS_POWERMGR_PART
class PowermgrEventSubscriber : public OHOS::EventFwk::CommonEventSubscriber {
public:
    explicit PowermgrEventSubscriber(const OHOS::EventFwk::CommonEventSubscribeInfo &subscriberInfo);
    virtual ~PowermgrEventSubscriber();
    void OnReceiveEvent(const OHOS::EventFwk::CommonEventData &eventData) override;
};
#endif
#ifdef SUPPORT_ClOUD_WIFI_ASSET
class AssetEventSubscriber : public OHOS::EventFwk::CommonEventSubscriber {
public:
    explicit AssetEventSubscriber(const OHOS::EventFwk::CommonEventSubscribeInfo &subscriberInfo);
    virtual ~AssetEventSubscriber();
    void OnReceiveEvent(const OHOS::EventFwk::CommonEventData &eventData) override;
};
#endif
#ifdef HAS_NETMANAGER_EVENT_PART
class NetmgrEventSubscriber : public OHOS::EventFwk::CommonEventSubscriber {
public:
    explicit NetmgrEventSubscriber(const OHOS::EventFwk::CommonEventSubscribeInfo &subscriberInfo);
    virtual ~NetmgrEventSubscriber();
    void OnReceiveEvent(const OHOS::EventFwk::CommonEventData &eventData) override;
};
#endif
class NetworkStateChangeSubscriber : public OHOS::EventFwk::CommonEventSubscriber {
public:
    explicit NetworkStateChangeSubscriber(const OHOS::EventFwk::CommonEventSubscribeInfo &subscriberInfo);
    ~NetworkStateChangeSubscriber() = default;
    void OnReceiveEvent(const OHOS::EventFwk::CommonEventData &eventData) override;
};

class WifiScanEventChangeSubscriber : public OHOS::EventFwk::CommonEventSubscriber {
public:
    explicit WifiScanEventChangeSubscriber(const OHOS::EventFwk::CommonEventSubscribeInfo &subscriberInfo);
    ~WifiScanEventChangeSubscriber() = default;
    void OnReceiveEvent(const OHOS::EventFwk::CommonEventData &eventData) override;
};

class SettingsEnterSubscriber : public OHOS::EventFwk::CommonEventSubscriber {
public:
    explicit SettingsEnterSubscriber(const OHOS::EventFwk::CommonEventSubscribeInfo &subscriberInfo);
    ~SettingsEnterSubscriber() = default;
    void OnReceiveEvent(const OHOS::EventFwk::CommonEventData &eventData) override;
};

class DataShareReadySubscriber : public OHOS::EventFwk::CommonEventSubscriber {
public:
    explicit DataShareReadySubscriber(const OHOS::EventFwk::CommonEventSubscribeInfo &subscriberInfo);
    ~DataShareReadySubscriber() = default;
    void OnReceiveEvent(const OHOS::EventFwk::CommonEventData &eventData) override;
};

class WifiFoldStateListener : public Rosen::DisplayManagerLite::IFoldStatusListener {
public:
    WifiFoldStateListener();
    ~WifiFoldStateListener() = default;
    void OnFoldStatusChanged(Rosen::FoldStatus foldStatus) override;
};

class NetworkStateChangeSubscriber : public NetManagerStandard::NetConnCallbackStub {
public:
    NetworkConnSubscriber() = default;
    ~NetworkConnSubscriber() default;
    int32_t NetCapabilitiedChange(sptr<NetMannagerStandard::NetHandl> &netHandle,
        cosnt sptr<NetManagerStandard::NetAllCapabiliites> &netAllCap) override;

};

class WifiEventSubscriberManager : public WifiSystemAbilityListener {
public:
    WifiEventSubscriberManager();
    virtual ~WifiEventSubscriberManager();

    void Init();
    void OnSystemAbilityChanged(int systemAbilityId, bool add) override;
    void GetAirplaneModeByDatashare();
    void GetWifiAllowSemiActiveByDatashare();
    bool GetLocationModeByDatashare();
    std::string GetScanMacInfoWhiteListByDatashare();
    void DealLocationModeChangeEvent();
    void CheckAndStartStaByDatashare();
    bool IsMdmForbidden(void);
    void AccessDataShare();
    void RegisterLocationEvent();

private:
    void InitSubscribeListener();
    void HandleAppMgrServiceChange(bool add);
    void HandleCommNetConnManagerSysChange(int systemAbilityId, bool add);
#ifdef HAS_MOVEMENT_PART
    void HandleHasMovementPartChange(int systemAbilityId, bool add);
#endif
    void HandleDistributedKvDataServiceChange(bool add);
    void HandleCastServiceChange(bool add);
    void HandleShareServiceChange(bool add);
    void HandleMouseCrossServiceChange(bool add);
    int GetLastStaStateByDatashare();
    void RegisterCesEvent();
#ifdef HAS_POWERMGR_PART
    void RegisterPowermgrEvent();
    void UnRegisterPowermgrEvent();
    std::shared_ptr<PowermgrEventSubscriber> wifiPowermgrEventSubsciber_ = nullptr;
    std::mutex powermgrEventMutex;
#endif
    void UnRegisterCesEvent();
    void UnRegisterLocationEvent();
    void RegisterNotificationEvent();
    void UnRegisterNotificationEvent();
#ifdef HAS_NETMANAGER_EVENT_PART
    void RegisterNetmgrEvent();
    void UnRegisterNetmgrEvent();
    std::shared_ptr<NetmgrEventSubscriber> wifiNetmgrEventSubsciber_ = nullptr;
    std::mutex netmgrEventMutex;
    uint32_t netMgrId{0};
#endif
    void GetMdmProp();
    void RegisterMdmPropListener();
    static void MdmPropChangeEvt(const char *key, const char *value, void *context);
#ifdef HAS_MOVEMENT_PART
    void RegisterMovementCallBack();
    void UnRegisterMovementCallBack();
#endif
#ifdef FEATURE_P2P_SUPPORT
    void HandleP2pBusinessChange(int systemAbilityId, bool add);
#endif
#ifdef SUPPORT_ClOUD_WIFI_ASSET
    void RegisterAssetEvent();
    void UnRegisterAssetEvent();
#endif
    void RegisterNetworkStateChangeEvent();
    void UnRegisterNetworkStateChangeEvent();
    void RegisterWifiScanChangeEvent();
    void UnRegisterWifiScanChangeEvent();
    void RegisterSettingsEnterEvent();
    void UnRegisterSettingsEnterEvent();
    void RegisterDataShareReadyEvent();
    void UnRegisterDataShareReadyEvent();
    void RegisterFoldStatusListener();
    void UnRegisterFoldStatusListener();
    void RegisterNetworkConnSubscriber();
    void UnRegisterNetworkConnSubscriber();

private:
    uint32_t cesTimerId{0};
    uint32_t notificationTimerId{0};
    uint32_t networkStateChangeTimerId{0};
    uint32_t wifiScanChangeTimerId{0};
    uint32_t settingsTimerId{0};
    uint32_t dataShareReadyTimerId_{0};
    std::mutex cesEventMutex;
    std::mutex notificationEventMutex;
    std::mutex networkStateChangeEventMutex;
    std::mutex wifiScanChangeEventMutex;
    std::mutex settingsEnterEventMutex;
    std::mutex dataShareReadyEventMutex_;
    bool isCesEventSubscribered = false;
    std::shared_ptr<CesEventSubscriber> cesEventSubscriber_ = nullptr;
    std::shared_ptr<NotificationEventSubscriber> wifiNotificationSubsciber_ = nullptr;
    std::shared_ptr<NetworkStateChangeSubscriber> networkStateChangeSubsciber_ = nullptr;
    std::shared_ptr<WifiScanEventChangeSubscriber> wifiScanEventChangeSubscriber_ = nullptr;
    std::shared_ptr<SettingsEnterSubscriber> settingsEnterSubscriber_ = nullptr;
    std::shared_ptr<DataShareReadySubscriber> dataShareReadySubscriber_ = nullptr;
#ifdef HAS_MOVEMENT_PART
    std::mutex deviceMovementEventMutex;
#endif
    static bool mIsMdmForbidden;
    bool islocationModeObservered = false;
    std::mutex locationEventMutex;
    std::unique_ptr<WifiEventHandler> mWifiEventSubsThread = nullptr;
#ifdef SUPPORT_ClOUD_WIFI_ASSET
    std::shared_ptr<AssetEventSubscriber> wifiAssetrEventSubsciber_ = nullptr;
    std::mutex AssetEventMutex;
    uint32_t assetMgrId{0};
#endif

    bool accessDataShare_ = false;
    std::mutex accessDataShareMutex_;
    sptr<Rosen::DisplayManagerLite::IFoldStatusListener> foldStatusListener_ = nullptr;
    std::mutex foldStatusListenerMutex_;
    std::mutex networkConnSubscriberLock_;
    sptr<NetworkStateChangeSubscriber> networkConnSubscriber_ = nullptr;
};

}  // namespace Wifi
}  // namespace OHOS
#endif
#endif // OHOS_WIFI_EVENT_SUBSCRIBER_MANAGER_H
