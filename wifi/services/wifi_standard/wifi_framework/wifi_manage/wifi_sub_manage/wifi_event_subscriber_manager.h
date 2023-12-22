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

namespace OHOS {
namespace Wifi {
class ScreenEventSubscriber : public OHOS::EventFwk::CommonEventSubscriber {
public:
    explicit ScreenEventSubscriber(const OHOS::EventFwk::CommonEventSubscribeInfo &subscriberInfo);
    virtual ~ScreenEventSubscriber();
    void OnReceiveEvent(const OHOS::EventFwk::CommonEventData &data) override;
};

class AirplaneModeEventSubscriber : public OHOS::EventFwk::CommonEventSubscriber {
public:
    explicit AirplaneModeEventSubscriber(const OHOS::EventFwk::CommonEventSubscribeInfo &subscriberInfo);
    virtual ~AirplaneModeEventSubscriber();
    void OnReceiveEvent(const OHOS::EventFwk::CommonEventData &eventData) override;
};

class BatteryEventSubscriber : public OHOS::EventFwk::CommonEventSubscriber {
public:
    explicit BatteryEventSubscriber(const OHOS::EventFwk::CommonEventSubscribeInfo &subscriberInfo);
    ~BatteryEventSubscriber();
    void OnReceiveEvent(const OHOS::EventFwk::CommonEventData &eventData) override;
};

class AppEventSubscriber : public OHOS::EventFwk::CommonEventSubscriber {
public:
    explicit AppEventSubscriber(const OHOS::EventFwk::CommonEventSubscribeInfo &subscriberInfo);
    virtual ~AppEventSubscriber();
    virtual void OnReceiveEvent(const OHOS::EventFwk::CommonEventData &data) override;
};

class ThermalLevelSubscriber : public OHOS::EventFwk::CommonEventSubscriber {
public:
    explicit ThermalLevelSubscriber(const OHOS::EventFwk::CommonEventSubscribeInfo &subscriberInfo);
    virtual ~ThermalLevelSubscriber();
    void OnReceiveEvent(const OHOS::EventFwk::CommonEventData &data) override;
};


class WifiEventSubscriberManager : public WifiSystemAbilityListener {
public:
    WifiEventSubscriberManager();
    virtual ~WifiEventSubscriberManager();

    void OnSystemAbilityChanged(int systemAbilityId, bool add) override;
    void GetAirplaneModeByDatashare();
    void GetDeviceProvisionByDatashare();
    bool GetLocationModeByDatashare();
    void DealLocationModeChangeEvent();
    void CheckAndStartStaByDatashare();
    bool IsMdmForbidden(void);

private:
    void InitSubscribeListener();
    int GetLastStaStateByDatashare();
    void RegisterScreenEvent();
    void UnRegisterScreenEvent();
    void RegisterAirplaneModeEvent();
    void UnRegisterAirplaneModeEvent();
    void RegisterLocationEvent();
    void UnRegisterLocationEvent();
    void RegisterDeviceProvisionEvent();
    void UnRegisterDeviceProvisionEvent();
    void RegisterBatteryEvent();
    void UnRegisterBatteryEvent();
    void RegisterSettingsMigrateEvent();
    void UnRegisterSettingsMigrateEvent();
    void GetMdmProp();
    void GetChipProp();
    void RegisterMdmPropListener();
    static void MdmPropChangeEvt(const char *key, const char *value, void *context);
    void RegisterPowerStateListener();
    void UnRegisterPowerStateListener();
    void RegisterAppRemoved();
    void UnRegisterAppRemoved();
    void RegisterThermalLevel();
    void UnRegisterThermalLevel();
#ifdef HAS_MOVEMENT_PART
    void RegisterMovementCallBack();
    void UnRegisterMovementCallBack();
#endif

private:
    std::mutex screenEventMutex;
    std::mutex airplaneModeEventMutex;
    std::mutex locationEventMutex;
    std::mutex batteryEventMutex;
    std::mutex appEventMutex;
    std::mutex thermalEventMutex;
    std::mutex settingsMigrateMutex;
#ifdef HAS_POWERMGR_PART
    std::mutex powerStateEventMutex;
#endif
    uint32_t screenTimerId{0};
    bool isScreenEventSubscribered = false;
    std::shared_ptr<ScreenEventSubscriber> screenEventSubscriber_ = nullptr;
    uint32_t airplaneModeTimerId{0};
    bool isAirplaneModeEventSubscribered = false;
    std::shared_ptr<AirplaneModeEventSubscriber> airplaneModeEventSubscriber_ = nullptr;
    uint32_t batteryTimerId{0};
    std::shared_ptr<BatteryEventSubscriber> batterySubscriber_ = nullptr;
    bool isBatterySubscribered = false;
    uint32_t locationTimerId{0};
    uint32_t migrateTimerId{0};
    static bool mIsMdmForbidden;
    bool isPowerStateListenerSubscribered = false;
    bool islocationModeObservered = false;
    uint32_t appEventTimerId{0};
	std::shared_ptr<AppEventSubscriber> eventSubscriber_ = nullptr;
    bool isEventSubscribered = false;
    uint32_t thermalTimerId{0};
    std::shared_ptr<ThermalLevelSubscriber> thermalLevelSubscriber_ = nullptr;
    bool isThermalLevelSubscribered = false;
};

}  // namespace Wifi
}  // namespace OHOS
#endif
#endif // OHOS_WIFI_EVENT_SUBSCRIBER_MANAGER_H