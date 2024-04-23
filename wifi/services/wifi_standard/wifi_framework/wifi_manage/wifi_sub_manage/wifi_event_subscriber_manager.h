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

namespace OHOS {
namespace Wifi {
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
    bool lastSleepState = false;
};

class WifiEventSubscriberManager : public WifiSystemAbilityListener {
public:
    WifiEventSubscriberManager();
    virtual ~WifiEventSubscriberManager();

    void OnSystemAbilityChanged(int systemAbilityId, bool add) override;
    void GetAirplaneModeByDatashare();
    bool GetLocationModeByDatashare();
    void DealLocationModeChangeEvent();
    void DealCloneDataChangeEvent();
    void CheckAndStartStaByDatashare();
    bool IsMdmForbidden(void);

private:
    void InitSubscribeListener();
    bool IsDataMgrServiceActive();
    void HandleCommNetConnManagerSysChange(int systemAbilityId, bool add);
    void HandleCommonEventServiceChange(int systemAbilityId, bool add);
#ifdef HAS_POWERMGR_PART
    void HandlePowerManagerServiceChange(int systemAbilityId, bool add);
#endif
#ifdef HAS_MOVEMENT_PART
    void HandleHasMovementPartChange(int systemAbilityId, bool add);
#endif
    void HandleDistributedKvDataServiceChange(bool add);
    int GetLastStaStateByDatashare();
    void GetCloneDataByDatashare(std::string &cloneData);
    void SetCloneDataByDatashare(const std::string &cloneData);
    void RegisterCloneEvent();
    void UnRegisterCloneEvent();
    void RegisterCesEvent();
    void UnRegisterCesEvent();
    void RegisterLocationEvent();
    void UnRegisterLocationEvent();
    void GetMdmProp();
    void GetChipProp();
    void RegisterMdmPropListener();
    static void MdmPropChangeEvt(const char *key, const char *value, void *context);
    void RegisterPowerStateListener();
    void UnRegisterPowerStateListener();
#ifdef HAS_MOVEMENT_PART
    void RegisterMovementCallBack();
    void UnRegisterMovementCallBack();
#endif

private:
    std::mutex cloneEventMutex;
    uint32_t cesTimerId{0};
    uint32_t migrateTimerId{0};
    std::mutex cesEventMutex;
    bool isCesEventSubscribered = false;
    std::shared_ptr<CesEventSubscriber> cesEventSubscriber_ = nullptr;
#ifdef HAS_POWERMGR_PART
    std::mutex powerStateEventMutex;
#endif
#ifdef HAS_MOVEMENT_PART
    std::mutex deviceMovementEventMutex;
#endif
    static bool mIsMdmForbidden;
    bool isPowerStateListenerSubscribered = false;
    bool islocationModeObservered = false;
    std::mutex locationEventMutex;
    std::unique_ptr<WifiEventHandler> mWifiEventSubsThread = nullptr;
};

}  // namespace Wifi
}  // namespace OHOS
#endif
#endif // OHOS_WIFI_EVENT_SUBSCRIBER_MANAGER_H