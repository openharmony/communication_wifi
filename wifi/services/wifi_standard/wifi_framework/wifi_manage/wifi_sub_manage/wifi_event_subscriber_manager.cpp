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

#ifndef OHOS_ARCH_LITE
#include "wifi_event_subscriber_manager.h"
#include "wifi_manager.h"
#include "wifi_service_manager.h"
#include "wifi_config_center.h"
#include "wifi_logger.h"
#include "wifi_protect_manager.h"
#include "wifi_global_func.h"
#include "wifi_system_timer.h"
#include "common_event_support.h"
#include "wifi_datashare_utils.h"
#include "wifi_location_mode_observer.h"
#ifdef HAS_POWERMGR_PART
#include "wifi_power_state_listener.h"
#include "suspend/sleep_priority.h"
#endif
#ifdef HAS_MOVEMENT_PART
#include "wifi_msdp_state_listener.h"
#endif

DEFINE_WIFILOG_LABEL("WifiEventSubscriberManager");

namespace OHOS {
namespace Wifi {
constexpr uint32_t TIMEOUT_EVENT_SUBSCRIBER = 3000;
constexpr uint32_t TIMEOUT_CHECK_LAST_STA_STATE_EVENT = 10 * 1000;
constexpr uint32_t PROP_LEN = 26;
constexpr uint32_t PROP_SUBCHIPTYPE_LEN = 10;
constexpr uint32_t SUPPORT_COEXCHIP_LEN = 7;
constexpr uint32_t PROP_TRUE_LEN = 4;
constexpr uint32_t PROP_FALSE_LEN = 5;
const std::string PROP_TRUE = "true";
const std::string PROP_FALSE = "false";
const std::string SUBCHIP_WIFI_PROP = "ohos.boot.odm.conn.schiptype";
const std::string MDM_WIFI_PROP = "persist.edm.wifi_enable";
const std::string SUPPORT_COEXCHIP = "bisheng";
const std::string COEX_IFACENAME = "wlan1";

bool WifiEventSubscriberManager::mIsMdmForbidden = false;
static sptr<WifiLocationModeObserver> locationModeObserver_ = nullptr;
#ifdef HAS_POWERMGR_PART
static sptr<WifiPowerStateListener> powerStateListener_ = nullptr;
#endif
#ifdef HAS_MOVEMENT_PART
static sptr<DeviceMovementCallback> deviceMovementCallback_ = nullptr;
#endif

WifiEventSubscriberManager::WifiEventSubscriberManager()
{
    WIFI_LOGI("create WifiEventSubscriberManager");
    if (!isScreenEventSubscribered && screenTimerId == 0) {
        WifiTimer::TimerCallback timeoutCallback = std::bind(&WifiEventSubscriberManager::RegisterScreenEvent, this);
        WifiTimer::GetInstance()->Register(timeoutCallback, screenTimerId, TIMEOUT_EVENT_SUBSCRIBER, false);
        WIFI_LOGI("RegisterScreenEvent success! screenTimerId:%{public}u", screenTimerId);
    }
    if (!isAirplaneModeEventSubscribered && airplaneModeTimerId == 0) {
        WifiTimer::TimerCallback timeoutCallback = std::bind(&WifiEventSubscriberManager::RegisterAirplaneModeEvent, this);
        WifiTimer::GetInstance()->Register(timeoutCallback, airplaneModeTimerId, TIMEOUT_EVENT_SUBSCRIBER, false);
        WIFI_LOGI("RegisterAirplaneModeEvent success! airplaneModeTimerId:%{public}u", airplaneModeTimerId);
    }
    if (!islocationModeObservered && locationTimerId == 0) {
        WifiTimer::TimerCallback timeoutCallback = std::bind(&WifiEventSubscriberManager::RegisterLocationEvent, this);
        WifiTimer::GetInstance()->Register(timeoutCallback, locationTimerId, TIMEOUT_EVENT_SUBSCRIBER, false);
        WIFI_LOGI("RegisterLocationEvent success! locationTimerId:%{public}u", locationTimerId);
    }
    if (batterySubscriber_ == nullptr && batteryTimerId == 0) {
        WifiTimer::TimerCallback timeoutCallback = std::bind(&WifiEventSubscriberManager::RegisterBatteryEvent, this);
        WifiTimer::GetInstance()->Register(timeoutCallback, batteryTimerId, TIMEOUT_EVENT_SUBSCRIBER, false);
        WIFI_LOGI("RegisterBatteryEvent success! locationTimerId:%{public}u", batteryTimerId);
    }
    if (eventSubscriber_ == nullptr && appEventTimerId == 0) {
        WifiTimer::TimerCallback timeoutCallback = std::bind(&WifiEventSubscriberManager::RegisterAppRemoved, this);
        WifiTimer::GetInstance()->Register(timeoutCallback, appEventTimerId, TIMEOUT_EVENT_SUBSCRIBER, false);
    }

    if (thermalLevelSubscriber_ == nullptr && thermalTimerId == 0) {
        WifiTimer::TimerCallback timeoutCallback = std::bind(&WifiEventSubscriberManager::RegisterThermalLevel, this);
        WifiTimer::GetInstance()->Register(timeoutCallback, thermalTimerId, TIMEOUT_EVENT_SUBSCRIBER, false);
    }
    if (!std::filesystem::exists(WIFI_CONFIG_FILE_PATH) && migrateTimerId == 0) {
        WifiTimer::TimerCallback timeoutCallback = std::bind(&WifiEventSubscriberManager::CheckAndStartStaByDatashare, this);
        WifiTimer::GetInstance()->Register(timeoutCallback, migrateTimerId, TIMEOUT_CHECK_LAST_STA_STATE_EVENT);
        WIFI_LOGI("CheckAndStartStaByDatashare register success! migrateTimerId:%{public}u", migrateTimerId);
    }
#ifdef HAS_POWERMGR_PART
    if (!isPowerStateListenerSubscribered) {
        RegisterPowerStateListener();
    }
#endif
    InitSubscribeListener();
    GetMdmProp();
    GetChipProp();
    RegisterMdmPropListener();
}

WifiEventSubscriberManager::~WifiEventSubscriberManager()
{
    WIFI_LOGI("~WifiEventSubscriberManager");
    if (isScreenEventSubscribered) {
        UnRegisterScreenEvent();
    }
    if (isAirplaneModeEventSubscribered) {
        UnRegisterAirplaneModeEvent();
    }
    if (islocationModeObservered) {
        UnRegisterLocationEvent();
    }
    if (batterySubscriber_) {
        UnRegisterBatteryEvent();
    }
    if (eventSubscriber_) {
        UnRegisterAppRemoved();
    }
    if (thermalLevelSubscriber_) {
        UnRegisterThermalLevel();
    }
#ifdef HAS_POWERMGR_PART
    if (isPowerStateListenerSubscribered) {
        UnRegisterPowerStateListener();
    }
#endif
}

void WifiEventSubscriberManager::OnSystemAbilityChanged(int systemAbilityId, bool add)
{
    switch (systemAbilityId) {
        case COMM_NET_CONN_MANAGER_SYS_ABILITY_ID: {
            if (!add) {
                break;
            }
            for (int i = 0; i < STA_INSTANCE_MAX_NUM; ++i) {
                IStaService *pService = WifiServiceManager::GetInstance().GetStaServiceInst(i);
                if (pService != nullptr) {
                    pService->OnSystemAbilityChanged(systemAbilityId, add);
                }
            }
            break;
        }
        case COMMON_EVENT_SERVICE_ID: {
            if (add) {
                RegisterScreenEvent();
                RegisterAirplaneModeEvent();
            } else {
                UnRegisterScreenEvent();
                UnRegisterAirplaneModeEvent();
                UnRegisterLocationEvent();
            }

            WIFI_LOGI("OnSystemAbilityChanged, id[%{public}d], mode=[%{public}d]!",
                systemAbilityId, add);
            for (int i = 0; i < STA_INSTANCE_MAX_NUM; ++i) {
                IScanService *pService = WifiServiceManager::GetInstance().GetScanServiceInst(i);
                if (pService != nullptr) {
                    pService->OnSystemAbilityChanged(systemAbilityId, add);
                }
            }
            break;
        }
#ifdef HAS_POWERMGR_PART
        case POWER_MANAGER_SERVICE_ID: {
            if (add) {
                RegisterPowerStateListener();
            } else {
                UnRegisterPowerStateListener();
            }

            WIFI_LOGI("OnSystemAbilityChanged, id[%{public}d], mode=[%{public}d]!",
                systemAbilityId, add);

            break;
        }
#endif
#ifdef HAS_MOVEMENT_PART
        case MSDP_MOVEMENT_SERVICE_ID: {
            if (add) {
                RegisterMovementCallBack();
            } else {
                UnRegisterMovementCallBack();
            }
            break;
        }
#endif
        case DISTRIBUTED_KV_DATA_SERVICE_ABILITY_ID:
            if (!add) {
                break;
            }
            RegisterLocationEvent();
            break;
        default:
            break;
    }
}

void WifiEventSubscriberManager::GetAirplaneModeByDatashare()
{
    auto datashareHelper = DelayedSingleton<WifiDataShareHelperUtils>::GetInstance();
    if (datashareHelper == nullptr) {
        WIFI_LOGE("GetAirplaneModeByDatashare, datashareHelper is nullptr!");
        return;
    }

    std::string airplaneMode;
    Uri uri(SETTINGS_DATASHARE_URL_AIRPLANE_MODE);
    int ret = datashareHelper->Query(uri, SETTINGS_DATASHARE_KEY_AIRPLANE_MODE, airplaneMode);
    if (ret != WIFI_OPT_SUCCESS) {
        WIFI_LOGE("GetAirplaneModeByDatashare, Query airplaneMode fail!");
        return;
    }

    WIFI_LOGD("GetAirplaneModeByDatashare, airplaneMode:%{public}s", airplaneMode.c_str());
    if (airplaneMode.compare("1") == 0) {
        WifiConfigCenter::GetInstance().SetAirplaneModeState(MODE_STATE_OPEN);
    }
    return;
}

bool WifiEventSubscriberManager::GetLocationModeByDatashare()
{
    auto datashareHelper = DelayedSingleton<WifiDataShareHelperUtils>::GetInstance();
    if (datashareHelper == nullptr) {
        WIFI_LOGE("GetLocationModeByDatashare, datashareHelper is nullptr!");
        return false;
    }

    std::string locationMode;
    Uri uri(datashareHelper->GetLoactionDataShareUri());
    int ret = datashareHelper->Query(uri, SETTINGS_DATASHARE_KEY_LOCATION_MODE, locationMode);
    if (ret != WIFI_OPT_SUCCESS) {
        WIFI_LOGE("GetLocationModeByDatashare, Query locationMode fail!");
        return false;
    }

    WIFI_LOGD("GetLocationModeByDatashare, locationMode:%{public}s", locationMode.c_str());
    return (locationMode.compare("1") == 0);
}

void WifiEventSubscriberManager::DealLocationModeChangeEvent()
{
    if (GetLocationModeByDatashare()) {
        WIFI_LOGI("DealLocationModeChangeEvent open");
        WifiManager::GetInstance().GetWifiTogglerManager()->ScanOnlyToggled(1);
    } else {
        WIFI_LOGI("DealLocationModeChangeEvent close");
        WifiManager::GetInstance().GetWifiTogglerManager()->ScanOnlyToggled(0);
    }
}

void WifiEventSubscriberManager::CheckAndStartStaByDatashare()
{
    constexpr int openWifi = 1;
    constexpr int openWifiInAirplanemode = 2;
    constexpr int closeWifiByAirplanemodeOpen = 3;

    int lastStaState = GetLastStaStateByDatashare();
    if (lastStaState == openWifi) {
        WifiSettings::GetInstance().SetWifiToggledState(true);
        WifiManager::GetInstance().GetWifiTogglerManager()->WifiToggled(1, 0);
    } else if (lastStaState == openWifiInAirplanemode) {
        WifiConfigCenter::GetInstance().SetOpenWifiWhenAirplaneMode(true);
        WifiSettings::GetInstance().SetWifiToggledState(true);
        WifiManager::GetInstance().GetWifiTogglerManager()->WifiToggled(1, 0);
    } else if (lastStaState == closeWifiByAirplanemodeOpen) {
        WifiSettings::GetInstance().SetWifiToggledState(true);
    }
    std::unique_lock<std::mutex> lock(settingsMigrateMutex);
    WifiTimer::GetInstance()->UnRegister(migrateTimerId);
    migrateTimerId = 0;
}

bool WifiEventSubscriberManager::IsMdmForbidden()
{
    return mIsMdmForbidden;
}

void WifiEventSubscriberManager::InitSubscribeListener()
{
    SubscribeSystemAbility(COMM_NET_CONN_MANAGER_SYS_ABILITY_ID);
    SubscribeSystemAbility(COMMON_EVENT_SERVICE_ID);
#ifdef HAS_POWERMGR_PART
    SubscribeSystemAbility(POWER_MANAGER_SERVICE_ID);
#endif
#ifdef HAS_MOVEMENT_PART
    SubscribeSystemAbility(MSDP_MOVEMENT_SERVICE_ID);
#endif
    SubscribeSystemAbility(DISTRIBUTED_KV_DATA_SERVICE_ABILITY_ID);  // data management service done
}

int WifiEventSubscriberManager::GetLastStaStateByDatashare()
{
    auto datashareHelper = DelayedSingleton<WifiDataShareHelperUtils>::GetInstance();
    if (datashareHelper == nullptr) {
        WIFI_LOGE("GetLastStaStateByDatashare, datashareHelper is nullptr!");
        return 0;
    }

    std::string lastStaState;
    Uri uri(SETTINGS_DATASHARE_URI_WIFI_ON);
    int ret = datashareHelper->Query(uri, SETTINGS_DATASHARE_KEY_WIFI_ON, lastStaState);
    if (ret != WIFI_OPT_SUCCESS) {
        WIFI_LOGE("GetLastStaStateByDatashare, Query lastStaState fail!");
        return 0;
    }

    WIFI_LOGI("GetLastStaStateByDatashare, lastStaState:%{public}s", lastStaState.c_str());
    int lastStaStateType = ConvertStringToInt(lastStaState);
    return lastStaStateType;
}

void WifiEventSubscriberManager::RegisterScreenEvent()
{
    std::unique_lock<std::mutex> lock(screenEventMutex);
    if (isScreenEventSubscribered) {
        return;
    }
    OHOS::EventFwk::MatchingSkills matchingSkills;
    matchingSkills.AddEvent(OHOS::EventFwk::CommonEventSupport::COMMON_EVENT_SCREEN_ON);
    matchingSkills.AddEvent(OHOS::EventFwk::CommonEventSupport::COMMON_EVENT_SCREEN_OFF);
    EventFwk::CommonEventSubscribeInfo subscriberInfo(matchingSkills);
    screenEventSubscriber_ = std::make_shared<ScreenEventSubscriber>(subscriberInfo);
    if (!EventFwk::CommonEventManager::SubscribeCommonEvent(screenEventSubscriber_)) {
        WIFI_LOGE("ScreenEvent SubscribeCommonEvent() failed");
    } else {
        WIFI_LOGI("ScreenEvent SubscribeCommonEvent() OK");
        isScreenEventSubscribered = true;
        WifiTimer::GetInstance()->UnRegister(screenTimerId);
    }
}

void WifiEventSubscriberManager::UnRegisterScreenEvent()
{
    std::unique_lock<std::mutex> lock(screenEventMutex);
    if (!isScreenEventSubscribered) {
        return;
    }
    if (!EventFwk::CommonEventManager::UnSubscribeCommonEvent(screenEventSubscriber_)) {
        WIFI_LOGE("ScreenEvent UnSubscribeCommonEvent() failed");
    } else {
        WIFI_LOGI("ScreenEvent UnSubscribeCommonEvent() OK");
        isScreenEventSubscribered = false;
    }
}

void WifiEventSubscriberManager::RegisterAirplaneModeEvent()
{
    std::unique_lock<std::mutex> lock(airplaneModeEventMutex);
    if (isAirplaneModeEventSubscribered) {
        return;
    }
    OHOS::EventFwk::MatchingSkills matchingSkills;
    matchingSkills.AddEvent(OHOS::EventFwk::CommonEventSupport::COMMON_EVENT_AIRPLANE_MODE_CHANGED);
    EventFwk::CommonEventSubscribeInfo subscriberInfo(matchingSkills);
    subscriberInfo.SetPriority(1);
    airplaneModeEventSubscriber_ = std::make_shared<AirplaneModeEventSubscriber>(subscriberInfo);
    if (!EventFwk::CommonEventManager::SubscribeCommonEvent(airplaneModeEventSubscriber_)) {
        WIFI_LOGE("AirplaneModeEvent SubscribeCommonEvent() failed");
    } else {
        WIFI_LOGI("AirplaneModeEvent SubscribeCommonEvent() OK");
        isAirplaneModeEventSubscribered = true;
        WifiTimer::GetInstance()->UnRegister(airplaneModeTimerId);
    }
}

void WifiEventSubscriberManager::UnRegisterAirplaneModeEvent()
{
    std::unique_lock<std::mutex> lock(airplaneModeEventMutex);
    if (!isAirplaneModeEventSubscribered) {
        return;
    }
    if (!EventFwk::CommonEventManager::UnSubscribeCommonEvent(airplaneModeEventSubscriber_)) {
        WIFI_LOGE("AirplaneModeEvent UnSubscribeCommonEvent() failed");
    } else {
        WIFI_LOGI("AirplaneModeEvent UnSubscribeCommonEvent() OK");
        isAirplaneModeEventSubscribered = false;
    }
}

void WifiEventSubscriberManager::RegisterLocationEvent()
{
    std::unique_lock<std::mutex> lock(locationEventMutex);
    if (islocationModeObservered) {
        return;
    }

    auto datashareHelper = DelayedSingleton<WifiDataShareHelperUtils>::GetInstance();
    if (datashareHelper == nullptr) {
        WIFI_LOGE("LocationEvent datashareHelper is nullptr");
        return;
    }
    locationModeObserver_ = sptr<WifiLocationModeObserver>(new (std::nothrow)WifiLocationModeObserver());
    Uri uri(datashareHelper->GetLoactionDataShareUri());
    datashareHelper->RegisterObserver(uri, locationModeObserver_);
    islocationModeObservered = true;
    WIFI_LOGI("registerLocationEvent success");
}

void WifiEventSubscriberManager::UnRegisterLocationEvent()
{
    std::unique_lock<std::mutex> lock(locationEventMutex);
    if (!islocationModeObservered) {
        WIFI_LOGE("UnRegisterLocationEvent islocationModeObservered is false");
        return;
    }

    auto datashareHelper = DelayedSingleton<WifiDataShareHelperUtils>::GetInstance();
    if (datashareHelper == nullptr) {
        WIFI_LOGE("UnRegisterLocationEvent datashareHelper is nullptr");
        return;
    }
    Uri uri(datashareHelper->GetLoactionDataShareUri());
    datashareHelper->UnRegisterObserver(uri, locationModeObserver_);
    islocationModeObservered = false;
}

void WifiEventSubscriberManager::RegisterBatteryEvent()
{
    std::unique_lock<std::mutex> lock(batteryEventMutex);
    if (batterySubscriber_) {
        return;
    }
    OHOS::EventFwk::MatchingSkills matchingSkills;
    matchingSkills.AddEvent(OHOS::EventFwk::CommonEventSupport::COMMON_EVENT_POWER_CONNECTED);
    matchingSkills.AddEvent(OHOS::EventFwk::CommonEventSupport::COMMON_EVENT_POWER_DISCONNECTED);
    EventFwk::CommonEventSubscribeInfo subscriberInfo(matchingSkills);
    batterySubscriber_ = std::make_shared<BatteryEventSubscriber>(subscriberInfo);
    if (!EventFwk::CommonEventManager::SubscribeCommonEvent(batterySubscriber_)) {
        WIFI_LOGE("BatteryEvent SubscribeCommonEvent() failed");
    } else {
        WIFI_LOGI("BatteryEvent SubscribeCommonEvent() OK");
        WifiTimer::GetInstance()->UnRegister(batteryTimerId);
    }
}

void WifiEventSubscriberManager::UnRegisterBatteryEvent()
{
    std::unique_lock<std::mutex> lock(batteryEventMutex);
    if (!batterySubscriber_) {
        return;
    }
    if (!EventFwk::CommonEventManager::UnSubscribeCommonEvent(batterySubscriber_)) {
        WIFI_LOGE("BatteryEvent UnSubscribeCommonEvent() failed");
    } else {
        WIFI_LOGI("BatteryEvent UnSubscribeCommonEvent() OK");
    }
}

void WifiEventSubscriberManager::GetMdmProp()
{
    char preValue[PROP_FALSE_LEN + 1] = {0};

    int errorCode = GetParamValue(MDM_WIFI_PROP.c_str(), 0, preValue, PROP_FALSE_LEN + 1);
    if (errorCode > 0) {
        if (strncmp(preValue, PROP_TRUE.c_str(), PROP_TRUE_LEN) == 0) {
            mIsMdmForbidden = true;
        }
    }
}

void WifiEventSubscriberManager::GetChipProp()
{
    char preValue[PROP_SUBCHIPTYPE_LEN] = {0};
    int errorCode = GetParamValue(SUBCHIP_WIFI_PROP.c_str(), 0, preValue, PROP_SUBCHIPTYPE_LEN);
    if (errorCode > 0) {
        if (strncmp(preValue, SUPPORT_COEXCHIP.c_str(), SUPPORT_COEXCHIP_LEN) == 0) {
            WifiSettings::GetInstance().SetApIfaceName(COEX_IFACENAME);
            WifiSettings::GetInstance().SetCoexSupport(true);
        }
    }
}

void WifiEventSubscriberManager::RegisterMdmPropListener()
{
    int ret = WatchParamValue(MDM_WIFI_PROP.c_str(), MdmPropChangeEvt, nullptr);
    if (ret != 0) {
        WIFI_LOGI("RegisterMdmPropListener failed");
    }
}

void WifiEventSubscriberManager::MdmPropChangeEvt(const char *key, const char *value, void *context)
{
    if (strncmp(key, MDM_WIFI_PROP.c_str(), PROP_LEN) != 0) {
        WIFI_LOGI("not mdm prop change");
        return;
    }
    WIFI_LOGI("mdm prop change");
    if (strncmp(value, PROP_TRUE.c_str(), PROP_TRUE_LEN) == 0) {
        mIsMdmForbidden = true;
        return;
    }
    if (strncmp(value, PROP_FALSE.c_str(), PROP_FALSE_LEN) == 0) {
        mIsMdmForbidden = false;
    }
}

#ifdef HAS_POWERMGR_PART
void WifiEventSubscriberManager::RegisterPowerStateListener()
{
    WIFI_LOGD("Enter RegisterPowerStateListener");
    std::unique_lock<std::mutex> lock(powerStateEventMutex);
    if (isPowerStateListenerSubscribered) {
        WIFI_LOGI("RegisterPowerStateListener, powerStateListener_ already exist!");
        return;
    }

    auto& powerManagerClient = OHOS::PowerMgr::PowerMgrClient::GetInstance();
    powerStateListener_ = new (std::nothrow) WifiPowerStateListener();
    if (!powerStateListener_) {
        WIFI_LOGE("RegisterPowerStateListener, create power state listener failed");
        return;
    }

    bool ret = powerManagerClient.RegisterSyncSleepCallback(powerStateListener_, SleepPriority::HIGH);
    if (!ret) {
        WIFI_LOGE("RegisterPowerStateListener, register power state callback failed");
    } else {
        WIFI_LOGI("RegisterPowerStateListener OK!");
        isPowerStateListenerSubscribered = true;
    }
}

void WifiEventSubscriberManager::UnRegisterPowerStateListener()
{
    WIFI_LOGD("Enter UnRegisterPowerStateListener");
    std::unique_lock<std::mutex> lock(powerStateEventMutex);
    if (!isPowerStateListenerSubscribered) {
        WIFI_LOGE("UnRegisterPowerStateListener, powerStateListener_ is nullptr");
        return;
    }

    auto& powerManagerClient = OHOS::PowerMgr::PowerMgrClient::GetInstance();
    bool ret = powerManagerClient.UnRegisterSyncSleepCallback(powerStateListener_);
    if (!ret) {
        WIFI_LOGE("UnRegisterPowerStateListener, unregister power state callback failed");
    } else {
        isPowerStateListenerSubscribered = false;
        WIFI_LOGI("UnRegisterPowerStateListener OK!");
    }
}
#endif

void WifiEventSubscriberManager::RegisterAppRemoved()
{
    std::unique_lock<std::mutex> lock(appEventMutex);
    if (eventSubscriber_) {
        return;
    }
    OHOS::EventFwk::MatchingSkills matchingSkills;
    matchingSkills.AddEvent(OHOS::EventFwk::CommonEventSupport::COMMON_EVENT_PACKAGE_REMOVED);
    EventFwk::CommonEventSubscribeInfo subscriberInfo(matchingSkills);
    eventSubscriber_ = std::make_shared<AppEventSubscriber>(subscriberInfo);
    if (!EventFwk::CommonEventManager::SubscribeCommonEvent(eventSubscriber_)) {
        WIFI_LOGE("AppEvent SubscribeCommonEvent() failed");
    } else {
        WIFI_LOGI("AppEvent SubscribeCommonEvent() OK");
        WifiTimer::GetInstance()->UnRegister(appEventTimerId);
    }
}

void WifiEventSubscriberManager::UnRegisterAppRemoved()
{
    std::unique_lock<std::mutex> lock(appEventMutex);
    if (!eventSubscriber_) {
        return;
    }
    if (!EventFwk::CommonEventManager::UnSubscribeCommonEvent(eventSubscriber_)) {
        WIFI_LOGE("AppEvent UnSubscribeCommonEvent() failed");
    } else {
        WIFI_LOGI("AppEvent UnSubscribeCommonEvent() OK");
    }
}

void WifiEventSubscriberManager::RegisterThermalLevel()
{
    std::unique_lock<std::mutex> lock(thermalEventMutex);
    if (thermalLevelSubscriber_) {
        return;
    }
    OHOS::EventFwk::MatchingSkills matchingSkills;
    matchingSkills.AddEvent(OHOS::EventFwk::CommonEventSupport::COMMON_EVENT_THERMAL_LEVEL_CHANGED);
    EventFwk::CommonEventSubscribeInfo subscriberInfo(matchingSkills);
    thermalLevelSubscriber_ = std::make_shared<ThermalLevelSubscriber>(subscriberInfo);
    if (!EventFwk::CommonEventManager::SubscribeCommonEvent(thermalLevelSubscriber_)) {
        WIFI_LOGE("THERMAL_LEVEL_CHANGED SubscribeCommonEvent() failed");
    } else {
        WIFI_LOGI("THERMAL_LEVEL_CHANGED SubscribeCommonEvent() OK");
        WifiTimer::GetInstance()->UnRegister(thermalTimerId);
    }
}

void WifiEventSubscriberManager::UnRegisterThermalLevel()
{
    std::unique_lock<std::mutex> lock(thermalEventMutex);
    if (!thermalLevelSubscriber_) {
        return;
    }
    if (!EventFwk::CommonEventManager::UnSubscribeCommonEvent(thermalLevelSubscriber_)) {
        WIFI_LOGE("THERMAL_LEVEL_CHANGED UnSubscribeCommonEvent() failed");
    } else {
        WIFI_LOGI("THERMAL_LEVEL_CHANGED UnSubscribeCommonEvent() OK");
    }
}

#ifdef HAS_MOVEMENT_PART
void WifiEventSubscriberManager::RegisterMovementCallBack()
{
    WIFI_LOGI("RegisterMovementCallBack");
    if (!deviceMovementCallback_) {
        deviceMovementCallback_ = sptr<DeviceMovementCallback>(new DeviceMovementCallback());
    }
    if (Msdp::MovementClient::GetInstance().SubscribeCallback(
        Msdp::MovementDataUtils::MovementType::TYPE_STILL, deviceMovementCallback_) != ERR_OK) {
        WIFI_LOGE("Register a device movement observer failed!");
    }
}

void WifiEventSubscriberManager::UnRegisterMovementCallBack()
{
    WIFI_LOGI("UnRegisterMovementCallBack");
    if (!deviceMovementCallback_) {
        return;
    }
    Msdp::MovementClient::GetInstance().UnSubscribeCallback(
        Msdp::MovementDataUtils::MovementType::TYPE_STILL, deviceMovementCallback_);
    deviceMovementCallback_ = nullptr;
}
#endif

ScreenEventSubscriber::ScreenEventSubscriber(const OHOS::EventFwk::CommonEventSubscribeInfo &subscriberInfo)
    : CommonEventSubscriber(subscriberInfo)
{
    WIFI_LOGI("ScreenEventSubscriber enter");
}

ScreenEventSubscriber::~ScreenEventSubscriber()
{
    WIFI_LOGI("~ScreenEventSubscriber enter");
}

void ScreenEventSubscriber::OnReceiveEvent(const OHOS::EventFwk::CommonEventData &data)
{
    std::string action = data.GetWant().GetAction();
    WIFI_LOGI("ScreenEventSubscriber::OnReceiveEvent: %{public}s.", action.c_str());

    int screenState = WifiSettings::GetInstance().GetScreenState();
    int screenStateNew = (action == OHOS::EventFwk::CommonEventSupport::COMMON_EVENT_SCREEN_ON)
        ? MODE_STATE_OPEN : MODE_STATE_CLOSE;
    WifiSettings::GetInstance().SetScreenState(screenStateNew);
    for (int i = 0; i < STA_INSTANCE_MAX_NUM; ++i) {
        IStaService *pService = WifiServiceManager::GetInstance().GetStaServiceInst(i);
        if (pService == nullptr) {
            WIFI_LOGE("sta service is NOT start!");
            return;
        }

        IScanService *pScanService = WifiServiceManager::GetInstance().GetScanServiceInst(i);
        if (pScanService == nullptr) {
            WIFI_LOGE("scan service is NOT start!");
            return;
        }
#ifndef OHOS_ARCH_LITE
        bool isScreenOn = (action == OHOS::EventFwk::CommonEventSupport::COMMON_EVENT_SCREEN_ON) ? true : false;
        WifiProtectManager::GetInstance().HandleScreenStateChanged(isScreenOn);
#endif
        if (action == OHOS::EventFwk::CommonEventSupport::COMMON_EVENT_SCREEN_OFF &&
            screenState == MODE_STATE_OPEN) {
            if (pScanService->OnScreenStateChanged(MODE_STATE_CLOSE) != WIFI_OPT_SUCCESS) {
                WIFI_LOGE("OnScreenStateChanged failed");
            }
            /* Send suspend to wpa */
            if (pService->SetSuspendMode(true) != WIFI_OPT_SUCCESS) {
                WIFI_LOGE("SetSuspendMode failed");
            }
            pService->OnScreenStateChanged(MODE_STATE_CLOSE);
#ifdef FEATURE_HPF_SUPPORT
            WifiManager::GetInstance().InstallPacketFilterProgram(screenState, i);
#endif
            return;
        }

        if (action == OHOS::EventFwk::CommonEventSupport::COMMON_EVENT_SCREEN_ON &&
            screenState == MODE_STATE_CLOSE) {
            if (pScanService->OnScreenStateChanged(MODE_STATE_OPEN) != WIFI_OPT_SUCCESS) {
                WIFI_LOGE("OnScreenStateChanged failed");
            }
            /* Send resume to wpa */
            if (pService->SetSuspendMode(false) != WIFI_OPT_SUCCESS) {
                WIFI_LOGE("SetSuspendMode failed");
            }
            pService->OnScreenStateChanged(MODE_STATE_OPEN);
#ifdef FEATURE_HPF_SUPPORT
            WifiManager::GetInstance().InstallPacketFilterProgram(screenState, i);
#endif
            return;
        }
    }
}

AirplaneModeEventSubscriber::AirplaneModeEventSubscriber(const OHOS::EventFwk::CommonEventSubscribeInfo &subscriberInfo)
        : CommonEventSubscriber(subscriberInfo)
{
    WIFI_LOGE("AirplaneModeEventSubscriber enter");
}

AirplaneModeEventSubscriber::~AirplaneModeEventSubscriber()
{
    WIFI_LOGE("~AirplaneModeEventSubscriber enter");
}

void AirplaneModeEventSubscriber::OnReceiveEvent(const OHOS::EventFwk::CommonEventData &eventData)
{
    const auto &action = eventData.GetWant().GetAction();
    const auto &data = eventData.GetData();
    const auto &code = eventData.GetCode();
    WIFI_LOGI("AirplaneModeEventSubscriber::OnReceiveEvent: %{public}s,  %{public}s,  %{public}d", action.c_str(),
        data.c_str(), code);
    if (action == OHOS::EventFwk::CommonEventSupport::COMMON_EVENT_AIRPLANE_MODE_CHANGED) {
        if (code == 1) {
            /* open airplane mode */
            WifiConfigCenter::GetInstance().SetAirplaneModeState(MODE_STATE_OPEN);
            WifiManager::GetInstance().GetWifiTogglerManager()->AirplaneToggled(1);
        } else {
            /* close airplane mode */
            WifiConfigCenter::GetInstance().SetAirplaneModeState(MODE_STATE_CLOSE);
            WifiManager::GetInstance().GetWifiTogglerManager()->AirplaneToggled(0);
        }
    }
}

BatteryEventSubscriber::BatteryEventSubscriber(const OHOS::EventFwk::CommonEventSubscribeInfo &subscriberInfo)
    : CommonEventSubscriber(subscriberInfo)
{
    WIFI_LOGI("BatteryEventSubscriber enter");
}

BatteryEventSubscriber::~BatteryEventSubscriber()
{
    WIFI_LOGI("~BatteryEventSubscriber exit");
}

void BatteryEventSubscriber::OnReceiveEvent(const OHOS::EventFwk::CommonEventData &data)
{
    std::string action = data.GetWant().GetAction();
    WIFI_LOGI("BatteryEventSubscriber::OnReceiveEvent: %{public}s.", action.c_str());
    if (action == OHOS::EventFwk::CommonEventSupport::COMMON_EVENT_POWER_CONNECTED) {
        WifiSettings::GetInstance().SetNoChargerPlugModeState(MODE_STATE_CLOSE);
    } else if (action == OHOS::EventFwk::CommonEventSupport::COMMON_EVENT_POWER_DISCONNECTED) {
        WifiSettings::GetInstance().SetNoChargerPlugModeState(MODE_STATE_OPEN);
    }
    for (int i = 0; i < AP_INSTANCE_MAX_NUM; ++i) {
        IApService *pService = WifiServiceManager::GetInstance().GetApServiceInst(i);
        if (pService == nullptr) {
            WIFI_LOGE("ap service is NOT start!");
            return;
        }

        if (action == OHOS::EventFwk::CommonEventSupport::COMMON_EVENT_POWER_CONNECTED) {
            WIFI_LOGE("usb connect do not stop hostapd!");
            WifiManager::GetInstance().GetWifiTogglerManager()->GetControllerMachine()->StopSoftapCloseTimer();
            return;
        }

        if (action == OHOS::EventFwk::CommonEventSupport::COMMON_EVENT_POWER_DISCONNECTED) {
            WIFI_LOGE("usb disconnect stop hostapd!");
            std::vector<StationInfo> result;
            IApService *pService = WifiServiceManager::GetInstance().GetApServiceInst(0);
            if (pService == nullptr) {
                WIFI_LOGE("get hotspot service is null!");
                return;
            }
            ErrCode errCode = pService->GetStationList(result);
            if (errCode != ErrCode::WIFI_OPT_SUCCESS) {
                return;
            }
            if (result.empty()) {
                WifiManager::GetInstance().GetWifiTogglerManager()->GetControllerMachine()->StartSoftapCloseTimer();
            }
            return;
        }
    }
}

AppEventSubscriber::AppEventSubscriber(const OHOS::EventFwk::CommonEventSubscribeInfo &subscriberInfo)
    : CommonEventSubscriber(subscriberInfo)
{
    WIFI_LOGI("AppEventSubscriber enter");
}

AppEventSubscriber::~AppEventSubscriber()
{
    WIFI_LOGI("~AppEventSubscriber enter");
}

void AppEventSubscriber::OnReceiveEvent(const OHOS::EventFwk::CommonEventData &data)
{
    std::string action = data.GetWant().GetAction();
    WIFI_LOGI("AppEventSubscriber::OnReceiveEvent : %{public}s.", action.c_str());
    if (action == OHOS::EventFwk::CommonEventSupport::COMMON_EVENT_PACKAGE_REMOVED) {
        auto wantTemp = data.GetWant();
        auto uid = wantTemp.GetIntParam(AppExecFwk::Constants::UID, -1);
        if (uid == -1) {
            WIFI_LOGE("%{public}s getPackage uid is illegal.", __func__);
            return;
        }
        WIFI_LOGI("Package removed of uid %{public}d.", uid);
        for (int i = 0; i < STA_INSTANCE_MAX_NUM; ++i) {
            IStaService *pService = WifiServiceManager::GetInstance().GetStaServiceInst(i);
            if (pService == nullptr) {
                WIFI_LOGI("Sta service not opend!");
                std::vector<WifiDeviceConfig> tempConfigs;
                WifiSettings::GetInstance().GetAllCandidateConfig(uid, tempConfigs);
                for (const auto &config : tempConfigs) {
                    if (WifiSettings::GetInstance().RemoveDevice(config.networkId) != WIFI_OPT_SUCCESS) {
                        WIFI_LOGE("RemoveAllCandidateConfig-RemoveDevice() failed!");
                    }
                }
                WifiSettings::GetInstance().SyncDeviceConfig();
                return;
            }
            if (pService->RemoveAllCandidateConfig(uid) != WIFI_OPT_SUCCESS) {
                WIFI_LOGE("RemoveAllCandidateConfig failed");
            }
        }
    }
}

ThermalLevelSubscriber::ThermalLevelSubscriber(const OHOS::EventFwk::CommonEventSubscribeInfo &subscriberInfo)
    : CommonEventSubscriber(subscriberInfo) 
{
    WIFI_LOGI("ThermalLevelSubscriber enter");
}

ThermalLevelSubscriber::~ThermalLevelSubscriber()
{
    WIFI_LOGI("~ThermalLevelSubscriber enter");
}

void ThermalLevelSubscriber::OnReceiveEvent(const OHOS::EventFwk::CommonEventData &data)
{
    std::string action = data.GetWant().GetAction();
    WIFI_LOGI("ThermalLevelSubscriber::OnReceiveEvent: %{public}s.", action.c_str());
    if (action == OHOS::EventFwk::CommonEventSupport::COMMON_EVENT_THERMAL_LEVEL_CHANGED) {
        static const std::string THERMAL_EVENT_ID = "0";
        int level = data.GetWant().GetIntParam(THERMAL_EVENT_ID, 0);
        WifiSettings::GetInstance().SetThermalLevel(level);
        WIFI_LOGI("ThermalLevelSubscriber SetThermalLevel: %{public}d.", level);
    }
}

}  // namespace Wifi
}  // namespace OHOS
#endif