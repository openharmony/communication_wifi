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
#include "wifi_global_func.h"
#include "wifi_system_timer.h"
#include "common_event_support.h"
#include "wifi_datashare_utils.h"
#include "wifi_location_mode_observer.h"
#include "wifi_common_util.h"
#include "wifi_settings.h"
#include "wifi_notification_util.h"
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
const std::string WIFI_STANDBY_NAP = "napped";
const std::string WIFI_STANDBY_SLEEPING = "sleeping";

bool WifiEventSubscriberManager::mIsMdmForbidden = false;
static sptr<WifiLocationModeObserver> locationModeObserver_ = nullptr;
static sptr<WifiCloneModeObserver> cloneModeObserver_ = nullptr;
#ifdef HAS_POWERMGR_PART
static sptr<WifiPowerStateListener> powerStateListener_ = nullptr;
#endif
#ifdef HAS_MOVEMENT_PART
static sptr<DeviceMovementCallback> deviceMovementCallback_ = nullptr;
#endif

using CesFuncType = void (CesEventSubscriber::*)(const OHOS::EventFwk::CommonEventData &eventData);

const std::map<std::string, CesFuncType> CES_REQUEST_MAP = {
    {OHOS::EventFwk::CommonEventSupport::COMMON_EVENT_SCREEN_ON, &CesEventSubscriber::OnReceiveScreenEvent},
    {OHOS::EventFwk::CommonEventSupport::COMMON_EVENT_SCREEN_OFF, &CesEventSubscriber::OnReceiveScreenEvent},
    {OHOS::EventFwk::CommonEventSupport::COMMON_EVENT_AIRPLANE_MODE_CHANGED, &
    CesEventSubscriber::OnReceiveAirplaneEvent},
    {OHOS::EventFwk::CommonEventSupport::COMMON_EVENT_POWER_CONNECTED, &
    CesEventSubscriber::OnReceiveBatteryEvent},
    {OHOS::EventFwk::CommonEventSupport::COMMON_EVENT_POWER_DISCONNECTED, &
    CesEventSubscriber::OnReceiveBatteryEvent},
    {OHOS::EventFwk::CommonEventSupport::COMMON_EVENT_PACKAGE_REMOVED, &CesEventSubscriber::OnReceiveAppEvent},
    {OHOS::EventFwk::CommonEventSupport::COMMON_EVENT_THERMAL_LEVEL_CHANGED, &
    CesEventSubscriber::OnReceiveThermalEvent},
    {OHOS::EventFwk::CommonEventSupport::COMMON_EVENT_DEVICE_IDLE_MODE_CHANGED, &
    CesEventSubscriber::OnReceiveStandbyEvent},
    {WIFI_EVENT_TAP_NOTIFICATION, &CesEventSubscriber::OnReceiveNotificationEvent}
};

WifiEventSubscriberManager::WifiEventSubscriberManager()
{
    WIFI_LOGI("create WifiEventSubscriberManager");

    RegisterCesEvent();

    if (!std::filesystem::exists(WIFI_CONFIG_FILE_PATH) && migrateTimerId == 0) {
        WifiTimer::TimerCallback timeoutCallback = std::bind(
            &WifiEventSubscriberManager::CheckAndStartStaByDatashare, this);
        WifiTimer::GetInstance()->Register(timeoutCallback, migrateTimerId, TIMEOUT_CHECK_LAST_STA_STATE_EVENT);
        WIFI_LOGI("CheckAndStartStaByDatashare register success! migrateTimerId:%{public}u", migrateTimerId);
    }
#ifdef HAS_POWERMGR_PART
    RegisterPowerStateListener();
#endif
    if (IsDataMgrServiceActive()) {
        RegisterCloneEvent();
    }
    InitSubscribeListener();
    GetMdmProp();
    GetChipProp();
    RegisterMdmPropListener();
    GetAirplaneModeByDatashare();
}

WifiEventSubscriberManager::~WifiEventSubscriberManager()
{
    WIFI_LOGI("~WifiEventSubscriberManager");
    UnRegisterCesEvent();
    UnRegisterCloneEvent();
    UnRegisterLocationEvent();
#ifdef HAS_POWERMGR_PART
    UnRegisterPowerStateListener();
#endif
}

void WifiEventSubscriberManager::RegisterCesEvent()
{
    std::unique_lock<std::mutex> lock(cesEventMutex);
    if (cesTimerId != 0) {
        WifiTimer::GetInstance()->UnRegister(cesTimerId);
    }
    if (isCesEventSubscribered) {
        return;
    }
    OHOS::EventFwk::MatchingSkills matchingSkills;
    for (auto itFunc : CES_REQUEST_MAP) {
        matchingSkills.AddEvent(itFunc.first);
    }
    WIFI_LOGI("RegisterCesEvent start");
    EventFwk::CommonEventSubscribeInfo subscriberInfo(matchingSkills);
    cesEventSubscriber_ = std::make_shared<CesEventSubscriber>(subscriberInfo);
    if (!EventFwk::CommonEventManager::SubscribeCommonEvent(cesEventSubscriber_)) {
        WIFI_LOGE("CesEvent SubscribeCommonEvent() failed");
        cesEventSubscriber_ = nullptr;
        WifiTimer::TimerCallback timeoutCallBack = std::bind(&WifiEventSubscriberManager::RegisterCesEvent, this);
        WifiTimer::GetInstance()->Register(timeoutCallBack, cesTimerId, TIMEOUT_EVENT_SUBSCRIBER, false);
        WIFI_LOGI("RegisterCesEvent retry, cesTimerId = %{public}u", cesTimerId);
    } else {
        WIFI_LOGI("RegisterCesEvent success");
        isCesEventSubscribered = true;
    }
}

void WifiEventSubscriberManager::UnRegisterCesEvent()
{
    std::unique_lock<std::mutex> lock(cesEventMutex);
    if (cesTimerId != 0) {
        WifiTimer::GetInstance()->UnRegister(cesTimerId);
    }
    if (!isCesEventSubscribered) {
        return;
    }
    if (!EventFwk::CommonEventManager::UnSubscribeCommonEvent(cesEventSubscriber_)) {
        WIFI_LOGE("UnRegisterCesEvent failed");
    }
    cesEventSubscriber_ = nullptr;
    isCesEventSubscribered = false;
    WIFI_LOGI("UnRegisterCesEvent finished");
}

void WifiEventSubscriberManager::HandleCommNetConnManagerSysChange(int systemAbilityId, bool add)
{
    if (!add) {
        return;
    }
    for (int i = 0; i < STA_INSTANCE_MAX_NUM; ++i) {
        IStaService *pService = WifiServiceManager::GetInstance().GetStaServiceInst(i);
        if (pService != nullptr) {
            pService->OnSystemAbilityChanged(systemAbilityId, add);
        }
    }
}

void WifiEventSubscriberManager::HandleCommonEventServiceChange(int systemAbilityId, bool add)
{
    WIFI_LOGI("OnSystemAbilityChanged, id[%{public}d], mode=[%{public}d]!", systemAbilityId, add);
    if (add) {
        RegisterCesEvent();
    } else {
        UnRegisterCesEvent();
    }
}

#ifdef HAS_POWERMGR_PART
void WifiEventSubscriberManager::HandlePowerManagerServiceChange(int systemAbilityId, bool add)
{
    if (add) {
        RegisterPowerStateListener();
    } else {
        UnRegisterPowerStateListener();
    }
    WIFI_LOGI("OnSystemAbilityChanged, id[%{public}d], mode=[%{public}d]!", systemAbilityId, add);
}
#endif

#ifdef HAS_MOVEMENT_PART
void WifiEventSubscriberManager::HandleHasMovementPartChange(int systemAbilityId, bool add)
{
    if (add) {
        RegisterMovementCallBack();
    } else {
        UnRegisterMovementCallBack();
    }
}
#endif

void WifiEventSubscriberManager::HandleDistributedKvDataServiceChange(bool add)
{
    if (!add) {
        UnRegisterCloneEvent();
        return;
    }
    RegisterLocationEvent();
    RegisterCloneEvent();
}

void WifiEventSubscriberManager::OnSystemAbilityChanged(int systemAbilityId, bool add)
{
    switch (systemAbilityId) {
        case COMM_NET_CONN_MANAGER_SYS_ABILITY_ID:
            HandleCommNetConnManagerSysChange(systemAbilityId, add);
            break;
        case COMMON_EVENT_SERVICE_ID:
            HandleCommonEventServiceChange(systemAbilityId, add);
            break;
#ifdef HAS_POWERMGR_PART
        case POWER_MANAGER_SERVICE_ID:
            HandlePowerManagerServiceChange(systemAbilityId, add);
            break;
#endif
#ifdef HAS_MOVEMENT_PART
        case MSDP_MOVEMENT_SERVICE_ID:
            HandleHasMovementPartChange(systemAbilityId, add);
            break;
#endif
        case DISTRIBUTED_KV_DATA_SERVICE_ABILITY_ID:
            HandleDistributedKvDataServiceChange(add);
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
        WifiConfigCenter::GetInstance().SetWifiStateOnAirplaneChanged(MODE_STATE_OPEN);
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

void WifiEventSubscriberManager::GetCloneDataByDatashare(std::string &cloneData)
{
    auto datashareHelper = DelayedSingleton<WifiDataShareHelperUtils>::GetInstance();
    if (datashareHelper == nullptr) {
        WIFI_LOGE("GetCloneDataByDatashare, datashareHelper is nullptr!");
        return;
    }

    Uri uri(SETTINGS_DATASHARE_URI_CLONE_DATA);
    int ret = datashareHelper->Query(uri, SETTINGS_DATASHARE_KEY_CLONE_DATA, cloneData);
    if (ret != WIFI_OPT_SUCCESS) {
        WIFI_LOGE("GetCloneDataByDatashare, Query cloneMode fail!");
        return;
    }
    WIFI_LOGI("GetCloneDataByDatashare success");
}

void WifiEventSubscriberManager::SetCloneDataByDatashare(const std::string &cloneData)
{
    auto datashareHelper = DelayedSingleton<WifiDataShareHelperUtils>::GetInstance();
    if (datashareHelper == nullptr) {
        WIFI_LOGE("SetCloneDataByDatashare, datashareHelper is nullptr!");
        return;
    }

    Uri uri(SETTINGS_DATASHARE_URI_CLONE_DATA);
    int ret = datashareHelper->Update(uri, SETTINGS_DATASHARE_KEY_CLONE_DATA, cloneData);
    if (ret != WIFI_OPT_SUCCESS) {
        WIFI_LOGE("SetCloneDataByDatashare, Update cloneData fail!");
        return;
    }
    WIFI_LOGI("SetCloneDataByDatashare success");
}

void WifiEventSubscriberManager::DealCloneDataChangeEvent()
{
    WIFI_LOGI("DealCloneDataChangeEvent enter");
    mWifiEventSubsThread = std::make_unique<WifiEventHandler>("WifiEventSubsThread");
    mWifiEventSubsThread->PostAsyncTask([this]() {
        std::string cloneData;
        GetCloneDataByDatashare(cloneData);
        if (cloneData.empty()) {
            return;
        }
        WifiSettings::GetInstance().MergeWifiCloneConfig(cloneData);
        cloneData.clear();
        SetCloneDataByDatashare("");
    });
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
        WifiConfigCenter::GetInstance().SetWifiFlagOnAirplaneMode(true);
        WifiSettings::GetInstance().SetWifiToggledState(true);
        WifiManager::GetInstance().GetWifiTogglerManager()->WifiToggled(1, 0);
    } else if (lastStaState == closeWifiByAirplanemodeOpen) {
        WifiSettings::GetInstance().SetWifiToggledState(true);
    }

    if (migrateTimerId != 0) {
        WifiTimer::GetInstance()->UnRegister(migrateTimerId);
        migrateTimerId = 0;
    }
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
    SubscribeSystemAbility(DISTRIBUTED_KV_DATA_SERVICE_ABILITY_ID);  // subscribe data management service done
}

bool WifiEventSubscriberManager::IsDataMgrServiceActive()
{
    sptr<ISystemAbilityManager> sa_mgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (sa_mgr == nullptr) {
        WIFI_LOGE("Failed to get SystemAbilityManager!");
        return false;
    }
    sptr<IRemoteObject> object = sa_mgr->CheckSystemAbility(DISTRIBUTED_KV_DATA_SERVICE_ABILITY_ID);
    if (object == nullptr) {
        WIFI_LOGE("Failed to get DataMgrService!");
        return false;
    }
    return true;
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
        WIFI_LOGW("Query lastStaState fail, query settingsdata again!");
        ret = datashareHelper->Query(uri, SETTINGS_DATASHARE_KEY_WIFI_ON, lastStaState, true);
        if (ret != WIFI_OPT_SUCCESS) {
            WIFI_LOGE("GetLastStaStateByDatashare Query lastStaState fail!");
            return 0;
        }
    }

    WIFI_LOGI("GetLastStaStateByDatashare, lastStaState:%{public}s", lastStaState.c_str());
    int lastStaStateType = ConvertStringToInt(lastStaState);
    return lastStaStateType;
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

void WifiEventSubscriberManager::RegisterCloneEvent()
{
    std::unique_lock<std::mutex> lock(cloneEventMutex);
    if (cloneModeObserver_) {
        return;
    }

    auto datashareHelper = DelayedSingleton<WifiDataShareHelperUtils>::GetInstance();
    if (datashareHelper == nullptr) {
        WIFI_LOGE("RegisterCloneEvent datashareHelper is nullptr");
        return;
    }
    cloneModeObserver_ = sptr<WifiCloneModeObserver>(new (std::nothrow)WifiCloneModeObserver());
    Uri uri(SETTINGS_DATASHARE_URI_CLONE_DATA);
    datashareHelper->RegisterObserver(uri, cloneModeObserver_);
    WIFI_LOGI("RegisterCloneEvent success");
}

void WifiEventSubscriberManager::UnRegisterCloneEvent()
{
    std::unique_lock<std::mutex> lock(cloneEventMutex);
    if (cloneModeObserver_ == nullptr) {
        WIFI_LOGE("UnRegisterCloneEvent cloneModeObserver_ is nullptr");
        return;
    }

    auto datashareHelper = DelayedSingleton<WifiDataShareHelperUtils>::GetInstance();
    if (datashareHelper == nullptr) {
        cloneModeObserver_ = nullptr;
        WIFI_LOGE("UnRegisterCloneEvent datashareHelper is nullptr");
        return;
    }
    Uri uri(SETTINGS_DATASHARE_URI_CLONE_DATA);
    datashareHelper->UnRegisterObserver(uri, cloneModeObserver_);
    cloneModeObserver_ = nullptr;
    WIFI_LOGI("UnRegisterCloneEvent success");
}

void WifiEventSubscriberManager::GetMdmProp()
{
    char preValue[PROP_FALSE_LEN + 1] = {0};
    mIsMdmForbidden = false;
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
        powerStateListener_ = nullptr;
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
        WIFI_LOGI("UnRegisterPowerStateListener OK!");
    }
    powerStateListener_ = nullptr;
    isPowerStateListenerSubscribered = false;
}
#endif

#ifdef HAS_MOVEMENT_PART
void WifiEventSubscriberManager::RegisterMovementCallBack()
{
    WIFI_LOGI("RegisterMovementCallBack");
    std::unique_lock<std::mutex> lock(deviceMovementEventMutex);
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
    std::unique_lock<std::mutex> lock(deviceMovementEventMutex);
    if (!deviceMovementCallback_) {
        return;
    }
    Msdp::MovementClient::GetInstance().UnSubscribeCallback(
        Msdp::MovementDataUtils::MovementType::TYPE_STILL, deviceMovementCallback_);
    deviceMovementCallback_ = nullptr;
}
#endif

CesEventSubscriber::CesEventSubscriber(const OHOS::EventFwk::CommonEventSubscribeInfo &subscriberInfo)
    : CommonEventSubscriber(subscriberInfo)
{
    WIFI_LOGI("CesEventSubscriber enter");
}

CesEventSubscriber::~CesEventSubscriber()
{
    WIFI_LOGI("~CesEventSubscriber enter");
}

void CesEventSubscriber::OnReceiveEvent(const OHOS::EventFwk::CommonEventData &eventData)
{
    std::string action = eventData.GetWant().GetAction();
    WIFI_LOGI("CesEventSubscriber OnReceiveEvent: %{public}s", action.c_str());
    auto itFunc = CES_REQUEST_MAP.find(action);
    if (itFunc != CES_REQUEST_MAP.end()) {
        auto requestFunc = itFunc->second;
        if (requestFunc != nullptr) {
            return (this->*requestFunc)(eventData);
        }
    }
    WIFI_LOGE("CesEventSubscriber OnReceiveEvent unknown Event: %{public}s", action.c_str());
}

void CesEventSubscriber::OnReceiveScreenEvent(const OHOS::EventFwk::CommonEventData &eventData)
{
    std::string action = eventData.GetWant().GetAction();
    WIFI_LOGI("OnReceiveScreenEvent: %{public}s.", action.c_str());

    int screenState = WifiSettings::GetInstance().GetScreenState();
    int screenStateNew = (action == OHOS::EventFwk::CommonEventSupport::COMMON_EVENT_SCREEN_ON)
        ? MODE_STATE_OPEN : MODE_STATE_CLOSE;
    WifiSettings::GetInstance().SetScreenState(screenStateNew);
    if (screenStateNew == screenState) {
        return;
    }
    for (int i = 0; i < STA_INSTANCE_MAX_NUM; ++i) {
        IStaService *pService = WifiServiceManager::GetInstance().GetStaServiceInst(i);
        if (pService != nullptr) {
            pService->OnScreenStateChanged(screenStateNew);
#ifdef FEATURE_HPF_SUPPORT
            WifiManager::GetInstance().InstallPacketFilterProgram(screenStateNew, i);
#endif
        }
        IScanService *pScanService = WifiServiceManager::GetInstance().GetScanServiceInst(i);
        if (pScanService != nullptr) {
            pScanService->OnScreenStateChanged(screenStateNew);
        }
    }
}


void CesEventSubscriber::OnReceiveAirplaneEvent(const OHOS::EventFwk::CommonEventData &eventData)
{
    const auto &action = eventData.GetWant().GetAction();
    const auto &data = eventData.GetData();
    const auto &code = eventData.GetCode();
    WIFI_LOGI("AirplaneModeEventSubscriber::OnReceiveEvent: %{public}s,  %{public}s,  %{public}d", action.c_str(),
        data.c_str(), code);
    if (action == OHOS::EventFwk::CommonEventSupport::COMMON_EVENT_AIRPLANE_MODE_CHANGED) {
        if (code == 1) {
            /* open airplane mode */
            if (WifiConfigCenter::GetInstance().SetWifiStateOnAirplaneChanged(MODE_STATE_OPEN)) {
                WifiManager::GetInstance().GetWifiTogglerManager()->AirplaneToggled(1);
            } else {
                WifiSettings::GetInstance().SetSoftapToggledState(false);
                WifiManager::GetInstance().GetWifiTogglerManager()->SoftapToggled(0);
            }
        } else {
            /* close airplane mode */
            if (WifiConfigCenter::GetInstance().SetWifiStateOnAirplaneChanged(MODE_STATE_CLOSE)) {
                WifiManager::GetInstance().GetWifiTogglerManager()->AirplaneToggled(0);
            }
        }
    }
}

void CesEventSubscriber::OnReceiveBatteryEvent(const OHOS::EventFwk::CommonEventData &eventData)
{
    std::string action = eventData.GetWant().GetAction();
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
    for (int i = 0; i < STA_INSTANCE_MAX_NUM; ++i) {
        IScanService *pScanService = WifiServiceManager::GetInstance().GetScanServiceInst(i);
        if (pScanService == nullptr) {
            WIFI_LOGE("scan service is NOT start!");
            return;
        }
        if (pScanService->OnMovingFreezeStateChange() != WIFI_OPT_SUCCESS) {
            WIFI_LOGE("OnMovingFreezeStateChange failed");
        }
    }
}

void CesEventSubscriber::OnReceiveAppEvent(const OHOS::EventFwk::CommonEventData &eventData)
{
    std::string action = eventData.GetWant().GetAction();
    WIFI_LOGI("AppEventSubscriber::OnReceiveEvent : %{public}s.", action.c_str());
    auto wantTemp = eventData.GetWant();
    auto uid = wantTemp.GetIntParam(AppExecFwk::Constants::UID, -1);
    if (uid == -1) {
        WIFI_LOGE("%{public}s getPackage uid is illegal.", __func__);
        return;
    }
    WIFI_LOGI("Package removed of uid %{public}d.", uid);
    std::vector<WifiDeviceConfig> tempConfigs;
    WifiSettings::GetInstance().GetAllCandidateConfig(uid, tempConfigs);
    for (const auto &config : tempConfigs) {
        if (WifiSettings::GetInstance().RemoveDevice(config.networkId) != WIFI_OPT_SUCCESS) {
            WIFI_LOGE("RemoveAllCandidateConfig-RemoveDevice() failed!");
        }
    }
    WifiSettings::GetInstance().SyncDeviceConfig();
}

void CesEventSubscriber::OnReceiveThermalEvent(const OHOS::EventFwk::CommonEventData &eventData)
{
    std::string action = eventData.GetWant().GetAction();
    WIFI_LOGI("ThermalLevelSubscriber::OnReceiveEvent: %{public}s.", action.c_str());
    if (action == OHOS::EventFwk::CommonEventSupport::COMMON_EVENT_THERMAL_LEVEL_CHANGED) {
        static const std::string THERMAL_EVENT_ID = "0";
        int level = eventData.GetWant().GetIntParam(THERMAL_EVENT_ID, 0);
        WifiSettings::GetInstance().SetThermalLevel(level);
        WIFI_LOGI("ThermalLevelSubscriber SetThermalLevel: %{public}d.", level);
    }
}

void CesEventSubscriber::OnReceiveStandbyEvent(const OHOS::EventFwk::CommonEventData &eventData)
{
    const auto &action = eventData.GetWant().GetAction();
    const bool napped = eventData.GetWant().GetBoolParam(WIFI_STANDBY_NAP, 0);
    const bool sleeping = eventData.GetWant().GetBoolParam(WIFI_STANDBY_SLEEPING, 0);
    WIFI_LOGI("StandByListerner OnReceiveEvent action[%{public}s], napped[%{public}d], sleeping[%{public}d]",
        action.c_str(), napped, sleeping);
    int state = WifiSettings::GetInstance().GetScreenState();
    if (lastSleepState != sleeping && state != MODE_STATE_CLOSE) {
        for (int i = 0; i < STA_INSTANCE_MAX_NUM; ++i) {
            IScanService *pScanService = WifiServiceManager::GetInstance().GetScanServiceInst(i);
            if (pScanService == nullptr) {
                WIFI_LOGE("scan service is NOT start!");
                continue;
            }
            pScanService->OnStandbyStateChanged(sleeping);
        }
        lastSleepState = sleeping;
    }
    if (napped || sleeping) {
        WifiSettings::GetInstance().SetPowerIdelState(MODE_STATE_OPEN);
    } else {
        WifiSettings::GetInstance().SetPowerIdelState(MODE_STATE_CLOSE);
    }
}

void CesEventSubscriber::OnReceiveNotificationEvent(const OHOS::EventFwk::CommonEventData &eventData)
{
    const auto &action = eventData.GetWant().GetAction();
    WIFI_LOGI("OnReceiveNotificationEvent action[%{public}s]", action.c_str());
    for (int i = 0; i < STA_INSTANCE_MAX_NUM; ++i) {
        IStaService *pService = WifiServiceManager::GetInstance().GetStaServiceInst(i);
        if (pService != nullptr) {
            pService->StartPortalCertification();
        }
    }
}
}  // namespace Wifi
}  // namespace OHOS
#endif