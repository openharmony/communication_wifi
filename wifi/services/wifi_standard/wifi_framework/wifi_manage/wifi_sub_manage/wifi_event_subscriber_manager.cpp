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
#include "wifi_notification_util.h"
#include "wifi_app_state_aware.h"
#ifdef HAS_MOVEMENT_PART
#include "wifi_msdp_state_listener.h"
#endif
#ifdef SUPPORT_ClOUD_WIFI_ASSET
#include "wifi_asset_manager.h"
#endif
DEFINE_WIFILOG_LABEL("WifiEventSubscriberManager");

namespace OHOS {
namespace Wifi {
constexpr uint32_t TIMEOUT_EVENT_SUBSCRIBER = 3000;
constexpr uint32_t TIMEOUT_EVENT_DELAY_ACCESS_DATASHARE = 10 * 1000;
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
    CesEventSubscriber::OnReceiveStandbyEvent}
};

WifiEventSubscriberManager::WifiEventSubscriberManager()
{
    WIFI_LOGI("create WifiEventSubscriberManager");
    if (accessDatashareTimerId == 0) {
        WifiTimer::TimerCallback timeoutCallback = std::bind(&WifiEventSubscriberManager::DelayedAccessDataShare, this);
        WifiTimer::GetInstance()->Register(
            timeoutCallback, accessDatashareTimerId, TIMEOUT_EVENT_DELAY_ACCESS_DATASHARE);
        WIFI_LOGI("DelayedAccessDataShare register success! accessDatashareTimerId:%{public}u", accessDatashareTimerId);
    }
    
    RegisterCesEvent();
    RegisterNotificationEvent();
#ifdef HAS_POWERMGR_PART
    RegisterPowermgrEvent();
#endif
#ifdef SUPPORT_ClOUD_WIFI_ASSET
    RegisterAssetEvent();
#endif
    if (IsDataMgrServiceActive()) {
        RegisterCloneEvent();
    }
    InitSubscribeListener();
    GetMdmProp();
    GetChipProp();
    RegisterMdmPropListener();
}

WifiEventSubscriberManager::~WifiEventSubscriberManager()
{
    WIFI_LOGI("~WifiEventSubscriberManager");
    UnRegisterCesEvent();
#ifdef SUPPORT_ClOUD_WIFI_ASSET
    UnRegisterAssetEvent();
#endif
    UnRegisterNotificationEvent();
    UnRegisterCloneEvent();
    UnRegisterLocationEvent();
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

void WifiEventSubscriberManager::HandleAppMgrServiceChange(bool add)
{
    WIFI_LOGI("%{public}s enter, add flag: %{public}d", __FUNCTION__, add);
    if (add) {
        WifiAppStateAware::GetInstance().RegisterAppStateObserver();
    } else {
        WifiAppStateAware::GetInstance().UnSubscribeAppState();
    }
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
        RegisterNotificationEvent();
#ifdef SUPPORT_ClOUD_WIFI_ASSET
        RegisterAssetEvent();
#endif
    } else {
        UnRegisterCesEvent();
        UnRegisterNotificationEvent();
#ifdef SUPPORT_ClOUD_WIFI_ASSET
        UnRegisterAssetEvent();
#endif
    }
}

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

void WifiEventSubscriberManager::HandleCastServiceChange(bool add)
{
    if (!add) {
        WifiConfigCenter::GetInstance().ClearLocalHid2dInfo(CAST_ENGINE_SERVICE_UID);
    }
}

#ifdef FEATURE_P2P_SUPPORT
void WifiEventSubscriberManager::HandleP2pBusinessChange(int systemAbilityId, bool add)
{
    WIFI_LOGI("HandleP2pBusinessChange, id[%{public}d], mode=[%{public}d]!", systemAbilityId, add);
    if (add) {
        return;
    }
    WifiConfigCenter::GetInstance().ClearLocalHid2dInfo(SOFT_BUS_SERVICE_UID);
    IP2pService *pService = WifiServiceManager::GetInstance().GetP2pServiceInst();
    if (pService == nullptr) {
        WIFI_LOGE("Get P2P service failed!");
        return;
    }
    pService->HandleBusinessSAException(systemAbilityId);
    return;
}
#endif

void WifiEventSubscriberManager::OnSystemAbilityChanged(int systemAbilityId, bool add)
{
    WIFI_LOGI("%{public}s enter, systemAbilityId: %{public}d", __FUNCTION__, systemAbilityId);
    switch (systemAbilityId) {
        case APP_MGR_SERVICE_ID:
            HandleAppMgrServiceChange(add);
            break;
        case COMM_NET_CONN_MANAGER_SYS_ABILITY_ID:
            HandleCommNetConnManagerSysChange(systemAbilityId, add);
            break;
        case COMMON_EVENT_SERVICE_ID:
            HandleCommonEventServiceChange(systemAbilityId, add);
            break;
#ifdef HAS_MOVEMENT_PART
        case MSDP_MOVEMENT_SERVICE_ID:
            HandleHasMovementPartChange(systemAbilityId, add);
            break;
#endif
        case DISTRIBUTED_KV_DATA_SERVICE_ABILITY_ID:
            HandleDistributedKvDataServiceChange(add);
            break;
#ifdef FEATURE_P2P_SUPPORT
        case SOFTBUS_SERVER_SA_ID:
            HandleP2pBusinessChange(systemAbilityId, add);
            break;
#endif
        case CAST_ENGINE_SA_ID:
            HandleCastServiceChange(add);
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
        WIFI_LOGE("GetAirplaneModeByDatashare, Query airplaneMode again!");
        ret = datashareHelper->Query(uri, SETTINGS_DATASHARE_KEY_AIRPLANE_MODE, airplaneMode, true);
        if (ret != WIFI_OPT_SUCCESS) {
            WIFI_LOGE("GetAirplaneModeByDatashare, Query airplaneMode fail!");
            return;
        }
    }

    WIFI_LOGI("GetAirplaneModeByDatashare, airplaneMode:%{public}s", airplaneMode.c_str());
    if (airplaneMode.compare("1") == 0) {
        WifiConfigCenter::GetInstance().SetWifiStateOnAirplaneChanged(MODE_STATE_OPEN);
    }
    return;
}

void WifiEventSubscriberManager::GetWifiAllowSemiActiveByDatashare()
{
    auto datashareHelper = DelayedSingleton<WifiDataShareHelperUtils>::GetInstance();
    if (datashareHelper == nullptr) {
        WIFI_LOGE("GetWifiAllowSemiActiveByDatashare, datashareHelper is nullptr!");
        return;
    }

    std::string isAllowed;
    Uri uri(SETTINGS_DATASHARE_URI_WIFI_ALLOW_SEMI_ACTIVE);
    int ret = datashareHelper->Query(uri, SETTINGS_DATASHARE_KEY_WIFI_ALLOW_SEMI_ACTIVE, isAllowed);
    if (ret != WIFI_OPT_SUCCESS) {
        WIFI_LOGE("GetWifiAllowSemiActiveByDatashare, Query wifiAllowSemiActive fail!");
        return;
    }

    WIFI_LOGI("GetWifiAllowSemiActiveByDatashare, isAllowed:%{public}s", isAllowed.c_str());
    WifiConfigCenter::GetInstance().SetWifiAllowSemiActive(isAllowed.compare("1") == 0);
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
        WifiConfigCenter::GetInstance().SetWifiToggledState(WIFI_STATE_ENABLED);
        WifiManager::GetInstance().GetWifiTogglerManager()->WifiToggled(1, 0);
    } else if (lastStaState == openWifiInAirplanemode) {
        WifiSettings::GetInstance().SetWifiFlagOnAirplaneMode(true);
        WifiConfigCenter::GetInstance().SetWifiToggledState(WIFI_STATE_ENABLED);
        WifiManager::GetInstance().GetWifiTogglerManager()->WifiToggled(1, 0);
    } else if (lastStaState == closeWifiByAirplanemodeOpen) {
        WifiConfigCenter::GetInstance().SetWifiToggledState(WIFI_STATE_ENABLED);
    }
}

bool WifiEventSubscriberManager::IsMdmForbidden()
{
    return mIsMdmForbidden;
}

void WifiEventSubscriberManager::DelayedAccessDataShare()
{
    WIFI_LOGI("DelayedAccessDataShare enter!");
    std::filesystem::path pathName = WIFI_CONFIG_FILE_PATH;
    std::error_code code;
    if (!std::filesystem::exists(pathName, code)) {
        CheckAndStartStaByDatashare();
    }
    GetAirplaneModeByDatashare();

    if (accessDatashareTimerId != 0) {
        WifiTimer::GetInstance()->UnRegister(accessDatashareTimerId);
        accessDatashareTimerId = 0;
    }
}

void WifiEventSubscriberManager::InitSubscribeListener()
{
    SubscribeSystemAbility(APP_MGR_SERVICE_ID);
    SubscribeSystemAbility(COMM_NET_CONN_MANAGER_SYS_ABILITY_ID);
    SubscribeSystemAbility(COMMON_EVENT_SERVICE_ID);
#ifdef HAS_MOVEMENT_PART
    SubscribeSystemAbility(MSDP_MOVEMENT_SERVICE_ID);
#endif
    SubscribeSystemAbility(DISTRIBUTED_KV_DATA_SERVICE_ABILITY_ID);  // subscribe data management service done
    SubscribeSystemAbility(SOFTBUS_SERVER_SA_ID);
    SubscribeSystemAbility(CAST_ENGINE_SA_ID);
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
            WifiConfigCenter::GetInstance().SetApIfaceName(COEX_IFACENAME);
            WifiConfigCenter::GetInstance().SetCoexSupport(true);
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

    int screenState = WifiConfigCenter::GetInstance().GetScreenState();
    int screenStateNew = (action == OHOS::EventFwk::CommonEventSupport::COMMON_EVENT_SCREEN_ON)
        ? MODE_STATE_OPEN : MODE_STATE_CLOSE;
    WifiConfigCenter::GetInstance().SetScreenState(screenStateNew);
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
                WifiConfigCenter::GetInstance().SetSoftapToggledState(false);
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
        WifiConfigCenter::GetInstance().SetNoChargerPlugModeState(MODE_STATE_CLOSE);
    } else if (action == OHOS::EventFwk::CommonEventSupport::COMMON_EVENT_POWER_DISCONNECTED) {
        WifiConfigCenter::GetInstance().SetNoChargerPlugModeState(MODE_STATE_OPEN);
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
    bool removeFlag = false;
    for (int i = 0; i < STA_INSTANCE_MAX_NUM; ++i) {
        IStaService *pService = WifiServiceManager::GetInstance().GetStaServiceInst(i);
        if (pService != nullptr) {
            pService->RemoveAllCandidateConfig(uid);
            removeFlag = true;
        }
    }
    if (!removeFlag) {
        std::vector<WifiDeviceConfig> tempConfigs;
        WifiSettings::GetInstance().GetAllCandidateConfig(uid, tempConfigs);
        for (const auto &config : tempConfigs) {
            if (WifiSettings::GetInstance().RemoveDevice(config.networkId) != WIFI_OPT_SUCCESS) {
                WIFI_LOGE("RemoveAllCandidateConfig-RemoveDevice() failed!");
            }
        }
        WifiSettings::GetInstance().SyncDeviceConfig();
    }
    return;
}

void CesEventSubscriber::OnReceiveThermalEvent(const OHOS::EventFwk::CommonEventData &eventData)
{
    std::string action = eventData.GetWant().GetAction();
    WIFI_LOGI("ThermalLevelSubscriber::OnReceiveEvent: %{public}s.", action.c_str());
    if (action == OHOS::EventFwk::CommonEventSupport::COMMON_EVENT_THERMAL_LEVEL_CHANGED) {
        static const std::string THERMAL_EVENT_ID = "0";
        int level = eventData.GetWant().GetIntParam(THERMAL_EVENT_ID, 0);
        WifiConfigCenter::GetInstance().SetThermalLevel(level);
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
    int state = WifiConfigCenter::GetInstance().GetScreenState();
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
        WifiConfigCenter::GetInstance().SetPowerIdelState(MODE_STATE_OPEN);
    } else {
        WifiConfigCenter::GetInstance().SetPowerIdelState(MODE_STATE_CLOSE);
    }
}

void WifiEventSubscriberManager::RegisterNotificationEvent()
{
    std::unique_lock<std::mutex> lock(notificationEventMutex);
    if (notificationTimerId != 0) {
        WifiTimer::GetInstance()->UnRegister(notificationTimerId);
    }
    if (wifiNotificationSubsciber_) {
        return;
    }
    OHOS::EventFwk::MatchingSkills matchingSkills;
    matchingSkills.AddEvent(WIFI_EVENT_TAP_NOTIFICATION);
    matchingSkills.AddEvent(WIFI_EVENT_DIALOG_ACCEPT);
    matchingSkills.AddEvent(WIFI_EVENT_DIALOG_REJECT);
    WIFI_LOGI("RegisterNotificationEvent start");
    EventFwk::CommonEventSubscribeInfo subscriberInfo(matchingSkills);
    subscriberInfo.SetThreadMode(EventFwk::CommonEventSubscribeInfo::COMMON);
    subscriberInfo.SetPermission("ohos.permission.SET_WIFI_CONFIG");
    wifiNotificationSubsciber_ = std::make_shared<NotificationEventSubscriber>(subscriberInfo);
    if (!EventFwk::CommonEventManager::SubscribeCommonEvent(wifiNotificationSubsciber_)) {
        WIFI_LOGE("WifiNotification SubscribeCommonEvent() failed");
        wifiNotificationSubsciber_ = nullptr;
        WifiTimer::TimerCallback timeoutCallBack =
            std::bind(&WifiEventSubscriberManager::RegisterNotificationEvent, this);
        WifiTimer::GetInstance()->Register(timeoutCallBack, notificationTimerId, TIMEOUT_EVENT_SUBSCRIBER, false);
        WIFI_LOGI("RegisterNotificationEvent retry, notificationTimerId = %{public}u", notificationTimerId);
    } else {
        WIFI_LOGI("RegisterNotificationEvent success");
    }
}

void WifiEventSubscriberManager::UnRegisterNotificationEvent()
{
    std::unique_lock<std::mutex> lock(notificationEventMutex);
    if (notificationTimerId != 0) {
        WifiTimer::GetInstance()->UnRegister(notificationTimerId);
    }
    if (!wifiNotificationSubsciber_) {
        return;
    }
    if (!EventFwk::CommonEventManager::UnSubscribeCommonEvent(wifiNotificationSubsciber_)) {
        WIFI_LOGE("UnRegisterNotificationEvent failed");
    }
    wifiNotificationSubsciber_ = nullptr;
    WIFI_LOGI("UnRegisterNotificationEvent finished");
}

NotificationEventSubscriber::NotificationEventSubscriber(const OHOS::EventFwk::CommonEventSubscribeInfo &subscriberInfo)
    : CommonEventSubscriber(subscriberInfo)
{
    WIFI_LOGI("NotificationEventSubscriber enter");
}

NotificationEventSubscriber::~NotificationEventSubscriber()
{
    WIFI_LOGI("~NotificationEventSubscriber enter");
}

void NotificationEventSubscriber::OnReceiveEvent(const OHOS::EventFwk::CommonEventData &eventData)
{
    std::string action = eventData.GetWant().GetAction();
    WIFI_LOGI("OnReceiveNotificationEvent action[%{public}s]", action.c_str());
    if (action == WIFI_EVENT_TAP_NOTIFICATION) {
        for (int i = 0; i < STA_INSTANCE_MAX_NUM; ++i) {
            IStaService *pService = WifiServiceManager::GetInstance().GetStaServiceInst(i);
            if (pService != nullptr) {
                pService->StartPortalCertification();
            }
        }
    } else if (action == WIFI_EVENT_DIALOG_ACCEPT) {
        int dialogType = eventData.GetWant().GetIntParam("dialogType", 0);
        WIFI_LOGI("dialogType[%{public}d]", dialogType);
        if (dialogType == static_cast<int>(WifiDialogType::CANDIDATE_CONNECT)) {
            int candidateNetworkId = WifiConfigCenter::GetInstance().GetSelectedCandidateNetworkId();
            if (candidateNetworkId == INVALID_NETWORK_ID) {
                WIFI_LOGI("OnReceiveNotificationEvent networkid is invalid");
                return;
            }
            IStaService *pService = WifiServiceManager::GetInstance().GetStaServiceInst(0);
            if (pService != nullptr) {
                pService->ConnectToNetwork(candidateNetworkId);
            }
        }
    } else {
        int dialogType = eventData.GetWant().GetIntParam("dialogType", 0);
        WIFI_LOGI("dialogType[%{public}d]", dialogType);
        if (dialogType == static_cast<int>(WifiDialogType::CANDIDATE_CONNECT)) {
            WifiConfigCenter::GetInstance().SetSelectedCandidateNetworkId(INVALID_NETWORK_ID);
        }
    }
}

#ifdef HAS_POWERMGR_PART
void WifiEventSubscriberManager::RegisterPowermgrEvent()
{
    std::unique_lock<std::mutex> lock(powermgrEventMutex);
    if (wifiPowermgrEventSubsciber_) {
        return;
    }
    OHOS::EventFwk::MatchingSkills matchingSkills;
    matchingSkills.AddEvent(COMMON_EVENT_POWER_MANAGER_STATE_CHANGED);
    WIFI_LOGI("RegisterPowermgrEvent start");
    EventFwk::CommonEventSubscribeInfo subscriberInfo(matchingSkills);
    subscriberInfo.SetThreadMode(EventFwk::CommonEventSubscribeInfo::COMMON);
    subscriberInfo.SetPermission("ohos.permission.SET_WIFI_CONFIG");
    wifiPowermgrEventSubsciber_ = std::make_shared<PowermgrEventSubscriber>(subscriberInfo);
    if (!EventFwk::CommonEventManager::SubscribeCommonEvent(wifiPowermgrEventSubsciber_)) {
        WIFI_LOGE("Powermgr SubscribeCommonEvent() failed");
        wifiPowermgrEventSubsciber_ = nullptr;
    } else {
        WIFI_LOGI("RegisterCesEvent success");
    }
}

void WifiEventSubscriberManager::UnRegisterPowermgrEvent()
{
    std::unique_lock<std::mutex> lock(powermgrEventMutex);
    if (!wifiPowermgrEventSubsciber_) {
        return;
    }
    if (!EventFwk::CommonEventManager::UnSubscribeCommonEvent(wifiPowermgrEventSubsciber_)) {
        WIFI_LOGE("UnRegisterPowermgrEvent failed");
    }
    wifiPowermgrEventSubsciber_ = nullptr;
    WIFI_LOGI("UnRegisterPowermgrEvent finished");
}

PowermgrEventSubscriber::PowermgrEventSubscriber(const OHOS::EventFwk::CommonEventSubscribeInfo &subscriberInfo)
    : CommonEventSubscriber(subscriberInfo)
{
    WIFI_LOGI("PowermgrEventSubscriber enter");
}

PowermgrEventSubscriber::~PowermgrEventSubscriber()
{
    WIFI_LOGI("~PowermgrEventSubscriber enter");
}

void PowermgrEventSubscriber::OnReceiveEvent(const OHOS::EventFwk::CommonEventData &eventData)
{
    std::string action = eventData.GetWant().GetAction();
    WIFI_LOGI("Receive ForceSleep Event: %{public}s", action.c_str());
#ifdef FEATURE_HPF_SUPPORT
    const int enterForceSleep = 0x30;
    const int exitForceSleep = 0x31;
    if (action == COMMON_EVENT_POWER_MANAGER_STATE_CHANGED) {
        for (int i = 0; i < STA_INSTANCE_MAX_NUM; ++i) {
            if (eventData.GetCode() == enterForceSleep) { // STATE_ENTER_FORCESLEEP
                WIFI_LOGI("Receive ForceSleep Event: %{public}d", enterForceSleep);
                WifiManager::GetInstance().InstallPacketFilterProgram(MODE_STATE_FORCESLEEP, i);
            }
            if (eventData.GetCode() == exitForceSleep) {
                WIFI_LOGI("Receive ForceSleep Event: %{public}d", exitForceSleep);
                WifiManager::GetInstance().InstallPacketFilterProgram(MODE_STATE_EXIT_FORCESLEEP, i);
            }
        }
    }
#endif
}

#endif
#ifdef SUPPORT_ClOUD_WIFI_ASSET
void WifiEventSubscriberManager::RegisterAssetEvent()
{
    std::unique_lock<std::mutex> lock(AssetEventMutex);
    if (assetMgrId != 0) {
        WifiTimer::GetInstance()->UnRegister(assetMgrId);
    }
    if (wifiAssetrEventSubsciber_) {
        return;
    }
    OHOS::EventFwk::MatchingSkills matchingSkills;
    matchingSkills.AddEvent(COMMON_EVENT_ASSETCLOUD_MANAGER_STATE_CHANGED);
    EventFwk::CommonEventSubscribeInfo subscriberInfo(matchingSkills);
    subscriberInfo.SetPublisherUid(ASSETID);
    wifiAssetrEventSubsciber_ = std::make_shared<AssetEventSubscriber>(subscriberInfo);
    WIFI_LOGI("RegisterAssetEvent start");
    if (!EventFwk::CommonEventManager::SubscribeCommonEvent(wifiAssetrEventSubsciber_)) {
        WIFI_LOGE("AssetCloud SubscribeCommonEvent() failed");
        wifiAssetrEventSubsciber_ = nullptr;
        WifiTimer::TimerCallback timeoutCallBack = std::bind(&WifiEventSubscriberManager::RegisterAssetEvent, this);
        WifiTimer::GetInstance()->Register(timeoutCallBack, assetMgrId, TIMEOUT_EVENT_SUBSCRIBER, false);
        WIFI_LOGI("RegisterAssetEvent retry, powerMgrId = %{public}u", assetMgrId);
    } else {
        WIFI_LOGI("RegisterAssetEvent success");
    }
}
 
void WifiEventSubscriberManager::UnRegisterAssetEvent()
{
    std::unique_lock<std::mutex> lock(AssetEventMutex);
    if (assetMgrId != 0) {
        WifiTimer::GetInstance()->UnRegister(assetMgrId);
    }
    if (!wifiAssetrEventSubsciber_) {
        return;
    }
    if (!EventFwk::CommonEventManager::UnSubscribeCommonEvent(wifiAssetrEventSubsciber_)) {
        WIFI_LOGE("UnRegisterAssetEvent failed");
    }
    wifiAssetrEventSubsciber_ = nullptr;
    WIFI_LOGI("UnRegisterAssetEvent finished");
}
 
AssetEventSubscriber::AssetEventSubscriber(const OHOS::EventFwk::CommonEventSubscribeInfo &subscriberInfo)
    : CommonEventSubscriber(subscriberInfo)
{
    WIFI_LOGI("AssetEventSubscriber enter");
}
 
AssetEventSubscriber::~AssetEventSubscriber()
{
    WIFI_LOGI("~AssetEventSubscriber enter");
}
 
void AssetEventSubscriber::OnReceiveEvent(const OHOS::EventFwk::CommonEventData &eventData)
{
    std::string action = eventData.GetWant().GetAction();
    WIFI_LOGI("AssetListerner OnReceiveEvent action: %{public}s", action.c_str());
    if (action == COMMON_EVENT_ASSETCLOUD_MANAGER_STATE_CHANGED) {
        WifiAssetManager::GetInstance().CloudAssetSyn();
    }
}
#endif
}  // namespace Wifi
}  // namespace OHOS
#endif
