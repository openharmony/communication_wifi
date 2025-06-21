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
#include "wifi_net_agent.h"
#include "block_connect_service.h"
#ifdef HAS_MOVEMENT_PART
#include "wifi_msdp_state_listener.h"
#endif
#ifdef SUPPORT_ClOUD_WIFI_ASSET
#include "wifi_asset_manager.h"
#endif
#include "wifi_country_code_manager.h"
#include "wifi_country_code_define.h"
#include "wifi_global_func.h"
#include "display_info.h"
#ifdef EXTENSIBLE_AUTHENTICATION
#include "net_eap_observer.h"
#endif
#include "wifi_internal_event_dispatcher.h"
#include "wifi_sensor_scene.h"
DEFINE_WIFILOG_LABEL("WifiEventSubscriberManager");

namespace OHOS {
namespace Wifi {
constexpr uint32_t TIMEOUT_EVENT_SUBSCRIBER = 3000;
constexpr uint32_t PROP_LEN = 26;
constexpr uint32_t PROP_TRUE_LEN = 4;
constexpr uint32_t PROP_FALSE_LEN = 5;
const std::string PROP_TRUE = "true";
const std::string PROP_FALSE = "false";
const std::string MDM_WIFI_PROP = "persist.edm.wifi_enable";
const std::string WIFI_STANDBY_NAP = "napped";
const std::string WIFI_STANDBY_SLEEPING = "sleeping";
const std::string ENTER_SETTINGS = "usual.event.wlan.ENTER_SETTINGS_WLAN_PAGE";
const std::string WLAN_PAGE_ENTER = "enterWlanPage";

bool WifiEventSubscriberManager::mIsMdmForbidden = false;
static sptr<WifiLocationModeObserver> locationModeObserver_ = nullptr;
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
    {OHOS::EventFwk::CommonEventSupport::COMMON_EVENT_USER_UNLOCKED, &
    CesEventSubscriber::OnReceiveUserUnlockedEvent}
};

WifiEventSubscriberManager::WifiEventSubscriberManager()
{
    WIFI_LOGI("create WifiEventSubscriberManager");
    RegisterCesEvent();
    RegisterNotificationEvent();
#ifdef HAS_POWERMGR_PART
    RegisterPowermgrEvent();
#endif
#ifdef SUPPORT_ClOUD_WIFI_ASSET
    RegisterAssetEvent();
#endif
    InitSubscribeListener();
    GetMdmProp();
    RegisterMdmPropListener();
    RegisterNetworkStateChangeEvent();
    RegisterWifiScanChangeEvent();
    RegisterSettingsEnterEvent();
    if (IsSignalSmoothingEnable()) {
        RegisterFoldStatusListener();
    }
    RegisterDisplayListener();
    RegisterNetworkConnSubscriber();
#ifdef HAS_NETMANAGER_EVENT_PART
    RegisterNetmgrEvent();
#endif
}

WifiEventSubscriberManager::~WifiEventSubscriberManager()
{
    WIFI_LOGI("~WifiEventSubscriberManager");
    UnRegisterCesEvent();
#ifdef SUPPORT_ClOUD_WIFI_ASSET
    UnRegisterAssetEvent();
#endif
    UnRegisterNotificationEvent();
    UnRegisterLocationEvent();
    UnRegisterNetworkStateChangeEvent();
    UnRegisterWifiScanChangeEvent();
    UnRegisterSettingsEnterEvent();
    UnRegisterDataShareReadyEvent();
    if (IsSignalSmoothingEnable()) {
        UnRegisterFoldStatusListener();
    }
    UnregisterDisplayListener();
    UnRegisterNetworkConnSubscriber();
#ifdef HAS_NETMANAGER_EVENT_PART
    UnRegisterNetmgrEvent();
#endif
#ifdef EXTENSIBLE_AUTHENTICATION
    NetEapObserver::GetInstance().StopNetEapObserver();
#endif
}

void WifiEventSubscriberManager::Init()
{
    WIFI_LOGI("WifiEventSubscriberManager Init");
    // Subscribe and register operation after wifiManager init completed.
    SubscribeSystemAbility(DISTRIBUTED_KV_DATA_SERVICE_ABILITY_ID);  // subscribe data management service done
    RegisterDataShareReadyEvent();
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
        WifiTimer::TimerCallback timeoutCallBack = [this]() { this->RegisterCesEvent(); };
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
    for (int i = 0; i < STA_INSTANCE_MAX_NUM; ++i) {
        IStaService *pService = WifiServiceManager::GetInstance().GetStaServiceInst(i);
        if (pService != nullptr) {
            pService->OnSystemAbilityChanged(systemAbilityId, add);
        }
    }
}

void WifiEventSubscriberManager::HandleEthernetServiceChange(int systemAbilityId, bool add)
{
#ifdef EXTENSIBLE_AUTHENTICATION
    WIFI_LOGI("StartNetEapObserver");
    NetEapObserver::GetInstance().StartNetEapObserver();
#endif
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
    WIFI_LOGI("HandleDistributedKvDataServiceChange, mode=[%{public}d]!", add);
    if (!add) {
        UnRegisterLocationEvent();
        return;
    }
    if (WifiDataShareHelperUtils::GetInstance().CheckIfSettingsDataReady()) {
        AccessDataShare();
        RegisterLocationEvent();
    }
}

void WifiEventSubscriberManager::HandleCastServiceChange(bool add)
{
    if (!add) {
        WifiConfigCenter::GetInstance().ClearLocalHid2dInfo(CAST_ENGINE_SERVICE_UID);
    }
}

void WifiEventSubscriberManager::HandleShareServiceChange(bool add)
{
    if (!add) {
        WifiConfigCenter::GetInstance().ClearLocalHid2dInfo(SHARE_SERVICE_UID);
    }
}

void WifiEventSubscriberManager::HandleMouseCrossServiceChange(bool add)
{
    if (!add) {
        WifiConfigCenter::GetInstance().ClearLocalHid2dInfo(MOUSE_CROSS_SERVICE_UID);
    }
}

#ifdef FEATURE_P2P_SUPPORT
void WifiEventSubscriberManager::HandleP2pBusinessChange(int systemAbilityId, bool add)
{
    WIFI_LOGI("HandleP2pBusinessChange, id[%{public}d], mode=[%{public}d]!", systemAbilityId, add);
    if (add) {
        return;
    }
    if (systemAbilityId == SOFTBUS_SERVER_SA_ID) {
        WifiConfigCenter::GetInstance().ClearLocalHid2dInfo(SOFT_BUS_SERVICE_UID);
    }
    if (systemAbilityId == MIRACAST_SERVICE_SA_ID) {
        WifiConfigCenter::GetInstance().ClearLocalHid2dInfo(MIRACAST_SERVICE_UID);
    }
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
        case MIRACAST_SERVICE_SA_ID:
            HandleP2pBusinessChange(systemAbilityId, add);
            break;
#endif
        case CAST_ENGINE_SA_ID:
            HandleCastServiceChange(add);
            break;
        case SHARE_SERVICE_ID:
            HandleShareServiceChange(add);
            break;
        case MOUSE_CROSS_SERVICE_ID:
            HandleMouseCrossServiceChange(add);
            break;
        case COMM_ETHERNET_MANAGER_SYS_ABILITY_ID:
            HandleEthernetServiceChange(systemAbilityId, add);
            break;
        default:
            break;
    }
}

void WifiEventSubscriberManager::GetAirplaneModeByDatashare()
{
    std::string airplaneMode;
    Uri uri(SETTINGS_DATASHARE_URL_AIRPLANE_MODE);
    int ret = WifiDataShareHelperUtils::GetInstance().Query(uri, SETTINGS_DATASHARE_KEY_AIRPLANE_MODE, airplaneMode);
    if (ret != WIFI_OPT_SUCCESS) {
        WIFI_LOGE("GetAirplaneModeByDatashare, Query airplaneMode again!");
        ret = WifiDataShareHelperUtils::GetInstance().Query(uri,
            SETTINGS_DATASHARE_KEY_AIRPLANE_MODE, airplaneMode, true);
        if (ret != WIFI_OPT_SUCCESS) {
            WIFI_LOGE("GetAirplaneModeByDatashare, Query airplaneMode fail!");
            return;
        }
    }
    if (airplaneMode.empty()) {
        WIFI_LOGI("GetAirplaneModeByDatashare, airplaneMode is empty!");
        return;
    }

    WIFI_LOGI("GetAirplaneModeByDatashare, airplaneMode:%{public}s", airplaneMode.c_str());
    if (airplaneMode.compare("1") == 0) {
        WifiConfigCenter::GetInstance().SetWifiStateOnAirplaneChanged(MODE_STATE_OPEN);
    } else {
        WifiConfigCenter::GetInstance().SetWifiStateOnAirplaneChanged(MODE_STATE_CLOSE);
    }
    return;
}

void WifiEventSubscriberManager::GetWifiAllowSemiActiveByDatashare()
{
    std::string isAllowed;
    Uri uri(SETTINGS_DATASHARE_URI_WIFI_ALLOW_SEMI_ACTIVE);
    int ret = WifiDataShareHelperUtils::GetInstance().Query(uri,
        SETTINGS_DATASHARE_KEY_WIFI_ALLOW_SEMI_ACTIVE, isAllowed);
    if (ret != WIFI_OPT_SUCCESS) {
        WIFI_LOGE("GetWifiAllowSemiActiveByDatashare, Query wifiAllowSemiActive fail!");
        return;
    }
    if (isAllowed.empty()) {
        WIFI_LOGI("GetWifiAllowSemiActiveByDatashare, isAllowed is empty!");
        return;
    }

    WIFI_LOGI("GetWifiAllowSemiActiveByDatashare, isAllowed:%{public}s", isAllowed.c_str());
    WifiConfigCenter::GetInstance().SetWifiAllowSemiActive(isAllowed.compare("1") == 0);
    return;
}

bool WifiEventSubscriberManager::GetLocationModeByDatashare()
{
    std::string locationMode;
    Uri uri(WifiDataShareHelperUtils::GetInstance().GetLoactionDataShareUri());
    int ret = WifiDataShareHelperUtils::GetInstance().Query(uri, SETTINGS_DATASHARE_KEY_LOCATION_MODE, locationMode);
    if (ret != WIFI_OPT_SUCCESS) {
        WIFI_LOGE("GetLocationModeByDatashare, Query locationMode fail!");
        return false;
    }

    WIFI_LOGD("GetLocationModeByDatashare, locationMode:%{public}s", locationMode.c_str());
    return (locationMode.compare("1") == 0);
}

std::string WifiEventSubscriberManager::GetScanMacInfoWhiteListByDatashare()
{
    if (!WifiDataShareHelperUtils::GetInstance().CheckIfSettingsDataReady()) {
        WIFI_LOGE("GetScanMacInfoWhiteListDataShareUri, SettingsDataIsNotReady!");
        return "";
    }
    std::string whiteList;
    Uri uri(WifiDataShareHelperUtils::GetInstance().GetScanMacInfoWhiteListDataShareUri());
    int ret = WifiDataShareHelperUtils::GetInstance().Query(uri,
        SETTINGS_DATASHARE_KEY_SCANMACINFO_WHITELIST, whiteList);
    if (ret != WIFI_OPT_SUCCESS) {
        WIFI_LOGE("GetScanMacInfoWhiteListDataShareUri, Query ScanWhiteList fail!");
        return "";
    }
    return whiteList;
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
        WifiConfigCenter::GetInstance().SetWifiToggledState(WIFI_STATE_ENABLED, INSTID_WLAN0);
        WifiManager::GetInstance().GetWifiTogglerManager()->WifiToggled(1, 0);
    } else if (lastStaState == openWifiInAirplanemode) {
        WifiSettings::GetInstance().SetWifiFlagOnAirplaneMode(true);
        WifiConfigCenter::GetInstance().SetWifiToggledState(WIFI_STATE_ENABLED, INSTID_WLAN0);
        WifiManager::GetInstance().GetWifiTogglerManager()->WifiToggled(1, 0);
    } else if (lastStaState == closeWifiByAirplanemodeOpen) {
        WifiConfigCenter::GetInstance().SetWifiToggledState(WIFI_STATE_ENABLED, INSTID_WLAN0);
    }
}

bool WifiEventSubscriberManager::IsMdmForbidden()
{
    return mIsMdmForbidden;
}

void WifiEventSubscriberManager::AccessDataShare()
{
    WIFI_LOGI("AccessDataShare enter!");
    {
        std::unique_lock<std::mutex> lock(accessDataShareMutex_);
        if (accessDataShare_) {
            return;
        }
        accessDataShare_ = true;
    }

    std::filesystem::path pathName = WIFI_CONFIG_FILE_PATH;
    std::error_code code;
    if (!std::filesystem::exists(pathName, code)) {
        CheckAndStartStaByDatashare();
    }
    GetAirplaneModeByDatashare();
    DealLocationModeChangeEvent();
}

void WifiEventSubscriberManager::InitSubscribeListener()
{
    SubscribeSystemAbility(APP_MGR_SERVICE_ID);
    SubscribeSystemAbility(COMM_NET_CONN_MANAGER_SYS_ABILITY_ID);
    SubscribeSystemAbility(COMM_ETHERNET_MANAGER_SYS_ABILITY_ID);
#ifdef HAS_MOVEMENT_PART
    SubscribeSystemAbility(MSDP_MOVEMENT_SERVICE_ID);
#endif
    SubscribeSystemAbility(SOFTBUS_SERVER_SA_ID);
    SubscribeSystemAbility(CAST_ENGINE_SA_ID);
    SubscribeSystemAbility(MIRACAST_SERVICE_SA_ID);
    SubscribeSystemAbility(SHARE_SERVICE_ID);
    SubscribeSystemAbility(MOUSE_CROSS_SERVICE_ID);
}

int WifiEventSubscriberManager::GetLastStaStateByDatashare()
{
    std::string lastStaState;
    Uri uri(SETTINGS_DATASHARE_URI_WIFI_ON);
    int ret = WifiDataShareHelperUtils::GetInstance().Query(uri, SETTINGS_DATASHARE_KEY_WIFI_ON, lastStaState);
    if (ret != WIFI_OPT_SUCCESS) {
        WIFI_LOGW("Query lastStaState fail, query settingsdata again!");
        ret = WifiDataShareHelperUtils::GetInstance().Query(uri, SETTINGS_DATASHARE_KEY_WIFI_ON, lastStaState, true);
        if (ret != WIFI_OPT_SUCCESS) {
            WIFI_LOGE("GetLastStaStateByDatashare Query lastStaState fail!");
            return 0;
        }
    }

    WIFI_LOGI("GetLastStaStateByDatashare, lastStaState:%{public}s", lastStaState.c_str());
    int lastStaStateType = CheckDataLegal(lastStaState);
    return lastStaStateType;
}

void WifiEventSubscriberManager::RegisterLocationEvent()
{
    std::unique_lock<std::mutex> lock(locationEventMutex);
    if (islocationModeObservered) {
        return;
    }
    locationModeObserver_ = sptr<WifiLocationModeObserver>(new (std::nothrow)WifiLocationModeObserver());
    Uri uri(WifiDataShareHelperUtils::GetInstance().GetLoactionDataShareUri());
    WifiDataShareHelperUtils::GetInstance().RegisterObserver(uri, locationModeObserver_);
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
    Uri uri(WifiDataShareHelperUtils::GetInstance().GetLoactionDataShareUri());
    WifiDataShareHelperUtils::GetInstance().UnRegisterObserver(uri, locationModeObserver_);
    islocationModeObservered = false;
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
        WIFI_LOGE("Register movement still observer failed!");
    }
    if (Msdp::MovementClient::GetInstance().SubscribeCallback(
        Msdp::MovementDataUtils::MovementType::TYPE_STAY, deviceMovementCallback_) != ERR_OK) {
        WIFI_LOGE("Register movement stay observer failed!");
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
    WIFI_LOGD("CesEventSubscriber OnReceiveEvent: %{public}s", action.c_str());
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
#if defined(FEATURE_AUTOOPEN_SPEC_LOC_SUPPORT) && defined(FEATURE_WIFI_PRO_SUPPORT)
        IWifiProService *pWifiProService = WifiServiceManager::GetInstance().GetWifiProServiceInst(i);
        if (pWifiProService != nullptr) {
            pWifiProService->OnScreenStateChanged(screenStateNew);
        }
#endif
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
    matchingSkills.AddEvent(EVENT_SETTINGS_WLAN_KEEP_CONNECTED);
    WIFI_LOGI("RegisterNotificationEvent start");
    EventFwk::CommonEventSubscribeInfo subscriberInfo(matchingSkills);
    subscriberInfo.SetThreadMode(EventFwk::CommonEventSubscribeInfo::COMMON);
    subscriberInfo.SetPermission("ohos.permission.SET_WIFI_CONFIG");
    wifiNotificationSubsciber_ = std::make_shared<NotificationEventSubscriber>(subscriberInfo);
    if (!EventFwk::CommonEventManager::SubscribeCommonEvent(wifiNotificationSubsciber_)) {
        WIFI_LOGE("WifiNotification SubscribeCommonEvent() failed");
        wifiNotificationSubsciber_ = nullptr;
        WifiTimer::TimerCallback timeoutCallBack = [this]() { this->RegisterNotificationEvent(); };
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

void NotificationEventSubscriber::OnReceiveWlanKeepConnected(const OHOS::EventFwk::CommonEventData &eventData)
{
    const int code = eventData.GetCode();
    WifiLinkedInfo linkedInfo;
    WifiConfigCenter::GetInstance().GetLinkedInfo(linkedInfo);
    int networkId = linkedInfo.networkId;
    WIFI_LOGI("received the WlanKeepConnected, code == %{public}d", code);
    if (code == 1) { // The user clicks the use button.
        WifiNetAgent::GetInstance().RestoreWifiConnection();
        WIFI_LOGI("change the value of AcceptUnvalidated to true");
        WifiSettings::GetInstance().SetAcceptUnvalidated(networkId, true);
        WifiSettings::GetInstance().SyncDeviceConfig();
    }
}

void NotificationEventSubscriber::OnReceiveEvent(const OHOS::EventFwk::CommonEventData &eventData)
{
    std::string action = eventData.GetWant().GetAction();
    WIFI_LOGI("OnReceiveNotificationEvent action[%{public}s]", action.c_str());
    if (action == WIFI_EVENT_TAP_NOTIFICATION) {
        int notificationId = eventData.GetWant().GetIntParam("notificationId", 0);
        WIFI_LOGI("notificationId[%{public}d]", notificationId);
        OnReceiveNotificationEvent(notificationId);
    } else if (action == WIFI_EVENT_DIALOG_ACCEPT) {
        int dialogType = eventData.GetWant().GetIntParam("dialogType", 0);
        WIFI_LOGI("dialogType[%{public}d]", dialogType);
        OnReceiveDialogAcceptEvent(dialogType);
    } else if (action == WIFI_EVENT_DIALOG_REJECT) {
        int dialogType = eventData.GetWant().GetIntParam("dialogType", 0);
        bool noAction = eventData.GetWant().GetBoolParam("noAction", false);
        WIFI_LOGI("dialogType[%{public}d], noAction[%{public}d]", dialogType, static_cast<int>(noAction));
        OnReceiveDialogRejectEvent(dialogType, noAction);
    } else if (action == EVENT_SETTINGS_WLAN_KEEP_CONNECTED) {
        OnReceiveWlanKeepConnected(eventData);
    } else {
        int dialogType = eventData.GetWant().GetIntParam("dialogType", 0);
        WIFI_LOGI("dialogType[%{public}d]", dialogType);
    }
}

void NotificationEventSubscriber::OnReceiveNotificationEvent(int notificationId)
{
    if (notificationId == static_cast<int>(WifiNotificationId::WIFI_PORTAL_NOTIFICATION_ID)) {
        for (int i = 0; i < STA_INSTANCE_MAX_NUM; ++i) {
            IStaService *pService = WifiServiceManager::GetInstance().GetStaServiceInst(i);
            if (pService != nullptr) {
                pService->StartPortalCertification();
            }
        }
    } else if (notificationId == static_cast<int>(WifiNotificationId::WIFI_5G_CONN_NOTIFICATION_ID)) {
        IEnhanceService *pEnhanceService = WifiServiceManager::GetInstance().GetEnhanceServiceInst();
        if (pEnhanceService != nullptr) {
            pEnhanceService->OnNotificationReceive();
        }
    }
}

void NotificationEventSubscriber::OnReceiveDialogAcceptEvent(int dialogType)
{
    if (dialogType == static_cast<int>(WifiDialogType::CANDIDATE_CONNECT)) {
        NotifyCandidateApprovalStatus(CandidateApprovalStatus::USER_ACCEPT);
        int candidateNetworkId = WifiConfigCenter::GetInstance().GetSelectedCandidateNetworkId();
        if (candidateNetworkId == INVALID_NETWORK_ID) {
            WIFI_LOGI("OnReceiveNotificationEvent networkid is invalid");
            return;
        }
        WifiSettings::GetInstance().SetDeviceEphemeral(candidateNetworkId, false);
        WifiSettings::GetInstance().SyncDeviceConfig();
        IStaService *pService = WifiServiceManager::GetInstance().GetStaServiceInst(0);
        if (pService != nullptr) {
            pService->ConnectToNetwork(candidateNetworkId);
        }
    } else if (dialogType == static_cast<int>(WifiDialogType::AUTO_IDENTIFY_CONN)) {
        IEnhanceService *pEnhanceService = WifiServiceManager::GetInstance().GetEnhanceServiceInst();
        if (pEnhanceService != nullptr) {
            pEnhanceService->OnDialogClick(true);
        }
    } else if (dialogType == static_cast<int>(WifiDialogType::SETTINGS_AUTO_IDENTIFY_CONN)) {
        IEnhanceService *pEnhanceService = WifiServiceManager::GetInstance().GetEnhanceServiceInst();
        if (pEnhanceService != nullptr) {
            pEnhanceService->OnSettingsDialogClick(true, SETTINGS_5G_AUTO_IDENTIFY_CONN);
        }
    }
#ifdef FEATURE_P2P_SUPPORT
    if (dialogType == static_cast<int>(WifiDialogType::P2P_WSC_PBC_DIALOG)) {
        WIFI_LOGI("OnReceiveNotification P2P_WSC_PBC_DIALOG Accept");

        IP2pService *p2pService = WifiServiceManager::GetInstance().GetP2pServiceInst();
        if (p2pService != nullptr) {
            p2pService->NotifyWscDialogConfirmResult(true);
        }
    }
#endif
}

void NotificationEventSubscriber::OnReceiveDialogRejectEvent(int dialogType, bool noAction)
{
    if (dialogType == static_cast<int>(WifiDialogType::AUTO_IDENTIFY_CONN)) {
        IEnhanceService *pEnhanceService = WifiServiceManager::GetInstance().GetEnhanceServiceInst();
        if (pEnhanceService != nullptr) {
            pEnhanceService->OnDialogClick(false);
        }
    } else if (dialogType == static_cast<int>(WifiDialogType::SETTINGS_AUTO_IDENTIFY_CONN)) {
        IEnhanceService *pEnhanceService = WifiServiceManager::GetInstance().GetEnhanceServiceInst();
        if (pEnhanceService != nullptr) {
            pEnhanceService->OnSettingsDialogClick(false, SETTINGS_5G_AUTO_IDENTIFY_CONN);
        }
    } else if (dialogType == static_cast<int>(WifiDialogType::CANDIDATE_CONNECT)) {
        WifiConfigCenter::GetInstance().SetSelectedCandidateNetworkId(INVALID_NETWORK_ID);
        if (noAction) {
            NotifyCandidateApprovalStatus(CandidateApprovalStatus::USER_NO_RESPOND);
        } else {
            NotifyCandidateApprovalStatus(CandidateApprovalStatus::USER_REJECT);
        }
    }

#ifdef FEATURE_P2P_SUPPORT
    if (dialogType == static_cast<int>(WifiDialogType::P2P_WSC_PBC_DIALOG)) {
        WIFI_LOGI("OnReceiveNotification P2P_WSC_PBC_DIALOG Reject");
        IP2pService *p2pService = WifiServiceManager::GetInstance().GetP2pServiceInst();
        if (p2pService != nullptr) {
            p2pService->NotifyWscDialogConfirmResult(false);
        }
    }
#endif
}

void NotificationEventSubscriber::NotifyCandidateApprovalStatus(CandidateApprovalStatus status)
{
    WifiEventCallbackMsg cbMsg;
    cbMsg.msgCode = WIFI_CBK_MSG_CANDIDATE_CONNECT_CHANGE;
    cbMsg.msgData = static_cast<int>(status);
    WifiInternalEventDispatcher::GetInstance().AddBroadCastMsg(cbMsg);
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
#ifdef FEATURE_HPF_SUPPORT
    if (action == COMMON_EVENT_POWER_MANAGER_STATE_CHANGED) {
        WIFI_LOGI("Receive power manager state Event: %{public}s", eventData.GetCode());
        for (int i = 0; i < STA_INSTANCE_MAX_NUM; ++i) {
            WifiManager::GetInstance().InstallPacketFilterProgram(eventData.GetCode(), i);
        }
    }
#endif
}

#endif
#ifdef HAS_NETMANAGER_EVENT_PART
void WifiEventSubscriberManager::RegisterNetmgrEvent()
{
    std::unique_lock<std::mutex> lock(netmgrEventMutex);
    if (netMgrId != 0) {
        WifiTimer::GetInstance()->UnRegister(netMgrId);
    }
    if (wifiNetmgrEventSubsciber_) {
        return;
    }
    OHOS::EventFwk::MatchingSkills matchingSkills;
    matchingSkills.AddEvent(WIFI_EVENT_BG_CONTINUOUS_TASK_STATE);
    WIFI_LOGI("RegisterNetmgrEvent start");
    EventFwk::CommonEventSubscribeInfo subscriberInfo(matchingSkills);
    subscriberInfo.SetThreadMode(EventFwk::CommonEventSubscribeInfo::COMMON);
    subscriberInfo.SetPermission("ohos.permission.ACCESS_BOOSTER_SERVICE");
    wifiNetmgrEventSubsciber_ = std::make_shared<NetmgrEventSubscriber>(subscriberInfo);
    if (!EventFwk::CommonEventManager::SubscribeCommonEvent(wifiNetmgrEventSubsciber_)) {
        WIFI_LOGE("RegisterNetmgrEvent SubscribeCommonEvent failed");
        wifiNetmgrEventSubsciber_ = nullptr;
        WifiTimer::TimerCallback timeoutCallBack = std::bind(&WifiEventSubscriberManager::RegisterNetmgrEvent, this);
        WifiTimer::GetInstance()->Register(timeoutCallBack, netMgrId, TIMEOUT_EVENT_SUBSCRIBER, false);
        WIFI_LOGI("RegisterNetmgrEvent retry, netMgrId = %{public}u", netMgrId);
    } else {
        WIFI_LOGI("RegisterNetmgrEvent success");
    }
}

void WifiEventSubscriberManager::UnRegisterNetmgrEvent()
{
    std::unique_lock<std::mutex> lock(netmgrEventMutex);
    if (netMgrId != 0) {
        WifiTimer::GetInstance()->UnRegister(netMgrId);
    }
    if (!wifiNetmgrEventSubsciber_) {
        return;
    }
    if (!EventFwk::CommonEventManager::UnSubscribeCommonEvent(wifiNetmgrEventSubsciber_)) {
        WIFI_LOGE("UnRegisterNetmgrEvent failed");
    }
    wifiNetmgrEventSubsciber_ = nullptr;
    WIFI_LOGI("UnRegisterNetmgrEvent finished");
}

NetmgrEventSubscriber::NetmgrEventSubscriber(const OHOS::EventFwk::CommonEventSubscribeInfo &subscriberInfo)
    : CommonEventSubscriber(subscriberInfo)
{
    WIFI_LOGI("NetmgrEventSubscriber enter");
}

NetmgrEventSubscriber::~NetmgrEventSubscriber()
{
    WIFI_LOGI("~NetmgrEventSubscriber enter");
}

void NetmgrEventSubscriber::OnReceiveEvent(const OHOS::EventFwk::CommonEventData &eventData)
{
    int bgContinuousTaskState = eventData.GetCode();
    WIFI_LOGI("NetmgrEventSubscriber OnReceiveEvent by BgTaskAware %{public}d", bgContinuousTaskState);
    IStaService *pService = WifiServiceManager::GetInstance().GetStaServiceInst();
    if (pService == nullptr) {
        WIFI_LOGE("pService is nullptr!");
        return;
    }
    pService->DeliverAudioState(bgContinuousTaskState);
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
        WifiTimer::TimerCallback timeoutCallBack = [this]() { this->RegisterAssetEvent(); };
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
    if (action != COMMON_EVENT_ASSETCLOUD_MANAGER_STATE_CHANGED) {
        return;
    }
    // Do not sync from cloud during connecting
    for (int i = 0; i < STA_INSTANCE_MAX_NUM; ++i) {
        IStaService *pService = WifiServiceManager::GetInstance().GetStaServiceInst(i);
        if (pService != nullptr) {
            WifiLinkedInfo linkedInfo;
            WifiConfigCenter::GetInstance().GetLinkedInfo(linkedInfo, i);
            if (linkedInfo.connState == ConnState::CONNECTING) {
                return;
            }
        }
    }
    WifiAssetManager::GetInstance().CloudAssetSync();
}
#endif
void CesEventSubscriber::OnReceiveUserUnlockedEvent(const OHOS::EventFwk::CommonEventData &eventData)
{
    WIFI_LOGI("OnReceiveUserUnlockedEvent");
#ifdef SUPPORT_ClOUD_WIFI_ASSET
    WifiAssetManager::GetInstance().InitUpLoadLocalDeviceSync();
#endif
}

void WifiEventSubscriberManager::RegisterNetworkStateChangeEvent()
{
    std::unique_lock<std::mutex> lock(networkStateChangeEventMutex);
    if (networkStateChangeTimerId != 0) {
        WifiTimer::GetInstance()->UnRegister(networkStateChangeTimerId);
    }
    if (networkStateChangeSubsciber_) {
        return;
    }
    EventFwk::MatchingSkills matchingSkills;
    matchingSkills.AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_NETWORK_STATE_CHANGED);
    EventFwk::CommonEventSubscribeInfo subscriberInfo(matchingSkills);
    networkStateChangeSubsciber_
        = std::make_shared<NetworkStateChangeSubscriber>(subscriberInfo);
    if (!EventFwk::CommonEventManager::SubscribeCommonEvent(networkStateChangeSubsciber_)) {
        WIFI_LOGE("network state change subscribe failed");
        networkStateChangeSubsciber_ = nullptr;
        WifiTimer::TimerCallback timeoutCallBack = [this]() { this->RegisterNetworkStateChangeEvent(); };
        WifiTimer::GetInstance()->Register(timeoutCallBack, networkStateChangeTimerId, TIMEOUT_EVENT_SUBSCRIBER, false);
        WIFI_LOGI("RegisterNetworkStateChangeEvent retry, timerId = %{public}u", networkStateChangeTimerId);
    } else {
        WIFI_LOGI("RegisterNetworkStateChangeEvent success");
    }
}

void WifiEventSubscriberManager::UnRegisterNetworkStateChangeEvent()
{
    std::unique_lock<std::mutex> lock(networkStateChangeEventMutex);
    if (networkStateChangeTimerId != 0) {
        WifiTimer::GetInstance()->UnRegister(networkStateChangeTimerId);
    }
    if (!networkStateChangeSubsciber_) {
        return;
    }
    if (!EventFwk::CommonEventManager::UnSubscribeCommonEvent(networkStateChangeSubsciber_)) {
        WIFI_LOGE("UnRegisterNetworkStateChangeEvent failed");
    }
    networkStateChangeSubsciber_ = nullptr;
    WIFI_LOGI("UnRegisterNetworkStateChangeEvent finished");
}

NetworkStateChangeSubscriber::NetworkStateChangeSubscriber(
    const EventFwk::CommonEventSubscribeInfo &subscriberInfo) : CommonEventSubscriber(subscriberInfo)
{
    WIFI_LOGI("NetworkStateChangeSubscriber enter");
}

void NetworkStateChangeSubscriber::OnReceiveEvent(const EventFwk::CommonEventData &eventData)
{
    const auto &action = eventData.GetWant().GetAction();
    if (action == EventFwk::CommonEventSupport::COMMON_EVENT_NETWORK_STATE_CHANGED) {
        WifiCountryCodeManager::GetInstance().TriggerUpdateWifiCountryCode(TRIGGER_UPDATE_REASON_TEL_NET_CHANGE);
    }
}

void WifiEventSubscriberManager::RegisterWifiScanChangeEvent()
{
    std::unique_lock<std::mutex> lock(wifiScanChangeEventMutex);
    if (wifiScanChangeTimerId != 0) {
        WifiTimer::GetInstance()->UnRegister(wifiScanChangeTimerId);
    }
    if (wifiScanEventChangeSubscriber_) {
        return;
    }
    EventFwk::MatchingSkills matchingSkills;
    matchingSkills.AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_WIFI_SCAN_FINISHED);
    EventFwk::CommonEventSubscribeInfo subscriberInfo(matchingSkills);
    wifiScanEventChangeSubscriber_
        = std::make_shared<WifiScanEventChangeSubscriber>(subscriberInfo);
    if (!EventFwk::CommonEventManager::SubscribeCommonEvent(wifiScanEventChangeSubscriber_)) {
        WIFI_LOGE("network state change subscribe failed");
        wifiScanEventChangeSubscriber_ = nullptr;
        WifiTimer::TimerCallback timeoutCallBack = [this]() {this->RegisterWifiScanChangeEvent(); };
        WifiTimer::GetInstance()->Register(timeoutCallBack, wifiScanChangeTimerId, TIMEOUT_EVENT_SUBSCRIBER, false);
        WIFI_LOGI("RegisterWifiScanChangeEvent retry, wifiScanChangeTimerId = %{public}u", wifiScanChangeTimerId);
    } else {
        WIFI_LOGI("RegisterWifiScanChangeEvent success");
    }
}

void WifiEventSubscriberManager::UnRegisterWifiScanChangeEvent()
{
    std::unique_lock<std::mutex> lock(wifiScanChangeEventMutex);
    if (wifiScanChangeTimerId != 0) {
        WifiTimer::GetInstance()->UnRegister(wifiScanChangeTimerId);
    }
    if (!wifiScanEventChangeSubscriber_) {
        return;
    }
    if (!EventFwk::CommonEventManager::UnSubscribeCommonEvent(wifiScanEventChangeSubscriber_)) {
        WIFI_LOGE("UnRegisterWifiScanChangeEvent failed");
    }
    wifiScanEventChangeSubscriber_ = nullptr;
    WIFI_LOGI("UnRegisterWifiScanChangeEvent finished");
}

WifiScanEventChangeSubscriber::WifiScanEventChangeSubscriber(
    const EventFwk::CommonEventSubscribeInfo &subscriberInfo) : CommonEventSubscriber(subscriberInfo)
{
    WIFI_LOGI("WifiScanEventChangeSubscriber enter");
}

void WifiScanEventChangeSubscriber::OnReceiveEvent(const EventFwk::CommonEventData &eventData)
{
    const auto &action = eventData.GetWant().GetAction();
    if (action == EventFwk::CommonEventSupport::COMMON_EVENT_WIFI_SCAN_FINISHED &&
        eventData.GetCode() == static_cast<int>(ScanHandleNotify::SCAN_OK)) {
        WifiCountryCodeManager::GetInstance().TriggerUpdateWifiCountryCode(TRIGGER_UPDATE_REASON_SCAN_CHANGE);
    }
}

void WifiEventSubscriberManager::RegisterSettingsEnterEvent()
{
    WIFI_LOGI("RegisterSettingsEnterEvent enter");
    std::unique_lock<std::mutex> lock(settingsEnterEventMutex);
    if (settingsTimerId != 0) {
        WifiTimer::GetInstance()->UnRegister(settingsTimerId);
    }
    if (settingsEnterSubscriber_) {
        return;
    }
    OHOS::EventFwk::MatchingSkills matchingSkills;
    matchingSkills.AddEvent(ENTER_SETTINGS);
    OHOS::EventFwk::CommonEventSubscribeInfo subscriberInfo(matchingSkills);
    subscriberInfo.SetThreadMode(EventFwk::CommonEventSubscribeInfo::COMMON);
    subscriberInfo.SetPermission("ohos.permission.SET_WIFI_CONFIG");
    settingsEnterSubscriber_ = std::make_shared<SettingsEnterSubscriber>(subscriberInfo);
    if (!EventFwk::CommonEventManager::SubscribeCommonEvent(settingsEnterSubscriber_)) {
        WIFI_LOGE("RegisterSettingsEnterEvent failed");
        settingsEnterSubscriber_ = nullptr;
        WifiTimer::TimerCallback timeoutCallBack = [this]() { this->RegisterSettingsEnterEvent(); };
        WifiTimer::GetInstance()->Register(timeoutCallBack, settingsTimerId, TIMEOUT_EVENT_SUBSCRIBER, false);
        WIFI_LOGI("RegisterSettingsEnterEvent retry, settingsTimerId = %{public}u", settingsTimerId);
    } else {
        WIFI_LOGI("RegisterSettingsEnterEvent success");
    }
}

void WifiEventSubscriberManager::UnRegisterSettingsEnterEvent()
{
    std::unique_lock<std::mutex> lock(settingsEnterEventMutex);
    if (settingsTimerId != 0) {
        WifiTimer::GetInstance()->UnRegister(settingsTimerId);
    }
    if (!settingsEnterSubscriber_) {
        return;
    }
    if (!EventFwk::CommonEventManager::UnSubscribeCommonEvent(settingsEnterSubscriber_)) {
        WIFI_LOGE("UnRegisterSettingsEnterEvent failed");
    }
    settingsEnterSubscriber_ = nullptr;
    WIFI_LOGI("UnRegisterSettingsEnterEvent finished");
}

SettingsEnterSubscriber::SettingsEnterSubscriber(
    const EventFwk::CommonEventSubscribeInfo &subscriberInfo) : CommonEventSubscriber(subscriberInfo)
{
    WIFI_LOGI("SettingsEnterSubscriber enter");
}

void SettingsEnterSubscriber::OnReceiveEvent(const EventFwk::CommonEventData &eventData)
{
    const auto &action = eventData.GetWant().GetAction();
    WIFI_LOGI("SettingsEnterSubscriber OnReceiveEvent: %{public}s", action.c_str());
    if (action == ENTER_SETTINGS) {
        bool isSettingsEnter = eventData.GetWant().GetBoolParam(WLAN_PAGE_ENTER, false);
        BlockConnectService::GetInstance().OnReceiveSettingsEnterEvent(isSettingsEnter);
        IEnhanceService *pEnhanceService = WifiServiceManager::GetInstance().GetEnhanceServiceInst();
        if (pEnhanceService != nullptr) {
            pEnhanceService->OnSettingsWlanEnterReceive();
        }
    }
}

void WifiEventSubscriberManager::RegisterDataShareReadyEvent()
{
    WIFI_LOGI("RegisterDataShareReadyEvent enter");
    std::unique_lock<std::mutex> lock(dataShareReadyEventMutex_);
    if (dataShareReadyTimerId_ != 0) {
        WifiTimer::GetInstance()->UnRegister(dataShareReadyTimerId_);
    }
    if (dataShareReadySubscriber_) {
        return;
    }
    OHOS::EventFwk::MatchingSkills matchingSkills;
    matchingSkills.AddEvent(OHOS::EventFwk::CommonEventSupport::COMMON_EVENT_DATA_SHARE_READY);
    OHOS::EventFwk::CommonEventSubscribeInfo subscriberInfo(matchingSkills);
    dataShareReadySubscriber_ = std::make_shared<DataShareReadySubscriber>(subscriberInfo);
    if (!EventFwk::CommonEventManager::SubscribeCommonEvent(dataShareReadySubscriber_)) {
        WIFI_LOGE("RegisterDataShareReadyEvent failed");
        dataShareReadySubscriber_ = nullptr;
        WifiTimer::TimerCallback timeoutCallBack = [this]() { this->RegisterDataShareReadyEvent(); };
        WifiTimer::GetInstance()->Register(timeoutCallBack, dataShareReadyTimerId_, TIMEOUT_EVENT_SUBSCRIBER, false);
        WIFI_LOGI("RegisterDataShareReadyEvent retry, dataShareReadyTimerId_ = %{public}u", dataShareReadyTimerId_);
    } else {
        WIFI_LOGI("RegisterDataShareReadyEvent success");
    }
}

void WifiEventSubscriberManager::UnRegisterDataShareReadyEvent()
{
    std::unique_lock<std::mutex> lock(dataShareReadyEventMutex_);
    if (dataShareReadyTimerId_ != 0) {
        WifiTimer::GetInstance()->UnRegister(dataShareReadyTimerId_);
    }
    if (!dataShareReadySubscriber_) {
        return;
    }
    if (!EventFwk::CommonEventManager::UnSubscribeCommonEvent(dataShareReadySubscriber_)) {
        WIFI_LOGE("UnRegisterDataShareReadyEvent failed");
    }
    dataShareReadySubscriber_ = nullptr;
    WIFI_LOGI("UnRegisterDataShareReadyEvent finished");
}

DataShareReadySubscriber::DataShareReadySubscriber(
    const EventFwk::CommonEventSubscribeInfo &subscriberInfo) : CommonEventSubscriber(subscriberInfo)
{
    WIFI_LOGI("DataShareReadySubscriber enter");
}

void DataShareReadySubscriber::OnReceiveEvent(const EventFwk::CommonEventData &eventData)
{
    const auto &action = eventData.GetWant().GetAction();
    WIFI_LOGI("DataShareReadySubscriber OnReceiveEvent: %{public}s", action.c_str());
    if (action == OHOS::EventFwk::CommonEventSupport::COMMON_EVENT_DATA_SHARE_READY) {
        WifiManager::GetInstance().GetWifiEventSubscriberManager()->AccessDataShare();
        WifiManager::GetInstance().GetWifiEventSubscriberManager()->RegisterLocationEvent();
        WifiSensorScene::GetInstance().Init();
    }
}

WifiDisplayStateListener::WifiDisplayStateListener()
{
    WIFI_LOGI("WifiDisplayStateListener Enter");
}
void WifiDisplayStateListener::OnCreate(uint64_t displayId)
{}
 
void WifiDisplayStateListener::OnDestroy(uint64_t displayId)
{}
 
void WifiDisplayStateListener::OnChange(uint64_t displayId)
{
    sptr<Rosen::DisplayLite> displayLite = Rosen::DisplayManagerLite::GetInstance().GetDisplayById(displayId);
    if (displayLite == nullptr) {
        WIFI_LOGE("OnChange displayLite fail");
        return;
    }
    auto displayInfo =  displayLite->GetDisplayInfo();
    if (displayInfo == nullptr) {
        WIFI_LOGE("OnChange displayInfo fail");
        return;
    }
    // screen state
    auto orientation = displayInfo->GetDisplayOrientation();
    WifiConfigCenter::GetInstance().SetScreenDispalyState(static_cast<int32_t>(orientation));
}

WifiFoldStateListener::WifiFoldStateListener()
{
    WIFI_LOGI("WifiFoldStateListener Enter");
}

void WifiFoldStateListener::OnFoldStatusChanged(Rosen::FoldStatus foldStatus)
{
    for (int i = 0; i < STA_INSTANCE_MAX_NUM; ++i) {
        IStaService *pService = WifiServiceManager::GetInstance().GetStaServiceInst(i);
        if (pService != nullptr) {
            pService->OnFoldStateChanged(static_cast<int>(foldStatus));
        }
    }
}

void WifiEventSubscriberManager::RegisterDisplayListener()
{
    std::unique_lock<std::mutex> lock(displayStatusListenerMutex_);
    if (displayStatusListener_ != nullptr) {
        return;
    }
    displayStatusListener_ = new(std::nothrow) WifiDisplayStateListener();
    if (displayStatusListener_ == nullptr) {
        WIFI_LOGE("RegisterDisplayListener fail");
        return;
    }
 
    auto ret = Rosen::DisplayManagerLite::GetInstance().RegisterDisplayListener(displayStatusListener_);
    if (ret != Rosen::DMError::DM_OK) {
        WIFI_LOGE("RegisterDisplayListener fail");
        displayStatusListener_ = nullptr;
    } else {
        WIFI_LOGI("RegisterDisplayListener success");
    }
}
 
void WifiEventSubscriberManager::UnregisterDisplayListener()
{
    std::unique_lock<std::mutex> lock(displayStatusListenerMutex_);
    if (displayStatusListener_ == nullptr) {
        WIFI_LOGE("UnregisterDisplayListener fail");
        return;
    }
 
    auto ret = Rosen::DisplayManagerLite::GetInstance().UnregisterDisplayListener(displayStatusListener_);
    if (ret != Rosen::DMError::DM_OK) {
        WIFI_LOGE("UnregisterDisplayListener fail");
    }
    displayStatusListener_ = nullptr;
    WIFI_LOGI("UnregisterDisplayListener finished");
}

void WifiEventSubscriberManager::RegisterFoldStatusListener()
{
    std::unique_lock<std::mutex> lock(foldStatusListenerMutex_);
    if (foldStatusListener_ != nullptr) {
        return;
    }
    foldStatusListener_ = new(std::nothrow) WifiFoldStateListener();
    if (foldStatusListener_ == nullptr) {
        WIFI_LOGE("RegisterFoldStatusListener fail");
        return;
    }

    auto ret = Rosen::DisplayManagerLite::GetInstance().RegisterFoldStatusListener(foldStatusListener_);
    if (ret != Rosen::DMError::DM_OK) {
        WIFI_LOGE("RegisterFoldStatusListener fail");
        foldStatusListener_ = nullptr;
    } else {
        WIFI_LOGI("RegisterDisplayMode success");
    }
}

void WifiEventSubscriberManager::UnRegisterFoldStatusListener()
{
    std::unique_lock<std::mutex> lock(foldStatusListenerMutex_);
    if (foldStatusListener_ == nullptr) {
        WIFI_LOGE("RegisterFoldStatusListener fail");
        return;
    }

    auto ret = Rosen::DisplayManagerLite::GetInstance().UnregisterFoldStatusListener(foldStatusListener_);
    if (ret != Rosen::DMError::DM_OK) {
        WIFI_LOGE("UnRegisterFoldStatusListener fail");
    }
    foldStatusListener_ = nullptr;
    WIFI_LOGI("UnRegisterDisplayMode finished");
}

void WifiEventSubscriberManager::RegisterNetworkConnSubscriber()
{
    std::lock_guard<std::mutex> lock(networkConnSubscriberLock_);
    if (networkConnSubscriber_ == nullptr) {
        networkConnSubscriber_ = sptr<NetworkConnSubscriber>::MakeSptr();
    } else {
        return;
    }
    if (networkConnSubscriber_ != nullptr) {
        int32_t  registerResult = NetManagerStandard::NetConnClient::GetInstance().RegisterNetConnCallback(
            networkConnSubscriber_);
        WIFI_LOGI("RegisterNetConnCallback end, registerResult=%{public}d.", registerResult);
    } else {
        WIFI_LOGE("Init, NetworkConnSubscriber make sptr error.");
    }
}

void WifiEventSubscriberManager::UnRegisterNetworkConnSubscriber()
{
    std::lock_guard<std::mutex> lock(networkConnSubscriberLock_);
    if (networkConnSubscriber_ != nullptr) {
        int32_t unregisterResult = NetManagerStandard::NetConnClient::GetInstance().UnregisterNetConnCallback(
            networkConnSubscriber_);
        WIFI_LOGI("UnregisterNetConnCallback end, result=%{public}d.", unregisterResult);
        networkConnSubscriber_ = nullptr;
    }
}

int NetworkConnSubscriber::NetCapabilitiesChange(sptr<NetManagerStandard::NetHandle> &netHandle,
    const sptr<NetManagerStandard::NetAllCapabilities> &netAllCap)
{
    const int noValidatedNet = 1;
    if (netAllCap->netCaps_.find(NetManagerStandard::NET_CAPABILITY_VALIDATED) == netAllCap->netCaps_.end()) {
        IApService *pService = WifiServiceManager::GetInstance().GetApServiceInst(0);
        if (pService != nullptr) {
            pService->OnNetCapabilitiesChanged(noValidatedNet);
        }
    }
    return 0;
}

}  // namespace Wifi
}  // namespace OHOS
#endif
