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

#include "wifi_toggler_manager.h"
#include "wifi_manager.h"
#include "wifi_service_manager.h"
#include "wifi_config_center.h"
#include "wifi_logger.h"
#ifdef HDI_CHIP_INTERFACE_SUPPORT
#include "hal_device_manage.h"
#endif
#ifndef OHOS_ARCH_LITE
#include "iservice_registry.h"
#include "netsys_native_service_proxy.h"
#include "system_ability_definition.h"
#endif
#include "wifi_controller_define.h"

DEFINE_WIFILOG_LABEL("WifiTogglerManager")

namespace OHOS {
namespace Wifi {

#ifndef OHOS_ARCH_LITE
bool mIsSatelliteStart = false;
constexpr int32_t WIFI_MODE_RSMC_START = 3009;
constexpr int32_t WIFI_MODE_RSMC_STOP = 3010;
constexpr int32_t WIFI_MODE_RSMC_CHECK = 3011;
constexpr const char *IFACE_LINK_UP = "up";
constexpr const char *IFACE_RUNNING = "running";
#endif

WifiTogglerManager::WifiTogglerManager()
{
    WIFI_LOGI("create WifiTogglerManager");
#ifdef HDI_CHIP_INTERFACE_SUPPORT
    HalDeviceManager::GetInstance().StartChipHdi();
#endif
    InitConcreteCallback();
    InitSoftapCallback();
    InitMultiStacallback();
    InitRptCallback();
#ifdef HDI_CHIP_INTERFACE_SUPPORT
    InitChipHdiCallback();
    HalDeviceManager::GetInstance().RegisterChipHdiDeathCallback(mChipHdiServiceCb);
#endif
    pWifiControllerMachine = std::make_unique<WifiControllerMachine>();
    if (pWifiControllerMachine) {
        pWifiControllerMachine->InitWifiControllerMachine();
    }
}

ConcreteModeCallback& WifiTogglerManager::GetConcreteCallback()
{
    return mConcreteModeCb;
}

SoftApModeCallback& WifiTogglerManager::GetSoftApCallback()
{
    return mSoftApModeCb;
}

MultiStaModeCallback& WifiTogglerManager::GetMultiStaCallback()
{
    return mMultiStaModeCb;
}

RptModeCallback& WifiTogglerManager::GetRptCallback()
{
    return mRptModeCb;
}

ErrCode WifiTogglerManager::WifiToggled(int isOpen, int id)
{
    pWifiControllerMachine->ClearWifiStartFailCount();
    WIFI_LOGI("WifiTogglerManager::WifiToggled, isOpen %{public}d instId: %{public}d", isOpen, id);
#ifdef FEATURE_SELF_CURE_SUPPORT
    if (isOpen == 0) {
        ISelfCureService *pSelfCureService = WifiServiceManager::GetInstance().GetSelfCureServiceInst(id);
        if (pSelfCureService != nullptr) {
            pSelfCureService->StopSelfCureWifi(SCE_WIFI_STATUS_LOST);
        }
    }
#endif // FEATURE_SELF_CURE_SUPPORT
    pWifiControllerMachine->SendMessage(CMD_WIFI_TOGGLED, isOpen, id);
    return WIFI_OPT_SUCCESS;
}

void WifiTogglerManager::StartWifiToggledTimer()
{
    WIFI_LOGD("StartWifiToggledTimer");
    WifiOprMidState midState = WifiConfigCenter::GetInstance().GetWifiMidState(INSTID_WLAN0);
    if (midState != WifiOprMidState::RUNNING && midState != WifiOprMidState::OPENING) {
        pWifiControllerMachine->StopTimer(CMD_WIFI_TOGGLED_TIMEOUT);
        pWifiControllerMachine->MessageExecutedLater(CMD_WIFI_TOGGLED_TIMEOUT, WIFI_OPEN_TIMEOUT);
    } else {
        WIFI_LOGW("start wifi when wifi is already opening or opened");
    }
}

void WifiTogglerManager::StopWifiToggledTimer()
{
    WIFI_LOGD("StopWifiToggledTimer");
    pWifiControllerMachine->StopTimer(CMD_WIFI_TOGGLED_TIMEOUT);
}

void WifiTogglerManager::OnWifiToggledTimeOut()
{
    WIFI_LOGE("OnWifiToggledTimeOut");
    WriteWifiOpenAndCloseFailedHiSysEvent(static_cast<int>(OperateResState::OPEN_WIFI_FAILED),
        "TIME_OUT", static_cast<int>(WifiConfigCenter::GetInstance().GetWifiMidState(INSTID_WLAN0)));
}

void WifiTogglerManager::StartSemiWifiToggledTimer()
{
    WIFI_LOGD("StartSemiWifiToggledTimer");
    pWifiControllerMachine->StopTimer(CMD_SEMI_WIFI_TOGGLED_TIMEOUT);
    pWifiControllerMachine->MessageExecutedLater(CMD_SEMI_WIFI_TOGGLED_TIMEOUT, WIFI_OPEN_TIMEOUT);
}

void WifiTogglerManager::StopSemiWifiToggledTimer()
{
    WIFI_LOGD("StopSemiWifiToggledTimer");
    pWifiControllerMachine->StopTimer(CMD_SEMI_WIFI_TOGGLED_TIMEOUT);
}

void WifiTogglerManager::OnSemiWifiToggledTimeOut()
{
    WIFI_LOGE("OnSemiWifiToggledTimeOut");
    WriteWifiOpenAndCloseFailedHiSysEvent(static_cast<int>(OperateResState::ENABLE_SEMI_WIFI_FAILED),
        "TIME_OUT", static_cast<int>(WifiConfigCenter::GetInstance().GetWifiMidState(INSTID_WLAN0)));
}

ErrCode WifiTogglerManager::SoftapToggled(int isOpen, int id)
{
    if (isOpen) {
        WIFI_LOGI("set softap toggled true");
        WifiConfigCenter::GetInstance().SetSoftapToggledState(true);
        WriteSoftApOperateHiSysEvent(static_cast<int>(SoftApChrEventType::SOFT_AP_OPEN_CNT));
    } else {
        WIFI_LOGI("set softap toggled false");
        WifiConfigCenter::GetInstance().SetSoftapToggledState(false);
    }
    pWifiControllerMachine->SendMessage(CMD_SOFTAP_TOGGLED, isOpen, id);
    return WIFI_OPT_SUCCESS;
}

ErrCode WifiTogglerManager::ScanOnlyToggled(int isOpen)
{
    int airplanState = WifiConfigCenter::GetInstance().GetAirplaneModeState();
    if (airplanState == MODE_STATE_OPEN) {
        WIFI_LOGE("Airplane mode do not start scanonly.");
        return WIFI_OPT_FAILED;
    }
    if (!WifiConfigCenter::GetInstance().GetCoexSupport() && HasAnyApRuning() &&
        WifiConfigCenter::GetInstance().GetApIfaceName() == "wlan0") {
        WIFI_LOGE("Softap(wlan0) mode do not start scanonly.");
        return WIFI_OPT_FAILED;
    }
    pWifiControllerMachine->SendMessage(CMD_SCAN_ALWAYS_MODE_CHANGED, isOpen, 0);
    return WIFI_OPT_SUCCESS;
}

ErrCode WifiTogglerManager::AirplaneToggled(int isOpen)
{
#ifdef FEATURE_SELF_CURE_SUPPORT
    if (isOpen) {
        for (int i = 0; i < STA_INSTANCE_MAX_NUM; ++i) {
            ISelfCureService *pSelfCureService = WifiServiceManager::GetInstance().GetSelfCureServiceInst(i);
            if (pSelfCureService != nullptr) {
                pSelfCureService->StopSelfCureWifi(SCE_WIFI_STATUS_LOST);
            }
        }
    }
#endif // FEATURE_SELF_CURE_SUPPORT
    if (pWifiControllerMachine) {
        pWifiControllerMachine->SendMessage(CMD_AIRPLANE_TOGGLED, isOpen);
    }
    return WIFI_OPT_SUCCESS;
}

bool WifiTogglerManager::HasAnyApRuning()
{
    WifiOprMidState apState0 = WifiConfigCenter::GetInstance().GetApMidState(0);
    WifiOprMidState apState1 = WifiConfigCenter::GetInstance().GetApMidState(1);
    if (apState0 == WifiOprMidState::RUNNING || apState0 == WifiOprMidState::OPENING ||
        apState1 == WifiOprMidState::RUNNING || apState1 == WifiOprMidState::OPENING) {
        return true;
    }
    return false;
}

std::unique_ptr<WifiControllerMachine>& WifiTogglerManager::GetControllerMachine()
{
    return pWifiControllerMachine;
}

void WifiTogglerManager::InitConcreteCallback()
{
    mConcreteModeCb.onStartFailure = [this](int id) { this->DealConcreateStartFailure(id); };
    mConcreteModeCb.onStopped = [this](int id) { this->DealConcreateStop(id); };
    mConcreteModeCb.onRemoved = [this](int id) { this->DealClientRemoved(id); };
}

void WifiTogglerManager::InitSoftapCallback()
{
    mSoftApModeCb.onStartFailure = [this](int id) { this->DealSoftapStartFailure(id); };
    mSoftApModeCb.onStopped =  [this](int id) { this->DealSoftapStop(id); };
}

void WifiTogglerManager::InitMultiStacallback()
{
    using namespace std::placeholders;
    mMultiStaModeCb.onStartFailure = [this](int id){ this->DealMultiStaStartFailure(id); };
    mMultiStaModeCb.onStopped = [this](int id){ this->DealMultiStaStop(id); };
}

void WifiTogglerManager::InitRptCallback()
{
    using namespace std::placeholders;
    mRptModeCb.onStartFailure = [this](int id){ this->DealRptStartFailure(id); };
    mRptModeCb.onStopped = [this](int id){ this->DealRptStop(id); };
}

void WifiTogglerManager::DealConcreateStop(int id)
{
    if (pWifiControllerMachine) {
        WIFI_LOGI("SendMessage msg is  CMD_CONCRETE_STOPPED");
        pWifiControllerMachine->SendMessage(CMD_CONCRETE_STOPPED, id);
    }
}

void WifiTogglerManager::DealConcreateStartFailure(int id)
{
    if (pWifiControllerMachine) {
        pWifiControllerMachine->SendMessage(CMD_STA_START_FAILURE, id);
    }
}

#ifdef HDI_CHIP_INTERFACE_SUPPORT
void WifiTogglerManager::InitChipHdiCallback(void)
{
    mChipHdiServiceCb = [this](){ this->DealChipServiceDied(); };
}
#endif

void WifiTogglerManager::DealSoftapStop(int id)
{
    if (pWifiControllerMachine) {
        pWifiControllerMachine->SendMessage(CMD_AP_STOPPED, id);
    }
}

void WifiTogglerManager::DealSoftapStartFailure(int id)
{
    if (pWifiControllerMachine) {
        pWifiControllerMachine->SendMessage(CMD_AP_START_FAILURE, id);
    }
}

void WifiTogglerManager::DealRptStop(int id)
{
    if (pWifiControllerMachine) {
        pWifiControllerMachine->SendMessage(CMD_RPT_STOPPED, id);
    }
}

void WifiTogglerManager::DealRptStartFailure(int id)
{
    if (pWifiControllerMachine) {
        pWifiControllerMachine->SendMessage(CMD_RPT_START_FAILURE);
    }
}

void WifiTogglerManager::DealClientRemoved(int id)
{
    if (pWifiControllerMachine) {
        WIFI_LOGI("SendMessage msg is  CMD_CONCRETECLIENT_REMOVED");
        pWifiControllerMachine->SendMessage(CMD_CONCRETECLIENT_REMOVED, id);
    }
}

void WifiTogglerManager::DealMultiStaStartFailure(int id)
{
    if (pWifiControllerMachine) {
        pWifiControllerMachine->SendMessage(CMD_STA_START_FAILURE, id);
    }
}

void WifiTogglerManager::DealMultiStaStop(int id)
{
    if (pWifiControllerMachine) {
        pWifiControllerMachine->SendMessage(CMD_MULTI_STA_STOPPED, id);
    }
}

void WifiTogglerManager::ForceStopWifi()
{
    if (pWifiControllerMachine) {
        pWifiControllerMachine->ShutdownWifi(false);
    }
}

#ifdef HDI_CHIP_INTERFACE_SUPPORT
void WifiTogglerManager::DealChipServiceDied(void)
{
    if (pWifiControllerMachine) {
        pWifiControllerMachine->ShutdownWifi(true);
    }
}
#endif

#ifndef OHOS_ARCH_LITE
ErrCode WifiTogglerManager::SatelliteToggled(int state)
{
    if (state == WIFI_MODE_RSMC_START) {
        WIFI_LOGI("Satellite state start.");
        SetSatelliteStartState(true);
        WifiManager::GetInstance().GetWifiStaManager()->StartSatelliteTimer();
    } else if (state == WIFI_MODE_RSMC_STOP) {
        WIFI_LOGI("Satellite state stop.");
        SetSatelliteStartState(false);
        WifiManager::GetInstance().GetWifiStaManager()->StopSatelliteTimer();
    } else if (state == WIFI_MODE_RSMC_CHECK) {
        WIFI_LOGI("Satellite state check.");
        CheckSatelliteState();
    } else {
        WIFI_LOGI("unknow state, not handle.");
    }
    return WIFI_OPT_SUCCESS;
}

void WifiTogglerManager::SetSatelliteStartState(bool state)
{
    mIsSatelliteStart = state;
}

void WifiTogglerManager::CheckSatelliteState()
{
    WIFI_LOGI("Enter CheckSatelliteState");
    std::string RSMC_CHECK_WHITE_LIST[] = {"wlan0", "wlan1", "wlan2", "p2p0", "chba0"};
    bool isUp = false;
    for (auto nif : RSMC_CHECK_WHITE_LIST) {
        if (IsInterfaceUp(nif)) {
            isUp = true;
        }
    }
    if (isUp) {
        pWifiControllerMachine->ShutdownWifi();
    }
}

bool WifiTogglerManager::IsInterfaceUp(std::string &iface)
{
    auto samgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (samgr == nullptr) {
        LOGE("GetSystemAbilityManager failed!");
        return false;
    }
    auto remote = samgr->GetSystemAbility(COMM_NETSYS_NATIVE_SYS_ABILITY_ID);
    if (remote == nullptr) {
        LOGE("GetSystemAbility failed!");
        return false;
    }
    OHOS::sptr<OHOS::NetsysNative::INetsysService> netsysService = iface_cast<NetsysNative::INetsysService>(remote);
    if (netsysService == nullptr) {
        LOGE("NetdService is nullptr!");
        return false;
    }
    OHOS::nmd::InterfaceConfigurationParcel config;
    config.ifName = iface;
    if (netsysService->GetInterfaceConfig(config) != ERR_NONE) {
        WIFI_LOGE("ret is not ERR_NONE, return false.");
        return false;
    }
    if (std::find(config.flags.begin(), config.flags.end(), IFACE_LINK_UP) != config.flags.end() ||
        std::find(config.flags.begin(), config.flags.end(), IFACE_RUNNING) != config.flags.end()) {
        return true;
    }
    return false;
}

bool WifiTogglerManager::IsSatelliteStateStart()
{
    return mIsSatelliteStart;
}

void WifiTogglerManager::RetryOpenP2p(void)
{
    if (pWifiControllerMachine) {
        pWifiControllerMachine->SendMessage(CMD_P2P_RETRY_OPEN);
    }
}
#endif
}  // namespace Wifi
}  // namespace OHOS