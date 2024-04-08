/*
 * Copyright (C) 2023-2023 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "wifi_rx_listen_arbitration.h"
#include "wifi_logger.h"
#include "wifi_cmd_client.h"
#include "wifi_app_parser.h"

namespace OHOS {
namespace Wifi {
DEFINE_WIFILOG_LABEL("WifiRxListen");

static const int SHIFT_BIT_UTIL = 1;
static const int GAME_APP_SHIFT = 0;

static const auto ENABLE_RX_LISTEN = "Y";
static const auto DISABLE_RX_LISTEN = "N";

RxListenArbitration::RxListenArbitration()
{
    WIFI_LOGI("%{public}s enter", __FUNCTION__);
}

RxListenArbitration::~RxListenArbitration()
{
    WIFI_LOGI("%{public}s enter", __FUNCTION__);
}

RxListenArbitration &RxListenArbitration::GetInstance()
{
    static RxListenArbitration instance;
    return instance;
}

void RxListenArbitration::OnForegroundAppChanged(const AppExecFwk::AppStateData &appStateData)
{
    std::unique_lock<std::mutex> lock(m_condMutex);
    if (appStateData.state == static_cast<int>(AppExecFwk::ApplicationState::APP_STATE_FOREGROUND) &&
        appStateData.isFocused) {
        WIFI_LOGD("%{public}s enter rx_listen arbitration, app name: %{public}s", __FUNCTION__,
            appStateData.bundleName.c_str());
        if (AppParser::GetInstance().IsLowLatencyApp(appStateData.bundleName)) {
            // game scene: set m_arbitrationCond to zero to enable rx_listen
            m_arbitrationCond = m_arbitrationCond | (SHIFT_BIT_UTIL << GAME_APP_SHIFT);
        } else {
            // not game scene: set m_arbitrationCond to one to disable rx_listen
            m_arbitrationCond = m_arbitrationCond & (~(SHIFT_BIT_UTIL << GAME_APP_SHIFT));
        }
        CheckRxListenSwitch();
    }
}

void RxListenArbitration::CheckRxListenSwitch()
{
    std::string param;
    std::string ifName = "wlan0";
    if ((m_arbitrationCond == 0) && !m_isRxListenOn) {
        param = ENABLE_RX_LISTEN;
        if (WifiCmdClient::GetInstance().SendCmdToDriver(ifName, CMD_SET_RX_LISTEN_POWER_SAVING_SWITCH,
            param) != 0) {
            WIFI_LOGE("%{public}s enable rx_listen fail", __FUNCTION__);
            return;
        }
        m_isRxListenOn = true;
        WIFI_LOGD("%{public}s enable rx_listen successful", __FUNCTION__);
    } else if ((m_arbitrationCond != 0) && m_isRxListenOn) {
        param = DISABLE_RX_LISTEN;
        if (WifiCmdClient::GetInstance().SendCmdToDriver(ifName, CMD_SET_RX_LISTEN_POWER_SAVING_SWITCH,
            param) != 0) {
            WIFI_LOGE("%{public}s disable rx_listen fail", __FUNCTION__);
            return;
        }
        m_isRxListenOn = false;
        WIFI_LOGD("%{public}s disable rx_listen successful", __FUNCTION__);
    } else {
        WIFI_LOGD("%{public}s no switch", __FUNCTION__);
    }
}
} // namespace Wifi
} // namespace OHOS