#include "wifi_power_cmd_client.h"
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
#include "wifi_power_cmd_client.h"
#include <linux/sockios.h>
#include <net/if.h>
#include <net/route.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <cerrno>
#include <unistd.h>
#include "securec.h"
#include "wifi_logger.h"

namespace OHOS {
namespace Wifi {
DEFINE_WIFILOG_LABEL("WifiPowerCmdClient");

static const int MAX_PRIV_CMD_SIZE = 4096;
static const int TINY_BUFF_SIZE = 64;

static const auto RX_LISTEN_ON = "Y";
static const auto RX_LISTEN_OFF = "N";
static const auto CMD_SET_RX_LISTEN_ON = "SET_RX_LISTEN_PS_SWITCH 1";
static const auto CMD_SET_RX_LISTEN_OFF = "SET_RX_LISTEN_PS_SWITCH 0";

WifiPowerCmdClient &Wifi::WifiPowerCmdClient::GetInstance()
{
    static WifiPowerCmdClient instance;
    return instance;
}
int Wifi::WifiPowerCmdClient::SendCmdToDriver(const std::string &ifName, int commandId, const std::string &param) const
{
    int ret = -1;
    if (ifName.empty() || param.empty() || (param.size() + 1) > MAX_PRIV_CMD_SIZE) {
        WIFI_LOGE("%{public}s invalid input params", __FUNCTION__);
        return ret;
    }
    if (commandId == CMD_SET_RX_LISTEN_POWER_SAVING_SWITCH) {
        ret = SetRxListen(ifName, param);
    } else {
        WIFI_LOGD("%{public}s not supported command", __FUNCTION__);
    }
    return ret;
}
int Wifi::WifiPowerCmdClient::SendCommandToDriverByInterfaceName(const std::string &ifName,
    const std::string &cmdParm) const
{
    int ret = -1;
    if (ifName.size() + 1 > IFNAMSIZ) {
        WIFI_LOGE("%{public}s ifName size too large", __FUNCTION__);
        return ret;
    }
    if (ifName.size() + 1 > MAX_PRIV_CMD_SIZE) {
        WIFI_LOGE("%{public}s cmdParm size too large", __FUNCTION__);
        return ret;
    }
    struct ifreq ifr;
    WifiPrivCmd privCmd = { 0 };
    uint8_t buf[MAX_PRIV_CMD_SIZE] = {0};
    (void)memset_s(&ifr, sizeof(ifr), 0, sizeof(ifr));
    if (memcpy_s(buf, MAX_PRIV_CMD_SIZE, cmdParm.c_str(), cmdParm.size() + 1) != EOK) {
        WIFI_LOGE("%{public}s memcpy_s privCmd buf error", __FUNCTION__);
        return ret;
    }
    privCmd.buf = buf;
    privCmd.size = sizeof(buf);
    privCmd.len = static_cast<int>(cmdParm.size());
    ifr.ifr_data = reinterpret_cast<void *>(&privCmd);
    if (memcpy_s(ifr.ifr_name, IFNAMSIZ, ifName.c_str(), ifName.size() + 1) != EOK) {
        WIFI_LOGE("%{public}s memcpy_s ifr fail", __FUNCTION__);
        return ret;
    }
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        WIFI_LOGE("%{public}s socked fail", __FUNCTION__);
        return ret;
    }
    ret = ioctl(sock, SIOCDEVPRIVATE + 1, &ifr);
    if (ret < 0) {
        WIFI_LOGE("%{public}s ioctl failed, error is: %{public}d.", __FUNCTION__, errno);
    }
    close(sock);
    return ret;
}

int Wifi::WifiPowerCmdClient::SetRxListen(const std::string &ifName, const std::string &param) const
{
    WIFI_LOGD("%{public}s enter", __FUNCTION__);
    std::string cmdParam;
    if (param.compare(RX_LISTEN_ON) == 0) {
        cmdParam = CMD_SET_RX_LISTEN_ON;
        WIFI_LOGD("%{public}s enable rx listen", __FUNCTION__);
    } else if (param.compare(RX_LISTEN_OFF) == 0) {
        cmdParam = CMD_SET_RX_LISTEN_OFF;
        WIFI_LOGD("%{public}s disable rx listen", __FUNCTION__);
    } else {
        WIFI_LOGE("%{public}s invalid param", __FUNCTION__);
        return -1;
    }
    return SendCommandToDriverByInterfaceName(ifName, cmdParam);
}
} // namespace Wifi
} // namespace OHOS