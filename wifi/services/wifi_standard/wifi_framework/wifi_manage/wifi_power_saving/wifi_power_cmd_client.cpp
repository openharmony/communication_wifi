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
#include <net/if.h>
#include <net/route.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <cerrno>
#include "wifi_logger.h"


namespace OHOS {
namespace Wifi {
DEFINE_WIFILOG_LABEL("WifiPowerCmdClient");

static const int MAX_PRIV_CMD_SIZE = 4096;
static const int TINY_BUFF_SIZE = 64;

static const char RX_LISTEN_ON = 'Y';
static const char RX_LISTEN_OFF = 'N';
static const auto CMD_SET_RX_LISTEN_ON = "SET_RX_LISTEN_PS_SWITCH 1";
static const auto CMD_SET_RX_LISTEN_OFF = "SET_RX_LISTEN_PS_SWITCH 0";


WifiPowerCmdClient &Wifi::WifiPowerCmdClient::GetInstance()
{
    static WifiPowerCmdClient instance;
    return instance;
}
int Wifi::WifiPowerCmdClient::SendCmdToDriver(const char *iface, int commandId, const char *paramBuf,
    unsigned int paramSize) const
{
    int ret = -1;
    if (iface == nullptr || paramBuf == nullptr) {
        WIFI_LOGE("%{public}s invalid params", __FUNCTION__);
        return ret;
    }
    if (commandId == CMD_SET_RX_LISTEN_POWER_SAVING_SWITCH) {
        ret = SetRxListen(paramBuf);
    }
    return ret;
}
int Wifi::WifiPowerCmdClient::SendCommandToDriverByInterfaceName(char *cmdBuf, int cmdSize,
    const char *interfaceName) const
{
    if (cmdBuf > MAX_PRIV_CMD_SIZE) {
        WIFI_LOGE("%{public}s cmdSize too large", __FUNCTION__);
        return ret;
    }
    if (cmdBuf == nullptr) {
        WIFI_LOGE("%{public}s cmdBuf is null", __FUNCTION__);
        return ret;
    }
    struct ifreq ifr;
    int ret = -1;
    WifiPrivCmd privCmd = { 0 };
    unint8_t buf[MAX_PRIV_CMD_SIZE] = {0};
    (void)memset_s(&ifr, sizeof(ifr), 0, sizeof(ifr));
    if (memcpy_s(buf, MAX_PRIV_CMD_SIZE, cmdBuf, cmdSize) != EOK) {
        WIFI_LOGE("%{public}s memcpy_s privCmd buf error", __FUNCTION__);
        return ret;
    }
    privCmd.buf = buf;
    privCmd.size = sizeof(buf);
    privCmd.len = cmdSize;
    ifr.ifr_data = reinterpret_cast<char *>(&privCmd);
    if (strcpy_s(ifr.ifr_name, IFNAMSIZ, interfaceName) != EOK) {
        WIFI_LOGE("%{public}s strcpy_s ifr fail", __FUNCTION__);
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
        return ret;
    }
    (void)memset_s(cmdBuf, cmdSize, 0, cmdSize);
    if (memcpy_s(cmdBuf, cmdSize, privCmd.buf, cmdSize - 1) != 0) {
        WIFI_LOGE("%{public}s memcpy_s cmd fail", __FUNCTION__);
    }
    close(sock);
    return ret;
}

int Wifi::WifiPowerCmdClient::SetRxListen(const char *paramBuf) const
{
    WIFI_LOGD("%{public}s enter", __FUNCTION__);
    int ret = -1;
    size_t cmdLen;
    char cmdBuf[TINY_BUFF_SIZE] = {0};
    if (*paramBuf == RX_LISTEN_ON) {
        cmdLen = strlen(CMD_SET_RX_LISTEN_ON);
        if (memcpy_s(cmdBuf, TINY_BUFF_SIZE - 1, CMD_SET_RX_LISTEN_ON, cmdLen) != EOK) {
            WIFI_LOGE("%{public}s memcpy_s cmdBuf fail", __FUNCTION__);
            return ret;
        }
    } else if (*paramBuf == RX_LISTEN_OFF) {
        cmdLen = strlen(CMD_SET_RX_LISTEN_OFF);
        if (memcpy_s(cmdBuf, TINY_BUFF_SIZE - 1, CMD_SET_RX_LISTEN_OFF, cmdLen) != EOK) {
            WIFI_LOGE("%{public}s memcpy_s cmdBuf fail", __FUNCTION__);
            return ret;
        }
    } else {
        WIFI_LOGE("%{public}s invalid param", __FUNCTION__);
        return ret;
    }
    ret = SendCommandToDriverByInterfaceName(cmdBuf, TINY_BUFF_SIZE, WiFI_IFNAME);
    return ret;
}
} // namespace Wifi
} // namespace OHOS