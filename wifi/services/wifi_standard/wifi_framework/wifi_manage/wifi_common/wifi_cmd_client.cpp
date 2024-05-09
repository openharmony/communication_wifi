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
#include "wifi_cmd_client.h"
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
DEFINE_WIFILOG_LABEL("WifiCmdClient");

static const int MAX_PRIV_CMD_SIZE = 4096;
static const int MSS_BLA_LIST_MAX_PARAMSIZE = 129;
static const int MSS_BLA_LIST_BUFSIZE = 192;
static const int TINY_BUFF_SIZE = 64;

static const auto RX_LISTEN_ON = "Y";
static const auto RX_LISTEN_OFF = "N";
static const auto CMD_SET_RX_LISTEN_ON = "SET_RX_LISTEN_PS_SWITCH 1";
static const auto CMD_SET_RX_LISTEN_OFF = "SET_RX_LISTEN_PS_SWITCH 0";
static const auto CMD_SET_AX_BLA_LIST = "SET_AX_BLACKLIST";
static const auto CMD_SET_AX_CLOSE_HTC = "SET_AX_CLOSE_HTC";

#define MSS_SOFTAP_MAX_IFNAMESIZE 5
#define MSS_SOFTAP_CMDSIZE 30

WifiCmdClient &WifiCmdClient::GetInstance()
{
    static WifiCmdClient instance;
    return instance;
}
int WifiCmdClient::SendCmdToDriver(const std::string &ifName, int commandId, const std::string &param) const
{
    int ret = -1;
    if (ifName.empty() || param.empty() || (param.size() + 1) > MAX_PRIV_CMD_SIZE) {
        WIFI_LOGE("%{public}s invalid input params", __FUNCTION__);
        return ret;
    }
    if (commandId == CMD_SET_RX_LISTEN_POWER_SAVING_SWITCH) {
        ret = SetRxListen(ifName, param);
    } else if (commandId == CMD_SET_SOFTAP_2G_MSS) {
        ret = Set2gSoftapMss(ifName, param);
    } else if (commandId == CMD_AX_BLA_LIST) {
        ret = SetAxBlaList(ifName, param);
    } else if (commandId == CMD_AX_SELFCURE) {
        ret = AxSelfcure(ifName, param);
    } else {
        WIFI_LOGD("%{public}s not supported command", __FUNCTION__);
    }
    return ret;
}
int WifiCmdClient::SendCommandToDriverByInterfaceName(const std::string &ifName,
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
    if (strncmp(cmdParm.c_str(), CMD_SET_AX_BLA_LIST, strlen(CMD_SET_AX_BLA_LIST)) == 0) {
        WIFI_LOGI("%{public}s send wifi6 bla list", __FUNCTION__);
        privCmd.size = static_cast<int>(cmdParm.size());
    } else {
        privCmd.size = sizeof(buf);
    }
    privCmd.len = static_cast<int>(cmdParm.size());
    ifr.ifr_data = reinterpret_cast<char *>(&privCmd);
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

int WifiCmdClient::SetRxListen(const std::string &ifName, const std::string &param) const
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

int WifiCmdClient::Set2gSoftapMss(const std::string &ifName, const std::string &param) const
{
    if (ifName.empty() || ifName.size() > MSS_SOFTAP_MAX_IFNAMESIZE) {
        WIFI_LOGE("%{public}s invalid input param", __FUNCTION__);
        return -1;
    }
    if ((ifName.size() + param.size()) > MSS_SOFTAP_CMDSIZE) {
        WIFI_LOGE("%{public}s ifNameLen + cmdLen overflow", __FUNCTION__);
        return -1;
    }
    return SendCommandToDriverByInterfaceName(ifName, param);
}

int WifiCmdClient::SetAxBlaList(const std::string &ifName, const std::string &param) const
{
    WIFI_LOGD("%{public}s enter", __FUNCTION__);
    if (param.size() > MSS_BLA_LIST_MAX_PARAMSIZE ||
        param.size() + strlen(CMD_SET_AX_BLA_LIST) > MSS_BLA_LIST_BUFSIZE) {
        WIFI_LOGE("%{public}s invalid input param", __FUNCTION__);
        return -1;
    }
    std::string cmdParm = CMD_SET_AX_BLA_LIST;
    cmdParm.append(" ");
    cmdParm.append(param);
    return SendCommandToDriverByInterfaceName(ifName, cmdParm);
}

int WifiCmdClient::AxSelfcure(const std::string &ifName, const std::string &param) const
{
    WIFI_LOGD("%{public}s enter", __FUNCTION__);
    if (param.empty() || param.size() == 0 ||
        param.size() + strlen(CMD_SET_AX_CLOSE_HTC) > TINY_BUFF_SIZE) {
        WIFI_LOGE("%{public}s invalid input param", __FUNCTION__);
        return -1;
    }
    std::string cmdParm = CMD_SET_AX_CLOSE_HTC;
    cmdParm.append(" ");
    cmdParm.append(param);
    return SendCommandToDriverByInterfaceName(ifName, cmdParm);
}

} // namespace Wifi
} // namespace OHOS