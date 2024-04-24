/*
 * Copyright (C) 2021-2022 Huawei Device Co., Ltd.
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

#include "speed_limit_configs_writer.h"
#include "wifi_common_util.h"
#include <fcntl.h>
#include <arpa/inet.h>
#include <unistd.h>
#include "wifi_logger.h"

namespace OHOS {
namespace Wifi {
DEFINE_WIFILOG_LABEL("WifiSpeedLimitConfigsWriter");

const int MAX_ARRAY_LENGTH = 256;
static const char * const AWARE_CTRL_FILENAME = "/proc/net/aware/aware_ctrl";
static const char * const FG_UID_PATH = "/proc/net/aware/fg_uids";
static const char * const BG_UID_PATH = "/proc/net/aware/bg_uids";
static const char * const BG_PID_PATH = "/proc/net/aware/bg_pids";

ErrCode SetBgLimitMode(int mode)
{
    int fd = open(AWARE_CTRL_FILENAME, O_RDWR);
    if (fd < 0) {
        WIFI_LOGE("open aware ctrl file failed, errno = %{public}d.", errno);
        return WIFI_OPT_FAILED;
    }

    char awareCtrlStr[MAX_ARRAY_LENGTH] = {0};
    int ret = snprintf_s(awareCtrlStr, sizeof(awareCtrlStr), MAX_ARRAY_LENGTH - 1, "1:%d", mode);
    if (ret == -1) {
        WIFI_LOGE("SetBgLimitMode snprintf_s failed.");
        close(fd);
        return WIFI_OPT_FAILED;
    }

    int len = strlen(awareCtrlStr);
    if (write(fd, awareCtrlStr, len) != len) {
        WIFI_LOGE("write awareCtrlStr failed, errno = %{public}d.", errno);
        close(fd);
        return WIFI_OPT_FAILED;
    }
    close(fd);
    return WIFI_OPT_SUCCESS;
}

void SetBgLimitIdList(std::vector<int> idList, int type)
{
    switch (type) {
        case SET_BG_UID:
            SetUidPids(BG_UID_PATH, idList.data(), static_cast<int>(idList.size()));
            break;
        case SET_BG_PID:
            SetUidPids(BG_PID_PATH, idList.data(), static_cast<int>(idList.size()));
            break;
        case SET_FG_UID:
            SetUidPids(FG_UID_PATH, idList.data(), static_cast<int>(idList.size()));
            break;
        default:
            WIFI_LOGD("Unknow type, not handle.");
            break;
    }
}

void SetUidPids(const char *filePath, const int *idArray, int size)
{
    int ret;
    char tempStr[MAX_ARRAY_LENGTH];
    char idStr[MAX_ARRAY_LENGTH];

    for (int i = 0; i < size; ++i) {
        if (i == 0) {
            ret = snprintf_s(tempStr, sizeof(tempStr), MAX_ARRAY_LENGTH - 1, "%d", idArray[i]);
        } else {
            ret = snprintf_s(tempStr, sizeof(tempStr), MAX_ARRAY_LENGTH - 1, "%s;%d", idStr, idArray[i]);
        }
        if (ret == -1) {
            WIFI_LOGE("SetUidPids failed.");
            break;
        }

        if (strcpy_s(idStr, sizeof(idStr), tempStr) != 0) {
            break;
        }
    }

    int len = strlen(idStr);
    if (len <= 0) {
        return;
    }

    int fd = open(filePath, O_RDWR);
    if (fd < 0) {
        WIFI_LOGE("open file failed, errno = %{public}d.", errno);
        return;
    }

    if (write(fd, idStr, len) != len) {
        WIFI_LOGE("write idStr failed, errno = %{public}d.", errno);
    }
    close(fd);
    return;
}
} // namespace Wifi
} // namespace OHOS