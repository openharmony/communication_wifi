/*
 * Copyright (C) 2022 Huawei Device Co., Ltd.
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

#ifndef OHOS_WIFI_COMMON_DEF_H
#define OHOS_WIFI_COMMON_DEF_H

#ifdef __cplusplus
extern "C" {
#endif

#ifdef OHOS_EUPDATER
#define CONFIG_ROOR_DIR "/tmp/service/el1/public/wifi"
#define P2P_CONFIG_DIR  "/tmp/service/el1/public/wifi/wpa_supplicant/"
#define P2P_WPA_CONFIG_FILE "/tmp/service/el1/public/wifi/wpa_supplicant/p2p_supplicant.conf"
#else
#define CONFIG_ROOR_DIR "/data/service/el1/public/wifi"
#define P2P_CONFIG_DIR  "/data/service/el1/public/wifi/wpa_supplicant/"
#define P2P_WPA_CONFIG_FILE "/data/service/el1/public/wifi/wpa_supplicant/p2p_supplicant.conf"
#endif // OHOS_EUPDATER

#define WIFI_MANAGGER_PID_NAME "wifi_mgr_pid"
#define DIR_MAX_LENGTH          256
#define PID_MAX_LENGTH          32
#define DEFAULT_UMASK_VALUE     027
#define MAX_READ_EVENT_SIZE     512

#ifndef MAC2STR
#define MAC2STR(a) (a)[0], (a)[1], (a)[2], (a)[3], (a)[4], (a)[5]
#define MACSTR "%02x:%02x:%02x:%02x:%02x:%02x"
#endif

#ifdef __cplusplus
}
#endif

#endif
