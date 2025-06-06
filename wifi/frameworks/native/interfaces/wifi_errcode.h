/*
 * Copyright (C) 2021 Huawei Device Co., Ltd.
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

#ifndef OHOS_WIFI_ERRCODE_H
#define OHOS_WIFI_ERRCODE_H

namespace OHOS {
namespace Wifi {
/* Wifi errcode defines */
enum ErrCode {
    WIFI_OPT_SUCCESS = 0,             /* successfully */
    WIFI_OPT_FAILED,                  /* failed */
    WIFI_OPT_NOT_SUPPORTED,           /* not supported */
    WIFI_OPT_INVALID_PARAM,           /* invalid params @deprecated, use WIFI_OPT_INVALID_PARAM_NEW instead */
    WIFI_OPT_FORBID_AIRPLANE,         /* forbid when current airplane opened */
    WIFI_OPT_FORBID_POWSAVING,        /* forbid when current powersaving opened */
    WIFI_OPT_PERMISSION_DENIED,       /* permission denied */
    WIFI_OPT_OPEN_FAIL_WHEN_CLOSING,  /* open failed when current is closing */
    WIFI_OPT_OPEN_SUCC_WHEN_OPENED,   /* open success when current has been opened */
    WIFI_OPT_CLOSE_FAIL_WHEN_OPENING, /* close failed when current is opening */
    WIFI_OPT_CLOSE_SUCC_WHEN_CLOSED,  /* close success when current has been closed */
    WIFI_OPT_STA_NOT_OPENED,          /* sta service not opened */
    WIFI_OPT_SCAN_NOT_OPENED,         /* scan service not opened */
    WIFI_OPT_AP_NOT_OPENED,           /* ap service not opened */
    WIFI_OPT_INVALID_CONFIG,          /* invalid config */
    WIFI_OPT_P2P_NOT_OPENED,          /* p2p service not opened */
    WIFI_OPT_P2P_MAC_NOT_FOUND,
    WIFI_OPT_P2P_ERR_MAC_FORMAT,
    WIFI_OPT_P2P_ERR_INTENT,
    WIFI_OPT_P2P_ERR_SIZE_NW_NAME,
    WIFI_OPT_MOVING_FREEZE_CTRL,      /* moving freeze scanning control */
    WIFI_OPT_NON_SYSTEMAPP,           /* not system app denied */
    WIFI_OPT_SCAN_NEXT_PERIOD,
    WIFI_OPT_GET_ENHANCE_SVC_FAILED,  /* get enhance service failed */
    WIFI_OPT_STA_AND_P2P_MAC_SAME,    /* sta and p2p mac is same */
    WIFI_OPT_ENTERPRISE_DENIED = 203, /* mdm forbidden */
    WIFI_OPT_MDM_BLOCKLIST_OUT_MAX_NUM,  /* mdm blocklist over max num fail */
    WIFI_OPT_MDM_WHITELIST_OUT_MAX_NUM,  /* mdm whitelist over max num fail */
    WIFI_OPT_MDM_OUT_MAX_NUM,  /* mdm block and white list totail size over max num fail */
    WIFI_OPT_USER_DOES_NOT_RESPOND,   /* user does not respond */
    WIFI_OPT_USER_REFUSE_THE_ACTION,  /* user refuse the action */
    WIFI_OPT_INVALID_PARAM_NEW,       /* invalid params since API-18 */
};
}  // namespace Wifi
}  // namespace OHOS
#endif
