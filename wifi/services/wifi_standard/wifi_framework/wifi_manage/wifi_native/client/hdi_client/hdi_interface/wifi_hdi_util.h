/*
 * Copyright (C) 2023 Huawei Device Co., Ltd.
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

#ifndef OHOS_WIFI_HDI_UTIL_H
#define OHOS_WIFI_HDI_UTIL_H

#include "wifi_hdi_struct.h"
#include "wifi_common_def.h"
#include "wifi_hdi_common.h"

#ifdef __cplusplus
extern "C" {
#endif

int Get80211ElemsFromIE(const uint8_t *start, size_t len, struct HdiElems *elems,
    int show);

int GetScanResultText(const struct WifiScanResultExt *scanResults,
    struct HdiElems *elems, char* buff, int buffLen);

int DelScanInfoLine(ScanInfo *pcmd, char *srcBuf, int length);

/**
 * @Description Convert [a,b,c,d,e,f] mac address to string type [xx:xx:xx:xx:xx:xx]
 *
 * @param srcMac - srcMac address
 * @param srcMacSize - srcMacSize size, must be equal to 6, or error
 * @param DesMacStr - output mac string, type: [xx:xx:xx:xx:xx:xx]
 * @param strLen - mac string length, must be bigger than 17
 * @return int - return result. 0 is Failed ,1 is Success
 */
int ConvertMacArr2String(const unsigned char *srcMac, int srcMacSize, char *destMacStr, int strLen);

/**
 * @Description Get ie from scan result
 *
 * @param scanInfo - output scan info
 * @param start - ie point
 * @param len - ie length
 */
void GetScanResultInfoElem(ScanInfo *scanInfo, const uint8_t *start, size_t len);

bool RouterSupportHiLinkByWifiInfo(const uint8_t *start, size_t len);

#ifdef __cplusplus
}
#endif
#endif