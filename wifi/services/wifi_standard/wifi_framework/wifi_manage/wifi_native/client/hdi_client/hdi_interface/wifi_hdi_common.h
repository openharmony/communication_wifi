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

#ifndef OHOS_WIFI_HDI_COMMON_H
#define OHOS_WIFI_HDI_COMMON_H

#include "wifi_hdi_define.h"
#include "wifi_hdi_struct.h"

typedef unsigned char u8;

#ifdef __cplusplus
extern "C" {
#endif

#ifndef HDI_BIT
#define HDI_BIT(x) (1U << (x))
#endif

#define MAC_STRING_SIZE 17
#define HDI_CHECK_ELEMENT(e, input, len)    \
    for ((e) = (const struct HdiElem *) (input);    \
        (const uint8_t *) (input) + (len) - (const uint8_t *)(e) >=    \
        (int) sizeof(*(e)) &&    \
        (const uint8_t *) (input) + (len) - (const uint8_t *)(e) >=    \
        (int) sizeof(*(e)) + (e)->datalen;    \
        (e) = (const struct HdiElem *) ((e)->data + (e)->datalen))

#define HDI_CHECK_ELEMENT_BY_ID(e, inputid, input, len)    \
    HDI_CHECK_ELEMENT(e, input, len)    \
        if ((e)->id == (inputid))

#define HDI_CHECK_ELEMENT_BY_EXTID(e, extid, input, len)		\
    HDI_CHECK_ELEMENT(e, input, len)    \
        if ((e)->id == HDI_EID_EXTENSION &&    \
            (e)->datalen > 0 &&	    \
            (e)->data[0] == (extid))

#define HDI_HANDLE_CIPHER_INFO(ret, start, end, delim, format) \
        ret = HdiTxtPrintf(pos, (end) - (pos), format, \
            pos == (start) ? "" : (delim)); \
        if (HdiCheckError((end) - pos, ret)) \
            return -1; \
        pos += ret; \

#define HDI_HANDLE_CIPHER_POS_INFO(flag, ret, pos, end, delim, format) \
        if (flag) { \
            ret = HdiTxtPrintf(pos, (end) - (pos), format, \
                pos == (start) ? "" : (delim)); \
            if (HdiCheckError((end) - (pos), ret)) \
                return pos; \
            pos += ret; \
        } \

static inline int HdiCheckCompleted(const struct HdiElem *e,
    const uint8_t *data, size_t datalen)
{
    return (const uint8_t *)e == data + datalen;
}

#define HDI_GET_RSN_ID(a) HdiGetBe32((const uint8_t *) (a))

#define HDI_BIT_MULTI(a, b, c, d) \
    ((((uint32_t) (a)) << 24) | (((uint32_t) (b)) << 16) | (((uint32_t) (c)) << 8) |    \
    (uint32_t) (d))

const uint8_t* HdiGetIe(const uint8_t *ies, size_t len, uint8_t eid);

const uint8_t* HdiBssGetIe(const uint8_t *ies, size_t len, uint8_t ie);

const uint8_t* HdiBssGetVendorIe(const uint8_t *ies, size_t len, uint32_t vendorType);

const uint8_t* HdiBssGetVendorBeacon(const uint8_t *ies, size_t len, size_t beaconIeLen, uint32_t vendorType);

static inline int HdiCheckError(size_t size, int res)
{
    return res < 0 || (unsigned int) res >= size;
}

static inline uint32_t HdiGetBe24(const uint8_t *a)
{
    return (a[HDI_POS_ZERO] << HDI_MOVE_SIXTEEN) | (a[HDI_POS_FIRST] << HDI_MOVE_EIGHT) | a[HDI_POS_SECOND];
}

static inline uint32_t HdiGetBe32(const uint8_t *a)
{
    return ((uint32_t) a[HDI_POS_ZERO] << HDI_MOVE_TF) | (a[HDI_POS_FIRST] << HDI_MOVE_SIXTEEN) |
        (a[HDI_POS_SECOND] << HDI_MOVE_EIGHT) | a[HDI_POS_THIRD];
}

static inline uint16_t HdiGetBe16(const uint8_t *a)
{
    return (a[HDI_POS_FIRST] << HDI_MOVE_EIGHT) | a[HDI_POS_ZERO];
}

size_t PrintfDecode(u8 *buf, size_t maxlen, const char *str);

int HdiTxtPrintf(char *str, size_t size, const char *format, ...);

const uint8_t* HdiBssGetIeExt(const uint8_t *ies, size_t len, uint8_t ext);

void HdiBufEncode(char *txt, size_t maxlen, const uint8_t *data, size_t len);

const char* HdiSSid2Txt(const uint8_t *ssid, size_t ssidLen);

char* HdiGetIeTxt(char *pos, char *end, const char *proto,
    const uint8_t *ie, size_t ieLen);

int8_t IsValidHexCharAndConvert(char c);

int CheckMacIsValid(const char *macStr);

void StrSafeCopy(char *dst, unsigned len, const char *src);

#ifdef __cplusplus
}
#endif
#endif