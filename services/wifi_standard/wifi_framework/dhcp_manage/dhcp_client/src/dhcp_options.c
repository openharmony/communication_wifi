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
#include "dhcp_options.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "securec.h"

#undef LOG_TAG
#define LOG_TAG "WifiDhcpOptions"


static bool CheckOptSoverloaded(const struct DhcpPacket *packet, int code, int maxLen, int *over, int *index)
{
    if (packet == NULL) {
        LOGE("CheckOptSoverloaded failed, packet == NULL!\n");
        return false;
    }

    const uint8_t *pOption = packet->options;
    if (*index + DHCP_OPT_LEN_INDEX + pOption[*index + DHCP_OPT_LEN_INDEX] >= maxLen) {
        LOGW("CheckOptSoverloaded code:%{public}d,*index:%{public}d more than max bytes:%{public}d!\n",
            code, *index, maxLen);
        return false;
    }
    *over = pOption[*index + DHCP_OPT_DATA_INDEX + DHCP_OPT_CODE_INDEX];
    *index += pOption[DHCP_OPT_LEN_INDEX] + DHCP_OPT_CODE_BYTES + DHCP_OPT_LEN_BYTES;
    return true;
}

static int GetDhcpOptionData(const struct DhcpPacket *packet, int code, int index, int maxLen)
{
    if (packet == NULL) {
        LOGE("GetDhcpOptionData failed, packet == NULL!\n");
        return DHCP_OPT_FAILED;
    }

    if (index >= maxLen) {
        LOGW("GetDhcpOptionData code:%{public}d,index:%{public}d more than max bytes:%{public}d!\n",
            code, index, maxLen);
        return DHCP_OPT_FAILED;
    }

    const uint8_t *pOption = packet->options;
    if (pOption[index + DHCP_OPT_CODE_INDEX] != code) {
        return DHCP_OPT_NONE;
    }

    if (index + DHCP_OPT_LEN_INDEX + pOption[index + DHCP_OPT_LEN_INDEX] >= maxLen) {
        LOGW("GetDhcpOptionData failed, options data too long, code:%{public}d,index:%{public}d!\n", code, index);
        return DHCP_OPT_FAILED;
    }

    return DHCP_OPT_SUCCESS;
}

static uint8_t GetDhcpOptionCodeType(const uint8_t code)
{
    if ((code <= DHO_PAD) || (code >= DHO_END)) {
        LOGE("GetDhcpOptionCodeType error, code:%{public}d is error!\n", code);
        return DHCP_OPTION_DATA_INVALID;
    }

    uint8_t nDataType = DHCP_OPTION_DATA_INVALID;
    switch (code) {
        case DHO_MESSAGETYPE:
            nDataType = DHCP_OPTION_DATA_U8;
            break;
        case DHO_MTU:
            nDataType = DHCP_OPTION_DATA_U16;
            break;
        case DHO_LEASETIME:
            nDataType = DHCP_OPTION_DATA_U32;
            break;
        case DHO_SUBNETMASK:
        case DHO_BROADCAST:
        case DHO_IPADDRESS:
        case DHO_SERVERID:
            nDataType = DHCP_OPTION_DATA_IP;
            break;
        case DHO_ROUTER:
        case DHO_DNSSERVER:
        case DHO_NTPSERVER:
            nDataType = DHCP_OPTION_DATA_IP_LIST;
            break;
        case DHO_HOSTNAME:
        case DHO_DNSDOMAIN:
        case DHO_MESSAGE:
            nDataType = DHCP_OPTION_DATA_IP_STRING;
            break;
        default:
            LOGE("GetDhcpOptionCodeType failed, code:%{public}d is invalid!\n", code);
            break;
    }

    return nDataType;
}

uint8_t GetDhcpOptionDataLen(const uint8_t code)
{
    uint8_t nDataType = GetDhcpOptionCodeType(code);
    if (nDataType == DHCP_OPTION_DATA_INVALID) {
        LOGE("GetDhcpOptionDataLen code:%{public}d error, GetDhcpOptionCodeType invalid!\n", code);
        return 0;
    }

    uint8_t nDataLen = 0;
    switch (nDataType) {
        case DHCP_OPTION_DATA_U8:
            nDataLen = DHCP_UINT8_BYTES;
            break;
        case DHCP_OPTION_DATA_U16:
            nDataLen = DHCP_UINT16_BYTES;
            break;
        case DHCP_OPTION_DATA_U32:
            nDataLen = DHCP_UINT32_BYTES;
            break;
        case DHCP_OPTION_DATA_IP:
            nDataLen = DHCP_UINT32_BYTES;
            break;
        case DHCP_OPTION_DATA_IP_PAIR:
            nDataLen = DHCP_UINT32_DOUBLE_BYTES;
            break;
        default:
            LOGE("GetDhcpOptionDataLen code:%{public}d failed, nDataType:%{public}d is invalid!\n",
                code, nDataType);
            break;
    }

    return nDataLen;
}

/* Get an option with bounds checking (warning, not aligned). */
const uint8_t *GetDhcpOption(const struct DhcpPacket *packet, int code, size_t *length)
{
    *length = 0;
    if (packet == NULL) {
        LOGE("GetDhcpOption failed, packet == NULL!\n");
        return NULL;
    }

    const uint8_t *pOption = packet->options;
    int i = 0, maxLen = DHCP_OPT_MAX_BYTES, over = 0, done = 0, curr = OPTION_FIELD;
    while (done == 0) {
        int getRet = GetDhcpOptionData(packet, code, i, maxLen);
        if (getRet == DHCP_OPT_SUCCESS) {
            *length = pOption[i + DHCP_OPT_LEN_INDEX];
            return pOption + i + DHCP_OPT_DATA_INDEX;
        } else if (getRet == DHCP_OPT_FAILED) {
            return NULL;
        }

        switch (pOption[i + DHCP_OPT_CODE_INDEX]) {
            case DHO_PAD:
                i++;
                break;
            case DHO_OPTSOVERLOADED:
                if (!CheckOptSoverloaded(packet, code, maxLen, &over, &i)) {
                    return NULL;
                }
                break;
            case DHO_END:
                if ((curr == OPTION_FIELD) && (over & FILE_FIELD)) {
                    pOption = packet->file;
                    i = 0;
                    maxLen = DHCP_FILE_MAX_BYTES;
                    curr = FILE_FIELD;
                } else if ((curr == FILE_FIELD) && (over & SNAME_FIELD)) {
                    pOption = packet->sname;
                    i = 0;
                    maxLen = DHCP_SNAME_MAX_BYTES;
                    curr = SNAME_FIELD;
                } else {
                    done = 1;
                }
                break;
            default:
                i += DHCP_OPT_CODE_BYTES + DHCP_OPT_LEN_BYTES + pOption[i + DHCP_OPT_LEN_INDEX];
                break;
        }
    }
    LOGW("GetDhcpOption options no find code:%{public}d, i:%{public}d!\n", code, i);
    return NULL;
}

bool GetDhcpOptionUint8(const struct DhcpPacket *packet, int code, uint8_t *data)
{
    size_t len = 0;
    const uint8_t *p = GetDhcpOption(packet, code, &len);
    if (p == NULL) {
        LOGW("GetDhcpOptionUint8 GetDhcpOption NULL, code:%{public}d!\n", code);
        return false;
    }
    if (len < (ssize_t)sizeof(uint8_t)) {
        LOGE("GetDhcpOptionUint8 failed, len:%{public}zu less data:%{public}zu, code:%{public}d!\n",
            len, sizeof(uint8_t), code);
        return false;
    }
    if (memcpy_s(data, sizeof(data), p, sizeof(uint8_t)) != EOK) {
        return false;
    }
    return true;
}

bool GetDhcpOptionUint32(const struct DhcpPacket *packet, int code, uint32_t *data)
{
    size_t len = 0;
    const uint8_t *p = GetDhcpOption(packet, code, &len);
    if (p == NULL) {
        LOGW("GetDhcpOptionUint32 GetDhcpOption NULL, code:%{public}d!\n", code);
        return false;
    }
    uint32_t uData = 0;
    if (len < (ssize_t)sizeof(uData)) {
        LOGE("GetDhcpOptionUint32 failed, len:%{public}zu less uData:%{public}zu, code:%{public}d!\n",
            len, sizeof(uData), code);
        return false;
    }
    if (memcpy_s(&uData, sizeof(uData), p, sizeof(uData)) != EOK) {
        return false;
    }
    if (uData > 0) {
        *data = ntohl(uData);
    }
    return true;
}

bool GetDhcpOptionUint32n(const struct DhcpPacket *packet, int code, uint32_t *data1, uint32_t *data2)
{
    size_t len = 0;
    const uint8_t *p = GetDhcpOption(packet, code, &len);
    if (p == NULL) {
        LOGW("GetDhcpOptionUint32n GetDhcpOption NULL, code:%{public}d!\n", code);
        return false;
    }
    uint32_t uData = 0;
    if ((len < (ssize_t)sizeof(uData)) || (len % (ssize_t)sizeof(uData) != 0)) {
        LOGE("GetDhcpOptionUint32n failed, len:%{public}zu is not %{public}zu * n, code:%{public}d!\n",
            len, sizeof(uData), code);
        return false;
    }
    if (memcpy_s(&uData, sizeof(uData), p, sizeof(uData)) != EOK) {
        return false;
    }
    if (uData > 0) {
        *data1 = ntohl(uData);
    }
    if (len > (ssize_t)sizeof(uData)) {
        p += sizeof(uData);
        uData = 0;
        if (memcpy_s(&uData, sizeof(uData), p, sizeof(uData)) != EOK) {
            return false;
        }
        if (uData > 0) {
            *data2 = ntohl(uData);
        }
    }
    return true;
}

char *GetDhcpOptionString(const struct DhcpPacket *packet, int code)
{
    size_t len;
    const uint8_t *p = GetDhcpOption(packet, code, &len);
    if ((p == NULL) || (*p == '\0')) {
        LOGW("GetDhcpOptionString GetDhcpOption NULL, code:%{public}d!\n", code);
        return NULL;
    }
    if (len < (ssize_t)sizeof(uint8_t)) {
        LOGE("GetDhcpOptionString failed, len:%{public}zu less data:%{public}zu, code:%{public}d!\n",
            len, sizeof(uint8_t), code);
        return NULL;
    }

    char *s = (char *)malloc(sizeof(char) * (len + 1));
    if (s) {
        if (memcpy_s(s, len + 1, p, len) != EOK) {
            free(s);
            return NULL;
        }
        s[len] = '\0';
    }
    return s;
}

/* Get option end index (no bounds checking) */
int GetEndOptionIndex(uint8_t *optionptr)
{
    int i = 0;
    while (optionptr[i] != DHO_END) {
        if (optionptr[i] == DHO_PAD) {
            i++;
        } else {
            i += optionptr[i + DHCP_OPT_LEN_INDEX] + DHCP_OPT_CODE_BYTES + DHCP_OPT_LEN_BYTES;
        }
    }
    return i;
}

/* add an option string to the options (an option string contains an option code,length, then data) */
int AddOptionString(uint8_t *optionptr, uint8_t *optionstr, int optionstrLen)
{
    int optStrLen = DHCP_OPT_CODE_BYTES + DHCP_OPT_LEN_BYTES + optionstr[DHCP_OPT_LEN_INDEX];
    if (optionstrLen != optStrLen) {
        LOGE("AddOptionString() code:%{public}u optionstrLen:%{public}d no equal optStrLen:%{public}d!\n",
            optionstr[DHCP_OPT_CODE_INDEX], optionstrLen, optStrLen);
        return 0;
    }

    /* end position + optionstr length + option code/length + end option */
    int end = GetEndOptionIndex(optionptr);
    if ((end + optionstrLen + 1) >= DHCP_OPT_MAX_BYTES) {
        LOGE("AddOptionString() code:%{public}u did not fit into the packet!\n", optionstr[DHCP_OPT_CODE_INDEX]);
        return 0;
    }

    LOGI("AddOptionString() adding option code %{public}u.\n", optionstr[DHCP_OPT_CODE_INDEX]);
    if (memcpy_s(optionptr + end, optionstrLen + 1, optionstr, optionstrLen) != EOK) {
        return 0;
    }
    optionptr[end + optionstrLen] = DHO_END;
    return optionstrLen;
}

/* add a one to four byte option to a packet */
int AddSimpleOption(uint8_t *optionptr, uint8_t code, uint32_t data)
{
    uint8_t length;
    uint8_t option[DHCP_OPT_CODE_BYTES + DHCP_OPT_LEN_BYTES + DHCP_UINT32_BYTES];
    uint8_t *u8;
    uint16_t *u16;
    uint32_t *u32;
    uint32_t aligned;
    u8 = (uint8_t *)&aligned;
    u16 = (uint16_t *)&aligned;
    u32 = &aligned;

    length = GetDhcpOptionDataLen(code);
    if (length == 0) {
        LOGE("AddSimpleOption() code:%{public}d failed, GetDhcpOptionDataLen length:0!\n", code);
        return 0;
    }

    option[DHCP_OPT_CODE_INDEX] = code;
    option[DHCP_OPT_LEN_INDEX] = length;

    switch (length) {
        case DHCP_UINT8_BYTES:
            *u8 =  data;
            break;
        case DHCP_UINT16_BYTES:
            *u16 = data;
            break;
        case DHCP_UINT32_BYTES:
            *u32 = data;
            break;
        default:
            LOGE("AddSimpleOption() length:%{public}u error, break!\n", length);
            break;
    }
    if (memcpy_s(option + DHCP_OPT_DATA_INDEX, sizeof(uint32_t), &aligned, length) != EOK) {
        return 0;
    }
    int nLen = DHCP_OPT_CODE_BYTES + DHCP_OPT_LEN_BYTES + option[DHCP_OPT_LEN_INDEX];
    return AddOptionString(optionptr, option, nLen);
}
