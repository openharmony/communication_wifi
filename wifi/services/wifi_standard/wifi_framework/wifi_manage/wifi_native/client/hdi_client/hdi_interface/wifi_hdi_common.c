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

#ifdef HDI_INTERFACE_SUPPORT
#include <unistd.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <pthread.h>

#include "securec.h"
#include "wifi_hdi_common.h"
#include "wifi_log.h"
#include "v1_2/iwlan_callback.h"
#include "wifi_hdi_proxy.h"
#include "wifi_hdi_sta_impl.h"

#undef LOG_TAG
#define LOG_TAG "WifiHdiCommon"

void HdiDeathCallbackCheck(HdiPortType portType, bool isRemoteDied)
{
    if (isRemoteDied) {
        switch (portType) {
            case HDI_PORT_TYPE_STATION:
                HdiReleaseLocalResources();
                if (StartHdiWifi() != WIFI_IDL_OPT_OK) {
                    LOGE("[STA] Start hdi failed!");
                    return;
                }
                struct IWlanCallback cEventCallback;
                if (memset_s(&cEventCallback, sizeof(cEventCallback), 0, sizeof(cEventCallback)) != EOK) {
                    LOGE("%{public}s: failed to memset", __func__);
                    return;
                }
                cEventCallback.ScanResults = HdiWifiScanResultsCallback;
                if (HdiRegisterEventCallback(&cEventCallback) != WIFI_IDL_OPT_OK) {
                    LOGE("[STA] RegisterHdiStaCallbackEvent failed!");
                    return;
                }
                break;
            case HDI_PORT_TYPE_AP:
            case HDI_PORT_TYPE_P2P_DEVICE:
                if (HdiStop() != WIFI_IDL_OPT_OK) {
                    LOGE("failed to stop ap hdi");
                    return;
                }
                if (StartHdiWifi() != WIFI_IDL_OPT_OK) {
                    LOGE("failed to start %{public}d", portType);
                    return;
                }
                break;
            default:
                LOGE("invalid portType:%{public}d", portType);
                break;
        }
    }
}

static int hex2num(char c)
{
    if (c >= '0' && c <= '9') {
        return c - '0';
    }
    if (c >= 'a' && c <= 'f') {
        return c - 'a' + HDI_POS_TEN;
    }
    if (c >= 'A' && c <= 'F') {
        return c - 'A' + HDI_POS_TEN;
    }
    return -1;
}

int hex2byte(const char *hex)
{
    int a, b;
    a = hex2num(*hex++);
    if (a < 0) {
        return -1;
    }
    b = hex2num(*hex++);
    if (b < 0) {
        return -1;
    }
    return (a << HDI_POS_FOURTH) | b;
}

int HdiTxtPrintf(char *str, size_t size, const char *format, ...)
{
    va_list ap;
    int ret;

    va_start(ap, format);
    ret = vsnprintf_s(str, size, size - 1, format, ap);
    va_end(ap);
    if (size > 0) {
        str[size - 1] = '\0';
    }
    return ret;
}

int HdiGetCipherInfo(char *start, char *end, int ciphers, const char *delim)
{
    char *pos = start;
    int ret;

    if (ciphers & HDI_CIPHER_CCMP_256) {
        HDI_HANDLE_CIPHER_INFO(ret, start, end, delim, "%sCCMP-256");
    }
    if (ciphers & HDI_CIPHER_GCMP_256) {
        HDI_HANDLE_CIPHER_INFO(ret, start, end, delim, "%sGCMP-256");
    }
    if (ciphers & HDI_CIPHER_CCMP) {
        HDI_HANDLE_CIPHER_INFO(ret, start, end, delim, "%sCCMP");
    }
    if (ciphers & HDI_CIPHER_GCMP) {
        HDI_HANDLE_CIPHER_INFO(ret, start, end, delim, "%sGCMP");
    }
    if (ciphers & HDI_CIPHER_TKIP) {
        HDI_HANDLE_CIPHER_INFO(ret, start, end, delim, "%sTKIP");
    }
    if (ciphers & HDI_CIPHER_AES_128_CMAC) {
        HDI_HANDLE_CIPHER_INFO(ret, start, end, delim, "%sAES-128-CMAC");
    }
    if (ciphers & HDI_CIPHER_BIP_GMAC_128) {
        HDI_HANDLE_CIPHER_INFO(ret, start, end, delim, "%sBIP-GMAC-128");
    }
    if (ciphers & HDI_CIPHER_BIP_GMAC_256) {
        HDI_HANDLE_CIPHER_INFO(ret, start, end, delim, "%sBIP-GMAC-256");
    }
    if (ciphers & HDI_CIPHER_BIP_CMAC_256) {
        HDI_HANDLE_CIPHER_INFO(ret, start, end, delim, "%sBIP-CMAC-256");
    }
    if (ciphers & HDI_CIPHER_NONE) {
        HDI_HANDLE_CIPHER_INFO(ret, start, end, delim, "%sNONE");
    }

    return pos - start;
}

static char* HdiGetCipherTxt(char *pos, char *end, int cipher)
{
    int ret;
    ret = HdiTxtPrintf(pos, end - pos, "-");
    if (HdiCheckError(end - pos, ret)) {
        return pos;
    }
    pos += ret;
    ret = HdiGetCipherInfo(pos, end, cipher, "+");
    if (ret < 0) {
        return pos;
    }
    pos += ret;
    return pos;
}

static int HdiRsnIdToCipher(const uint8_t *s)
{
    if (HDI_GET_RSN_ID(s) == HDI_CIPHER_SUITE_NONE) {
        return HDI_CIPHER_NONE;
    }
    if (HDI_GET_RSN_ID(s) == HDI_CIPHER_SUITE_TKIP) {
        return HDI_CIPHER_TKIP;
    }
    if (HDI_GET_RSN_ID(s) == HDI_CIPHER_SUITE_CCMP) {
        return HDI_CIPHER_CCMP;
    }
    return 0;
}

static int HdiRsnIdToCipherSuite(const uint8_t *s)
{
    if (HDI_GET_RSN_ID(s) == HDI_RSN_CIPHER_SUITE_NONE) {
        return HDI_CIPHER_NONE;
    }
    if (HDI_GET_RSN_ID(s) == HDI_RSN_CIPHER_SUITE_TKIP) {
        return HDI_CIPHER_TKIP;
    }
    if (HDI_GET_RSN_ID(s) == HDI_RSN_CIPHER_SUITE_CCMP) {
        return HDI_CIPHER_CCMP;
    }
    if (HDI_GET_RSN_ID(s) == HDI_RSN_CIPHER_SUITE_GCMP) {
        return HDI_CIPHER_GCMP;
    }
    if (HDI_GET_RSN_ID(s) == HDI_RSN_CIPHER_SUITE_CCMP_256) {
        return HDI_CIPHER_CCMP_256;
    }
    if (HDI_GET_RSN_ID(s) == HDI_RSN_CIPHER_SUITE_GCMP_256) {
        return HDI_CIPHER_GCMP_256;
    }
    if (HDI_GET_RSN_ID(s) == HDI_RSN_CIPHER_SUITE_BIP_GMAC_128) {
        return HDI_CIPHER_BIP_GMAC_128;
    }
    if (HDI_GET_RSN_ID(s) == HDI_RSN_CIPHER_SUITE_BIP_GMAC_256) {
        return HDI_CIPHER_BIP_GMAC_256;
    }
    if (HDI_GET_RSN_ID(s) == HDI_RSN_CIPHER_SUITE_BIP_CMAC_256) {
        return HDI_CIPHER_BIP_CMAC_256;
    }
    if (HDI_GET_RSN_ID(s) == HDI_RSN_CIPHER_SUITE_NO_GROUP_ADDRESSED) {
        return HDI_CIPHER_GTK_NOT_USED;
    }
    return 0;
}

static int HdiKeyMgmtToAuthMgmt(const uint8_t *s)
{
    if (HDI_GET_RSN_ID(s) == HDI_AUTH_KEY_MGMT_UNSPEC) {
        return HDI_KEY_MGMT;
    }
    if (HDI_GET_RSN_ID(s) == HDI_AUTH_KEY_MGMT_PSK_OVER) {
        return HDI_KEY_MGMT_PSK;
    }
    if (HDI_GET_RSN_ID(s) == HDI_AUTH_KEY_MGMT_NONE) {
        return HDI_KEY_MGMT_HDI_NONE;
    }
    return 0;
}

static int HdiRsnKeyMgmtToAuthMgmt(const uint8_t *s)
{
    if (HDI_GET_RSN_ID(s) == HDI_RSN_AUTH_KEY_MGMT_UNSPEC) {
        return HDI_KEY_MGMT;
    }
    if (HDI_GET_RSN_ID(s) == HDI_RSN_AUTH_KEY_MGMT_SAE) {
        return HDI_KEY_MGMT_SAE;
    }
    if (HDI_GET_RSN_ID(s) == HDI_RSN_AUTH_KEY_MGMT_PSK_OVER) {
        return HDI_KEY_MGMT_PSK;
    }
    if (HDI_GET_RSN_ID(s) == HDI_RSN_AUTH_KEY_MGMT_SUITE_B) {
        return HDI_KEY_MGMT_SUITE_B;
    }
    if (HDI_GET_RSN_ID(s) == HDI_RSN_AUTH_KEY_MGMT_SUITE_B_192) {
        return HDI_KEY_MGMT_SUITE_B_192;
    }
    if (HDI_GET_RSN_ID(s) == HDI_RSN_AUTH_KEY_MGMT_FILS_SHA256) {
        return HDI_KEY_MGMT_FILS_SHA256;
    }
    if (HDI_GET_RSN_ID(s) == HDI_RSN_AUTH_KEY_MGMT_FILS_SHA384) {
        return HDI_KEY_MGMT_FILS_SHA384;
    }
    if (HDI_GET_RSN_ID(s) == HDI_RSN_AUTH_KEY_MGMT_FT_FILS_SHA256) {
        return HDI_KEY_MGMT_FT_FILS_SHA256;
    }
    if (HDI_GET_RSN_ID(s) == HDI_RSN_AUTH_KEY_MGMT_FT_FILS_SHA384) {
        return HDI_KEY_MGMT_FT_FILS_SHA384;
    }
    if (HDI_GET_RSN_ID(s) == HDI_RSN_AUTH_KEY_MGMT_OSEN) {
        return HDI_KEY_MGMT_OSEN;
    }
    if (HDI_GET_RSN_ID(s) == HDI_RSN_AUTH_KEY_MGMT_OWE) {
        return HDI_KEY_MGMT_OWE;
    }
    if (HDI_GET_RSN_ID(s) == HDI_RSN_AUTH_KEY_MGMT_PSK_SHA256) {
        return HDI_KEY_MGMT_PSK_SHA256;
    }
    return 0;
}

const uint8_t* HdiGetIe(const uint8_t *ies, size_t len, uint8_t eid)
{
    const struct HdiElem *elem;

    if (!ies) {
        return NULL;
    }

    HDI_CHECK_ELEMENT_BY_ID(elem, eid, ies, len)
        return &elem->id;

    return NULL;
}

const uint8_t* HdiBssGetIe(const uint8_t *ies, size_t len, uint8_t ie)
{
    return HdiGetIe(ies, len, ie);
}

const uint8_t *HdiBssGetVendorIe(const uint8_t *ies, size_t len, uint32_t vendorType)
{
    const struct HdiElem *elem;
    HDI_CHECK_ELEMENT_BY_ID(elem, HDI_EID_VENDOR_SPECIFIC, ies, len) {
        if (elem->datalen >= HDI_POS_FOURTH &&
            vendorType == HdiGetBe32(elem->data))
            return &elem->id;
    }

    return NULL;
}

const uint8_t* HdiBssGetVendorBeacon(const uint8_t *ies, size_t len, size_t beaconIeLen, uint32_t vendorType)
{
    const struct HdiElem *elem;

    if (beaconIeLen == 0)
        return NULL;

    ies += len;

    HDI_CHECK_ELEMENT_BY_ID(elem, HDI_EID_VENDOR_SPECIFIC, ies, beaconIeLen) {
        if (elem->datalen >= HDI_POS_FOURTH &&
            vendorType == HdiGetBe32(elem->data))
            return &elem->id;
    }

    return NULL;
}

int HdiCheckValidWise(int cipher)
{
    return cipher == HDI_CIPHER_CCMP_256 ||
        cipher == HDI_CIPHER_GCMP_256 ||
        cipher == HDI_CIPHER_CCMP ||
        cipher == HDI_CIPHER_GCMP ||
        cipher == HDI_CIPHER_TKIP;
}

int HdiCheckValidGroup(int cipher)
{
    return HdiCheckValidWise(cipher) ||
        cipher == HDI_CIPHER_GTK_NOT_USED;
}

int HdiConvertIe(const uint8_t *hdiIe, size_t wpaIeLen,
             struct HdiIeData *data)
{
    const struct HdiIeHdr *hdr;
    const uint8_t *pos;
    int left;
    int i, count;

    (void)memset_s(data, sizeof(*data), 0, sizeof(*data));
    data->proto = HDI_PROTO_DEFAULT;
    data->pairwiseCipher = HDI_CIPHER_TKIP;
    data->groupCipher = HDI_CIPHER_TKIP;
    data->keyMgmt = HDI_KEY_MGMT;
    data->capabilities = 0;
    data->pmkid = NULL;
    data->numPmkid = 0;
    data->mgmtGroupCipher = 0;

    if (wpaIeLen < sizeof(struct HdiIeHdr)) {
        LOGI("ie len too short %{public}lu", (unsigned long) wpaIeLen);
        return -1;
    }

    hdr = (const struct HdiIeHdr *) hdiIe;

    if (hdr->elemId != HDI_EID_VENDOR_SPECIFIC ||
        hdr->len != wpaIeLen - HDI_POS_SECOND ||
        HDI_GET_RSN_ID(hdr->oui) != HDI_OUI_TYPE ||
        HdiGetBe16(hdr->version) != HDI_VERSION) {
        LOGI("malformed ie or unknown version");
        return -1;
    }

    pos = (const uint8_t *) (hdr + 1);
    left = wpaIeLen - sizeof(*hdr);

    if (left >= HDI_SELECTOR_LEN) {
        data->groupCipher = HdiRsnIdToCipher(pos);
        pos += HDI_SELECTOR_LEN;
        left -= HDI_SELECTOR_LEN;
    } else if (left > 0) {
        LOGI("ie length mismatch, %{public}u too much", left);
        return -1;
    }

    if (left >= HDI_POS_SECOND) {
        data->pairwiseCipher = 0;
        count = HdiGetBe16(pos);
        pos += HDI_POS_SECOND;
        left -= HDI_POS_SECOND;
        if (count == 0 || count > left / HDI_SELECTOR_LEN) {
            LOGI("ie count botch (pairwise), count %{public}u left %{public}u", count, left);
            return -1;
        }
        for (i = 0; i < count; i++) {
            data->pairwiseCipher |= HdiRsnIdToCipher(pos);
            pos += HDI_SELECTOR_LEN;
            left -= HDI_SELECTOR_LEN;
        }
    } else if (left == 1) {
        LOGI("ie too short (for key mgmt)");
        return -1;
    }

    if (left >= HDI_POS_SECOND) {
        data->keyMgmt = 0;
        count = HdiGetBe16(pos);
        pos += HDI_POS_SECOND;
        left -= HDI_POS_SECOND;
        if (count == 0 || count > left / HDI_SELECTOR_LEN) {
            LOGI("ie count botch (key mgmt),count %{public}u left %{public}u", count, left);
            return -1;
        }
        for (i = 0; i < count; i++) {
            data->keyMgmt |= HdiKeyMgmtToAuthMgmt(pos);
            pos += HDI_SELECTOR_LEN;
            left -= HDI_SELECTOR_LEN;
        }
    } else if (left == 1) {
        LOGI("ie too short (for capabilities)");
        return -1;
    }

    if (left >= HDI_POS_SECOND) {
        data->capabilities = HdiGetBe16(pos);
    }
    return 0;
}

int HdiConvertIeRsn(const uint8_t *rsnIe, size_t rsnIeLen,
    struct HdiIeData *data)
{
    const uint8_t *pos;
    int left;
    int i, count;

    (void)memset_s(data, sizeof(*data), 0, sizeof(*data));
    data->proto = HDI_PROTO_ONE;
    data->pairwiseCipher = HDI_CIPHER_CCMP;
    data->groupCipher = HDI_CIPHER_CCMP;
    data->keyMgmt = HDI_KEY_MGMT;
    data->capabilities = 0;
    data->pmkid = NULL;
    data->numPmkid = 0;
    data->mgmtGroupCipher = 0;

    if (rsnIeLen == 0) {
        return -1;
    }

    if (rsnIeLen < sizeof(struct HdiRsnIeHdr)) {
        LOGI("ie len too short %{public}lu", (unsigned long) rsnIeLen);
        return -1;
    }

    if (rsnIeLen >= HDI_POS_SIX && rsnIe[1] >= HDI_POS_FOURTH &&
        rsnIe[1] == rsnIeLen - HDI_POS_SECOND &&
        HdiGetBe32(&rsnIe[HDI_POS_SECOND]) == HDI_OSEN_IE_VENDOR_TYPE) {
        pos = rsnIe + HDI_POS_SIX;
        left = rsnIeLen - HDI_POS_SIX;

        data->groupCipher = HDI_CIPHER_GTK_NOT_USED;
        data->hasGroup = 1;
        data->keyMgmt = HDI_KEY_MGMT_OSEN;
        data->proto = HDI_PROTO_THREE;
    } else {
        const struct HdiRsnIeHdr *hdr;

        hdr = (const struct HdiRsnIeHdr *) rsnIe;

        if (hdr->elemId != HDI_EID_RSN ||
            hdr->len != rsnIeLen - HDI_POS_SECOND ||
            HdiGetBe16(hdr->version) != HDI_VERSION) {
            LOGI("malformed ie or unknown version");
            return -1;
        }

        pos = (const uint8_t *) (hdr + 1);
        left = rsnIeLen - sizeof(*hdr);
    }

    if (left >= HDI_SELECTOR_LEN) {
        data->groupCipher = HdiRsnIdToCipherSuite(pos);
        data->hasGroup = 1;
        if (!HdiCheckValidGroup(data->groupCipher)) {
            LOGI("invalid group cipher 0x%{public}x (%08x)", data->groupCipher,
                   HdiGetBe32(pos));
            return -1;
        }
        pos += HDI_SELECTOR_LEN;
        left -= HDI_SELECTOR_LEN;
    } else if (left > 0) {
        LOGI("ie length mismatch, %u too much", left);
        return -1;
    }

    if (left >= HDI_POS_SECOND) {
        data->pairwiseCipher = 0;
        count = HdiGetBe16(pos);
        pos += HDI_POS_SECOND;
        left -= HDI_POS_SECOND;
        if (count == 0 || count > left / HDI_SELECTOR_LEN) {
            LOGI("ie count botch (pairwise), count %{public}u left %{public}u", count, left);
            return -1;
        }
        data->hasPairwise = 1;
        for (i = 0; i < count; i++) {
            data->pairwiseCipher |= HdiRsnIdToCipherSuite(pos);
            pos += HDI_SELECTOR_LEN;
            left -= HDI_SELECTOR_LEN;
        }
    } else if (left == 1) {
        LOGI("ie too short (for key mgmt)");
        return -1;
    }

    if (left >= HDI_POS_SECOND) {
        data->keyMgmt = 0;
        count = HdiGetBe16(pos);
        pos += HDI_POS_SECOND;
        left -= HDI_POS_SECOND;
        if (count == 0 || count > left / HDI_SELECTOR_LEN) {
            LOGI("ie count botch (key mgmt) count %{public}u left %{public}u", count, left);
            return -1;
        }
        for (i = 0; i < count; i++) {
            data->keyMgmt |= HdiRsnKeyMgmtToAuthMgmt(pos);
            pos += HDI_SELECTOR_LEN;
            left -= HDI_SELECTOR_LEN;
        }
    } else if (left == 1) {
        LOGI("ie too short (for capabilities)");
        return -1;
    }

    if (left >= HDI_POS_SECOND) {
        data->capabilities = HdiGetBe16(pos);
        pos += HDI_POS_SECOND;
        left -= HDI_POS_SECOND;
    }

    if (left >= HDI_POS_SECOND) {
        uint16_t numPmkid = HdiGetBe16(pos);
        pos += HDI_POS_SECOND;
        left -= HDI_POS_SECOND;
        if (numPmkid > (unsigned int) left / HDI_PMKID_LEN) {
            LOGI("PMKID underflow(numPmkid=%{public}u left=%{public}d)", numPmkid, left);
            data->numPmkid = 0;
            return -1;
        } else {
            data->numPmkid = numPmkid;
            data->pmkid = pos;
        }
    }

    return 0;
}

int HdiParseIe(const uint8_t *hdiIe, size_t wpaIeLen,
             struct HdiIeData *data)
{
    if (wpaIeLen >= HDI_POS_FIRST && hdiIe[0] == HDI_EID_RSN) {
        return HdiConvertIeRsn(hdiIe, wpaIeLen, data);
    }        
    if (wpaIeLen >= HDI_POS_SIX && hdiIe[0] == HDI_EID_VENDOR_SPECIFIC &&
        hdiIe[1] >= HDI_POS_FOURTH && HdiGetBe32(&hdiIe[HDI_POS_SECOND]) == HDI_OSEN_IE_VENDOR_TYPE) {
        return HdiConvertIeRsn(hdiIe, wpaIeLen, data);
    }
    else {
        return HdiConvertIe(hdiIe, wpaIeLen, data);
    }
}

char* HdiGetIeTxt(char *pos, char *end, const char *proto,
                    const uint8_t *ie, size_t ieLen)
{
    struct HdiIeData data;
    char *start;
    int ret;

    ret = HdiTxtPrintf(pos, end - pos, "[%s-", proto);
    if (HdiCheckError(end - pos, ret)) {
        return pos;
    }
    pos += ret;

    if (HdiParseIe(ie, ieLen, &data) < 0) {
        ret = HdiTxtPrintf(pos, end - pos, "?]");
        if (HdiCheckError(end - pos, ret)) {
            return pos;
        }
        pos += ret;
        return pos;
    }

    start = pos;

    HDI_HANDLE_CIPHER_POS_INFO(data.keyMgmt & HDI_KEY_MGMT, ret, pos, end, "+", "%sEAP");
    HDI_HANDLE_CIPHER_POS_INFO(data.keyMgmt & HDI_KEY_MGMT_PSK, ret, pos, end, "+", "%sPSK");
    HDI_HANDLE_CIPHER_POS_INFO(data.keyMgmt & HDI_KEY_MGMT_HDI_NONE, ret, pos, end, "+", "%sNone");
    HDI_HANDLE_CIPHER_POS_INFO(data.keyMgmt & HDI_KEY_MGMT_SAE, ret, pos, end, "+", "%sSAE");
    HDI_HANDLE_CIPHER_POS_INFO(data.keyMgmt & HDI_KEY_MGMT_OSEN, ret, pos, end, "+", "%sOSEN");
    HDI_HANDLE_CIPHER_POS_INFO(data.keyMgmt & HDI_KEY_MGMT_OWE, ret, pos, end, "+", "%sOWE");
    HDI_HANDLE_CIPHER_POS_INFO(data.keyMgmt & HDI_KEY_MGMT_PSK_SHA256, ret, pos, end, "+", "%sPSK");

    pos = HdiGetCipherTxt(pos, end, data.pairwiseCipher);

    if (data.capabilities & HDI_CAPABILITY_PREAUTH) {
        ret = HdiTxtPrintf(pos, end - pos, "-preauth");
        if (HdiCheckError(end - pos, ret))
            return pos;
        pos += ret;
    }

    ret = HdiTxtPrintf(pos, end - pos, "]");
    if (HdiCheckError(end - pos, ret)) {
        return pos;
    }
    pos += ret;

    return pos;
}

const uint8_t* HdiGetIeExt(const uint8_t *ies, size_t len, uint8_t ext)
{
    const struct HdiElem *elem;

    if (!ies) {
        return NULL;
    }
    HDI_CHECK_ELEMENT_BY_EXTID(elem, ext, ies, len)
        return &elem->id;

    return NULL;
}

const uint8_t* HdiBssGetIeExt(const uint8_t *ies, size_t len, uint8_t ext)
{
    return HdiGetIeExt(ies, len, ext);
}

void HdiBufEncode(char *txt, size_t maxlen, const uint8_t *data, size_t len)
{
    char *end = txt + maxlen;
    size_t i;

    for (i = 0; i < len; i++) {
        if (txt + HDI_POS_FOURTH >= end)
            break;

        switch (data[i]) {
            case '\"':
                *txt++ = '\\';
                *txt++ = '\"';
                break;
            case '\\':
                *txt++ = '\\';
                *txt++ = '\\';
                break;
            case '\033':
                *txt++ = '\\';
                *txt++ = 'e';
                break;
            case '\n':
                *txt++ = '\\';
                *txt++ = 'n';
                break;
            case '\r':
                *txt++ = '\\';
                *txt++ = 'r';
                break;
            case '\t':
                *txt++ = '\\';
                *txt++ = 't';
                break;
            default:
                if (data[i] >= HDI_POS_TT && data[i] <= HDI_POS_OTX) {
                    *txt++ = data[i];
                } else {
                    txt += HdiTxtPrintf(txt, end - txt, "\\x%02x",
                            data[i]);
                }
                break;
        }
    }

    *txt = '\0';
}

const char* HdiSSid2Txt(const uint8_t *ssid, size_t ssidLen)
{
    static char ssid_txt[SSID_MAX_LEN * HDI_POS_FOURTH + 1];
    if (ssid == NULL) {
        ssid_txt[0] = '\0';
        return ssid_txt;
    }

    HdiBufEncode(ssid_txt, sizeof(ssid_txt), ssid, ssidLen);
    return ssid_txt;
}

int8_t IsValidHexCharAndConvert(char c)
{
    if (c >= '0' && c <= '9') {
        return c - '0';
    }
    if (c >= 'a' && c <= 'f') {
        return c - 'a' + ('9' - '0' + 1);
    }
    if (c >= 'A' && c <= 'F') {
        return c - 'A' + ('9' - '0' + 1);
    }
    return -1;
}

int CheckMacIsValid(const char *macStr)
{
    if (macStr == NULL || strlen(macStr) != MAC_STRING_SIZE) {
        return -1;
    }
    for (int i = 0, j = 0; i < MAC_STRING_SIZE; ++i) {
        if (j == 0 || j == 1) {
            int v = IsValidHexCharAndConvert(macStr[i]);
            if (v < 0) {
                return -1;
            }
            ++j;
        } else {
            if (macStr[i] != ':') {
                return -1;
            }
            j = 0;
        }
    }
    return 0;
}
#ifdef SUPPORT_LOCAL_RANDOM_MAC
static const uint32_t MAC_ADDR_INDEX_0 = 0;
static const uint32_t MAC_ADDR_INDEX_1 = 1;
static const uint32_t MAC_ADDR_INDEX_2 = 2;
static const uint32_t MAC_ADDR_INDEX_3 = 3;
static const uint32_t MAC_ADDR_INDEX_4 = 4;
static const uint32_t MAC_ADDR_INDEX_5 = 5;
static const uint32_t MAC_ADDR_INDEX_SIZE = 6;

int32_t GetFeatureType(int portType)
{
    switch (portType) {
        case HDI_PORT_TYPE_STATION:
            return PROTOCOL_80211_IFTYPE_STATION;
        case HDI_PORT_TYPE_AP:
            return PROTOCOL_80211_IFTYPE_AP;
        case HDI_PORT_TYPE_P2P_CLIENT:
            return PROTOCOL_80211_IFTYPE_P2P_CLIENT;
        case HDI_PORT_TYPE_P2P_GO:
            return PROTOCOL_80211_IFTYPE_P2P_GO;
        case HDI_PORT_TYPE_P2P_DEVICE:
            return PROTOCOL_80211_IFTYPE_P2P_DEVICE;
        default:
            return PROTOCOL_80211_IFTYPE_UNSPECIFIED;
    }
}

void UpDownLink(int flag, int type, const char *iface)
{
    struct ifreq ifr;
    int32_t ret = 0;
    if (memset_s(&ifr, sizeof(ifr), 0, sizeof(ifr)) != EOK) {
        LOGE("%{public}s: failed to init", __func__);
        return;
    }
    if (memcpy_s(ifr.ifr_name, sizeof(ifr.ifr_name), iface, strlen(iface)) != EOK) {
        LOGE("memcpy iface name fail");
        return;
    }
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        LOGE("%{public}s: failed to create the socket", __func__);
        return;
    }
    ret = ioctl(fd, SIOCGIFFLAGS, &ifr);
    if (ret != 0) {
        LOGE("%{public}s: failed to ioctl[SIOCGIFFLAGS], error:%{public}d(%{public}s)",
            __func__, errno, strerror(errno));
        close(fd);
        return;
    }
    if (flag == 1) {
        ifr.ifr_flags |= IFF_UP;
    } else {
        ifr.ifr_flags &= ~IFF_UP;
    }
    LOGD("%{public}s: flag=%{public}d, ifr_flags=%{public}d", __func__, flag, ifr.ifr_flags);
    ret = ioctl(fd, SIOCSIFFLAGS, &ifr);
    if (ret < 0) {
        LOGE("%{public}s: failed to ioctl[SIOCSIFFLAGS], error:%{public}d(%{public}s)",
            __func__, errno, strerror(errno));
        close(fd);
        return;
    }

    close(fd);
}

WifiErrorNo HdiSetAssocMacAddr(const unsigned char *mac, int lenMac, const int portType)
{
    if (mac == NULL) {
        LOGE("HdiSetAssocMacAddr is NULL");
        return WIFI_IDL_OPT_FAILED;
    }
    LOGD("%{public}s: begin to set random mac address, type:%{public}d, mac:%{private}s",
        __func__, portType, mac);
    HdiDeathCallbackCheck(portType, IsHdiRemoteDied());
    if (strlen((const char *)mac) != HDI_MAC_LENGTH || lenMac != HDI_MAC_LENGTH) {
        LOGE("%{public}s: Mac size not correct! real len:%{public}zu, lenMac:%{public}d",
            __func__, strlen((const char *)mac), lenMac);
        return WIFI_IDL_OPT_FAILED;
    }
    int32_t featureType = GetFeatureType(portType);
    WifiHdiProxy proxy = GetHdiProxy(featureType);
    CHECK_HDI_PROXY_AND_RETURN(proxy, WIFI_IDL_OPT_FAILED);

    unsigned char mac_bin[MAC_ADDR_INDEX_SIZE];
    int32_t ret = sscanf_s((char *)mac, "%2hhx:%2hhx:%2hhx:%2hhx:%2hhx:%2hhx",
           &mac_bin[MAC_ADDR_INDEX_0], &mac_bin[MAC_ADDR_INDEX_1], &mac_bin[MAC_ADDR_INDEX_2],
           &mac_bin[MAC_ADDR_INDEX_3], &mac_bin[MAC_ADDR_INDEX_4], &mac_bin[MAC_ADDR_INDEX_5]);
    if (ret <= EOK) {
        LOGE("%{public}s: failed to parse mac, ret:%{public}d", __func__, ret);
        return WIFI_IDL_OPT_FAILED;
    }

    UpDownLink(0, portType, proxy.feature->ifName);
    ret = proxy.wlanObj->SetMacAddress(proxy.wlanObj, proxy.feature, mac_bin, MAC_ADDR_INDEX_SIZE);
    if (ret != HDF_SUCCESS) {
        LOGE("%{public}s: failed to set the mac, ret:%{public}d, portType:%{public}d",
            __func__, ret, portType);
    }
    UpDownLink(1, portType, proxy.feature->ifName);
    LOGI("%{public}s: result is %{public}d", __func__, ret);
    return (ret == 0) ? WIFI_IDL_OPT_OK : WIFI_IDL_OPT_FAILED;
}
#endif

#endif
