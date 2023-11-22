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

#ifdef HDI_WPA_INTERFACE_SUPPORT
#include "wifi_hdi_wpa_sta_impl.h"

#undef LOG_TAG
#define LOG_TAG "WifiHdiWpaStaImpl"
#define COLUMN_INDEX_ZERO 0
#define COLUMN_INDEX_ONE 1
#define COLUMN_INDEX_TWO 2
#define COLUMN_INDEX_THREE 3
#define COLUMN_INDEX_FOUR 4
#define COLUMN_INDEX_FIVE 5
#define REPLY_BUF_LENGTH (4096 * 10)

const int QUOTATION_MARKS_FLAG_YES = 0;
const int QUOTATION_MARKS_FLAG_NO = 1;
const unsigned int HT_OPER_EID = 61;
const unsigned int VHT_OPER_EID = 192;
const unsigned int EXT_EXIST_EID = 255;
const unsigned int EXT_HE_OPER_EID = 36;
const unsigned int HE_OPER_BASIC_LEN = 6;
const unsigned int VHT_OPER_INFO_EXTST_MASK = 0x40;
const unsigned int GHZ_HE_INFO_EXIST_MASK_6 = 0x02;
const unsigned int GHZ_HE_WIDTH_MASK_6 = 0x03;
const unsigned int BSS_EXIST_MASK = 0x80;
const unsigned int VHT_OPER_INFO_BEGIN_INDEX = 6;
const unsigned int VHT_INFO_SIZE = 3;
const unsigned int HT_INFO_SIZE = 3;
const unsigned int UINT8_MASK = 0xFF;
const unsigned int UNSPECIFIED = -1;
const unsigned int MAX_INFO_ELEMS_SIZE = 256;
const unsigned int SUPP_RATES_SIZE = 8;
const unsigned int EXT_SUPP_RATES_SIZE = 4;
const unsigned int SUPPORTED_RATES_EID = 1;
const unsigned int ERP_EID = 42;
const unsigned int EXT_SUPPORTED_RATES_EID = 50;
const unsigned int BAND_5_GHZ = 2;
const unsigned int BAND_6_GHZ = 8;
const unsigned int CHAN_WIDTH_20MHZ = 0;
const unsigned int CHAN_WIDTH_40MHZ = 1;
const unsigned int CHAN_WIDTH_80MHZ = 2;
const unsigned int CHAN_WIDTH_160MHZ = 3;
const unsigned int CHAN_WIDTH_80MHZ_MHZ = 4;

static pthread_mutex_t g_hdiCallbackMutex = PTHREAD_MUTEX_INITIALIZER;
static struct IWpaCallback *g_hdiWpaStaCallbackObj = NULL;
static WpaSsidField g_wpaSsidFields[] = {
    {DEVICE_CONFIG_SSID, "ssid", QUOTATION_MARKS_FLAG_YES},
    {DEVICE_CONFIG_PSK, "psk", QUOTATION_MARKS_FLAG_YES},
    {DEVICE_CONFIG_KEYMGMT, "key_mgmt", QUOTATION_MARKS_FLAG_NO},
    {DEVICE_CONFIG_PRIORITY, "priority", QUOTATION_MARKS_FLAG_NO},
    {DEVICE_CONFIG_SCAN_SSID, "scan_ssid", QUOTATION_MARKS_FLAG_NO},
    {DEVICE_CONFIG_EAP, "eap", QUOTATION_MARKS_FLAG_NO},
    {DEVICE_CONFIG_IDENTITY, "identity", QUOTATION_MARKS_FLAG_YES},
    {DEVICE_CONFIG_PASSWORD, "password", QUOTATION_MARKS_FLAG_YES},
    {DEVICE_CONFIG_BSSID, "bssid", QUOTATION_MARKS_FLAG_NO},
    {DEVICE_CONFIG_AUTH_ALGORITHMS, "auth_alg", QUOTATION_MARKS_FLAG_NO},
    {DEVICE_CONFIG_WEP_KEY_IDX, "wep_tx_keyidx", QUOTATION_MARKS_FLAG_NO},
    {DEVICE_CONFIG_WEP_KEY_0, "wep_key0", QUOTATION_MARKS_FLAG_NO},
    {DEVICE_CONFIG_WEP_KEY_1, "wep_key1", QUOTATION_MARKS_FLAG_NO},
    {DEVICE_CONFIG_WEP_KEY_2, "wep_key2", QUOTATION_MARKS_FLAG_NO},
    {DEVICE_CONFIG_WEP_KEY_3, "wep_key3", QUOTATION_MARKS_FLAG_NO},
    {DEVICE_CONFIG_EAP_CLIENT_CERT, "client_cert", QUOTATION_MARKS_FLAG_YES},
    {DEVICE_CONFIG_EAP_PRIVATE_KEY, "private_key", QUOTATION_MARKS_FLAG_YES},
    {DEVICE_CONFIG_EAP_PHASE2METHOD, "phase2", QUOTATION_MARKS_FLAG_YES},
    {DEVICE_CONFIG_IEEE80211W, "ieee80211w", QUOTATION_MARKS_FLAG_NO},
    {DEVICE_CONFIG_ALLOW_PROTOCOLS, "proto", QUOTATION_MARKS_FLAG_NO},
    {DEVICE_CONFIG_GROUP_CIPHERS, "group", QUOTATION_MARKS_FLAG_NO},
    {DEVICE_CONFIG_PAIRWISE_CIPHERS, "pairwise", QUOTATION_MARKS_FLAG_NO},
    {DEVICE_CONFIG_SAE_PASSWD, "sae_password", QUOTATION_MARKS_FLAG_YES},
};

static WifiErrorNo RegisterEventCallback()
{
    LOGI("RegisterEventCallback enter");
    pthread_mutex_lock(&g_hdiCallbackMutex);
    if (g_hdiWpaStaCallbackObj == NULL) {
        pthread_mutex_unlock(&g_hdiCallbackMutex);
        LOGE("RegisterEventCallback: g_hdiWpaStaCallbackObj is NULL");
        return WIFI_IDL_OPT_FAILED;
    }

    struct IWpaInterface *wpaObj = GetWpaInterface();
    if (wpaObj == NULL) {
        pthread_mutex_unlock(&g_hdiCallbackMutex);
        LOGE("RegisterEventCallback: wpaObj is NULL");
        return WIFI_IDL_OPT_FAILED;
    }

    int32_t result = wpaObj->RegisterEventCallback(wpaObj, g_hdiWpaStaCallbackObj, "wlan0");
    if (result != HDF_SUCCESS) {
        pthread_mutex_unlock(&g_hdiCallbackMutex);
        LOGE("RegisterEventCallback: RegisterEventCallback failed result:%{public}d", result);
        return WIFI_IDL_OPT_FAILED;
    }

    pthread_mutex_unlock(&g_hdiCallbackMutex);
    LOGI("RegisterEventCallback success.");
    return WIFI_IDL_OPT_OK;
}

static WifiErrorNo UnRegisterEventCallback()
{
    LOGI("UnRegisterEventCallback enter");
    pthread_mutex_lock(&g_hdiCallbackMutex);
    if (g_hdiWpaStaCallbackObj != NULL) {
        struct IWpaInterface *wpaObj = GetWpaInterface();
        if (wpaObj == NULL) {
            pthread_mutex_unlock(&g_hdiCallbackMutex);
            LOGE("UnRegisterEventCallback: wpaObj is NULL");
            return WIFI_IDL_OPT_FAILED;
        }

        int32_t result = wpaObj->UnregisterEventCallback(wpaObj, g_hdiWpaStaCallbackObj, "wlan0");
        if (result != HDF_SUCCESS) {
            pthread_mutex_unlock(&g_hdiCallbackMutex);
            LOGE("UnRegisterEventCallback: UnregisterEventCallback failed result:%{public}d", result);
            return WIFI_IDL_OPT_FAILED;
        }

        free(g_hdiWpaStaCallbackObj);
        g_hdiWpaStaCallbackObj = NULL;
    }

    pthread_mutex_unlock(&g_hdiCallbackMutex);
    LOGI("UnRegisterEventCallback success.");
    return WIFI_IDL_OPT_OK;
}

static int CalcQuotationMarksFlag(int pos, const char value[WIFI_NETWORK_CONFIG_VALUE_LENGTH])
{
    int flag = g_wpaSsidFields[pos].flag;
    const int HEX_PSK_MAX_LEN = 64;
    int len = strlen(value);
    /* if the psk length is 64, it's hex format and don't need quotation marks */
    if (pos == DEVICE_CONFIG_PSK && len >= HEX_PSK_MAX_LEN) {
        flag = QUOTATION_MARKS_FLAG_NO;
    }
    if (pos == DEVICE_CONFIG_WEP_KEY_0 ||
        pos == DEVICE_CONFIG_WEP_KEY_1 ||
        pos == DEVICE_CONFIG_WEP_KEY_2 ||
        pos == DEVICE_CONFIG_WEP_KEY_3) {
        const int WEP_KEY_LEN1 = 5;
        const int WEP_KEY_LEN2 = 13;
        const int WEP_KEY_LEN3 = 16;
        /* For wep key, ASCII format need quotation marks, hex format is not required */
        if (len == WEP_KEY_LEN1 || len == WEP_KEY_LEN2 || len == WEP_KEY_LEN3) {
            flag = QUOTATION_MARKS_FLAG_YES;
        }
    }
    return flag;
}

static WifiErrorNo SetNetwork(int networkId, SetNetworkConfig conf)
{
    int pos = -1;
    for (unsigned i = 0; i < sizeof(g_wpaSsidFields) / sizeof(g_wpaSsidFields[0]); ++i) {
        if (g_wpaSsidFields[i].field == conf.cfgParam) {
            pos = i;
            break;
        }
    }
    if (pos < 0) {
        LOGE("SetNetwork: unsupported param: %{public}d", conf.cfgParam);
        return WIFI_IDL_OPT_INVALID_PARAM;
    }

    char tmpCfgValue[WIFI_NETWORK_CONFIG_VALUE_LENGTH] = {0};
    if (CalcQuotationMarksFlag(pos, conf.cfgValue) == QUOTATION_MARKS_FLAG_YES) {
        if (snprintf_s(tmpCfgValue, sizeof(tmpCfgValue), sizeof(tmpCfgValue) - 1, "\"%s\"", conf.cfgValue) < 0) {
            LOGE("SetNetwork: snprintf_s failed!");
            return WIFI_IDL_OPT_FAILED;
        }
        if (snprintf_s(conf.cfgValue, sizeof(conf.cfgValue), sizeof(conf.cfgValue) - 1, "%s", tmpCfgValue) < 0) {
            LOGE("SetNetwork: snprintf_s failed!");
            return WIFI_IDL_OPT_FAILED;
        }
    }

    struct IWpaInterface *wpaObj = GetWpaInterface();
    if (wpaObj == NULL) {
        LOGE("SetNetwork: wpaObj is NULL");
        return WIFI_IDL_OPT_FAILED;
    }

    int32_t result = wpaObj->SetNetwork(wpaObj, networkId, g_wpaSsidFields[pos].fieldName, conf.cfgValue);
    if (result != HDF_SUCCESS) {
        LOGE("SetNetwork: SetNetwork failed result:%{public}d", result);
        return WIFI_IDL_OPT_FAILED;
    }

    LOGI("SetNetwork success.");
    return WIFI_IDL_OPT_OK;
}

#ifndef OHOS_ARCH_LITE
static int ConvertChanToFreqMhz(int channel, int band)
{
    int BAND_FIRST_CH_NUM_24 = 1;
    int BAND_LAST_CH_NUM_24 = 14;
    int BAND_START_FREQ_MHZ_24 = 2412;
    int BAND_FIRST_CH_NUM_5 = 32;
    int BAND_LAST_CH_NUM_5 = 173;
    int BAND_START_FREQ_MHZ_5 = 5160;
    int BAND_FIRST_CH_NUM_6 = 1;
    int BAND_LAST_CH_NUM_6 = 233;
    int BAND_START_FREQ_MHZ_6 = 5955;
    int BAND_CLA_2_FREQ_136_CH_MHZ_6 = 5935;
    int BAND_24_GHZ = 1;
    int BAND_SPECIAL = 2484;
    int CHANNEL_SPECIAL = 14;
    int CHANNEL_TIMES = 5;
    int CHANNEL_TYPE = 2;

    if (band == BAND_24_GHZ) {
        if (channel == CHANNEL_SPECIAL) {
            return BAND_SPECIAL;
        } else if (channel >= BAND_FIRST_CH_NUM_24 && channel <= BAND_LAST_CH_NUM_24) {
            return ((channel - BAND_FIRST_CH_NUM_24) * CHANNEL_TIMES) + BAND_START_FREQ_MHZ_24;
        } else {
            return UNSPECIFIED;
        }
    }
    if (band == BAND_5_GHZ) {
        if (channel >= BAND_FIRST_CH_NUM_5 && channel <= BAND_LAST_CH_NUM_5) {
            return ((channel - BAND_FIRST_CH_NUM_5) * CHANNEL_TIMES) + BAND_START_FREQ_MHZ_5;
        } else {
            return UNSPECIFIED;
        }
    }
    if (band == BAND_6_GHZ) {
        if (channel >= BAND_FIRST_CH_NUM_6 && channel <= BAND_LAST_CH_NUM_6) {
            if (channel == CHANNEL_TYPE) {
                return BAND_CLA_2_FREQ_136_CH_MHZ_6;
            }
            return ((channel - BAND_FIRST_CH_NUM_6) * CHANNEL_TIMES) + BAND_START_FREQ_MHZ_6;
            } else {
                return UNSPECIFIED;
            }
    }
    return UNSPECIFIED;
}

static int GetHeChanWidth(int heChannelWidth, int centerSegFreq0, int centerSegFreq1)
{
    int CHANNEL_WIDTH = 2;
    int SEG_FREQ_VALUE = 8;
    if (heChannelWidth == 0) {
        return CHAN_WIDTH_20MHZ;
    } else if (heChannelWidth == 1) {
        return CHAN_WIDTH_40MHZ;
    } else if (heChannelWidth == CHANNEL_WIDTH) {
        return CHAN_WIDTH_80MHZ;
    } else if (abs(centerSegFreq1 - centerSegFreq0) == SEG_FREQ_VALUE) {
        return CHAN_WIDTH_160MHZ;
    } else {
        return CHAN_WIDTH_80MHZ_MHZ;
    }
}

static int GetHeCentFreq(int centerSegFreq)
{
    if (centerSegFreq == 0) {
        return 0;
    }
    return ConvertChanToFreqMhz(centerSegFreq, BAND_6_GHZ);
}

static int GetHtChanWidth(int secondOffsetChannel)
{
    if (secondOffsetChannel != 0) {
        return CHAN_WIDTH_40MHZ;
    } else {
        return CHAN_WIDTH_20MHZ;
    }
}

static int GetHtCentFreq0(int primaryFrequency, int secondOffsetChannel)
{
    int freqValue = 10;
    int offsetChannle = 3;
    if (secondOffsetChannel != 0) {
        if (secondOffsetChannel == 1) {
            return primaryFrequency + freqValue;
        } else if (secondOffsetChannel == offsetChannle) {
            return primaryFrequency - freqValue;
        } else {
            LOGE("error on get centFreq0");
            return 0;
        }
    } else {
        return primaryFrequency;
    }
}

static int GetVhtChanWidth(int channelType, int centerFrequencyIndex1, int centerFrequencyIndex2)
{
    int FREQ_VALUE = 8;
    if (channelType == 0) {
        return UNSPECIFIED;
    } else if (centerFrequencyIndex2 == 0) {
        return CHAN_WIDTH_80MHZ;
    } else if (abs(centerFrequencyIndex1 - centerFrequencyIndex2) == FREQ_VALUE) {
        return CHAN_WIDTH_160MHZ;
    } else {
        return CHAN_WIDTH_80MHZ_MHZ;
    }
}

static int GetVhtCentFreq(int channelType, int centerFrequencyIndex)
{
    if (centerFrequencyIndex == 0 || channelType == 0) {
        return 0;
    } else {
        return ConvertChanToFreqMhz(centerFrequencyIndex, BAND_5_GHZ);
    }
}

static int8_t IsValidHexCharAndConvert(char c)
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

static int HexStringToString(const char *str, char *out)
{
    unsigned len = strlen(str);
    if ((len & 1) != 0) {
        return -1;
    }
    const int hexShiftNum = 4;
    for (unsigned i = 0, j = 0; i + 1 < len; ++i) {
        int8_t high = IsValidHexCharAndConvert(str[i]);
        int8_t low = IsValidHexCharAndConvert(str[++i]);
        if (high < 0 || low < 0) {
            return -1;
        }
        char tmp = ((high << hexShiftNum) | (low & 0x0F));
        out[j] = tmp;
        ++j;
    }
    return 0;
}

static bool GetChanWidthCenterFreqVht(ScanInfo *pcmd, ScanInfoElem* infoElem)
{
    if ((pcmd == NULL) || (infoElem == NULL)) {
        LOGE("pcmd or infoElem is NULL.");
        return false;
    }
    if ((infoElem->content == NULL) || ((unsigned int)infoElem->size < VHT_INFO_SIZE)) {
        return false;
    }
    int channelType = infoElem->content[COLUMN_INDEX_ZERO] & UINT8_MASK;
    int centerFrequencyIndex1 = infoElem->content[COLUMN_INDEX_ONE] & UINT8_MASK;
    int centerFrequencyIndex2 = infoElem->content[COLUMN_INDEX_TWO] & UINT8_MASK;
    pcmd->isVhtInfoExist = 1;
    pcmd->channelWidth = GetVhtChanWidth(channelType, centerFrequencyIndex1, centerFrequencyIndex2);
    if ((unsigned int)pcmd->channelWidth == UNSPECIFIED) {
        return false;
    }
    pcmd->centerFrequency0 = GetVhtCentFreq(channelType, centerFrequencyIndex1);
    pcmd->centerFrequency1 = GetVhtCentFreq(channelType, centerFrequencyIndex2);
    return true;
}

static bool GetChanWidthCenterFreqHe(ScanInfo *pcmd, ScanInfoElem* infoElem)
{
    if ((pcmd == NULL) || (infoElem == NULL)) {
        LOGE("pcmd or iesNeedParse is NULL.");
        return false;
    }
    if ((infoElem->content == NULL) || ((unsigned int)infoElem->size < (HE_OPER_BASIC_LEN + 1))) {
        return false;
    }
    if (infoElem->content[0] != EXT_HE_OPER_EID) {
        return false;
    }
    char* content = infoElem->content + 1;
    bool isVhtInfoExist = (content[COLUMN_INDEX_ONE] & VHT_OPER_INFO_EXTST_MASK) != 0;
    bool is6GhzInfoExist = (content[COLUMN_INDEX_TWO] & GHZ_HE_INFO_EXIST_MASK_6) != 0;
    bool coHostedBssPresent = (content[COLUMN_INDEX_ONE] & BSS_EXIST_MASK) != 0;
    int expectedLen = HE_OPER_BASIC_LEN + (isVhtInfoExist ? COLUMN_INDEX_THREE : 0)
        + (coHostedBssPresent ? 1 : 0) + (is6GhzInfoExist ? COLUMN_INDEX_FIVE : 0);
    pcmd->isHeInfoExist = 1;
    if (infoElem->size < expectedLen) {
        return false;
    }
    if (is6GhzInfoExist) {
        int startIndx = VHT_OPER_INFO_BEGIN_INDEX + (isVhtInfoExist ? COLUMN_INDEX_THREE : 0)
            + (coHostedBssPresent ? 1 : 0);
        int heChannelWidth = content[startIndx + 1] & GHZ_HE_WIDTH_MASK_6;
        int centerSegFreq0 = content[startIndx + COLUMN_INDEX_TWO] & UINT8_MASK;
        int centerSegFreq1 = content[startIndx + COLUMN_INDEX_THREE] & UINT8_MASK;
        pcmd->channelWidth = GetHeChanWidth(heChannelWidth, centerSegFreq0, centerSegFreq1);
        pcmd->centerFrequency0 = GetHeCentFreq(centerSegFreq0);
        pcmd->centerFrequency1 = GetHeCentFreq(centerSegFreq1);
        return true;
    }
    if (isVhtInfoExist) {
        struct ScanInfoElem vhtInformation = {0};
        vhtInformation.id = VHT_OPER_EID;
        vhtInformation.size = VHT_INFO_SIZE;
        vhtInformation.content = content + VHT_OPER_INFO_BEGIN_INDEX;
        return GetChanWidthCenterFreqVht(pcmd, &vhtInformation);
    }
    return false;
}

static bool GetChanWidthCenterFreqHt(ScanInfo *pcmd, ScanInfoElem* infoElem)
{
    const int offsetBit = 0x3;
    if ((pcmd == NULL) || (infoElem == NULL)) {
        LOGE("pcmd or infoElem is NULL.");
        return false;
    }
    if ((infoElem->content == NULL) || ((unsigned int)infoElem->size < HT_INFO_SIZE)) {
        return false;
    }
    int secondOffsetChannel = infoElem->content[1] & offsetBit;
    pcmd->channelWidth = GetHtChanWidth(secondOffsetChannel);
    pcmd->centerFrequency0 = GetHtCentFreq0(pcmd->freq, secondOffsetChannel);
    pcmd->isHtInfoExist = 1;
    return true;
}

static bool GetChanMaxRates(ScanInfo *pcmd, ScanInfoElem* infoElem)
{
    if ((pcmd == NULL) || (infoElem == NULL)) {
        LOGE("pcmd or infoElem is NULL.");
        return false;
    }
    if ((infoElem->content == NULL) || ((unsigned int)infoElem->size < SUPP_RATES_SIZE)) {
        return false;
    }
    int maxIndex = infoElem->size - 1;
    int maxRates = infoElem->content[maxIndex] & UINT8_MASK;
    pcmd->maxRates = maxRates;
    return true;
}

static bool GetChanExtMaxRates(ScanInfo *pcmd, ScanInfoElem* infoElem)
{
    if ((pcmd == NULL) || (infoElem == NULL)) {
        LOGE("pcmd or infoElem is NULL.");
        return false;
    }
    if ((infoElem->content == NULL) || ((unsigned int)infoElem->size < EXT_SUPP_RATES_SIZE)) {
        return false;
    }
    int maxIndex = infoElem->size - 1;
    int maxRates = infoElem->content[maxIndex] & UINT8_MASK;
    pcmd->extMaxRates = maxRates;
    return true;
}

static void GetChanWidthCenterFreq(ScanInfo *pcmd, struct NeedParseIe* iesNeedParse)
{
    if ((pcmd == NULL) || (iesNeedParse == NULL)) {
        LOGE("pcmd or iesNeedParse is NULL.");
        return;
    }

    if ((iesNeedParse->ieExtern != NULL) && GetChanWidthCenterFreqHe(pcmd, iesNeedParse->ieExtern)) {
        return;
    }
    if ((iesNeedParse->ieVhtOper != NULL) && GetChanWidthCenterFreqVht(pcmd, iesNeedParse->ieVhtOper)) {
        return;
    }
    if ((iesNeedParse->ieHtOper != NULL) && GetChanWidthCenterFreqHt(pcmd, iesNeedParse->ieHtOper)) {
        return;
    }
    if ((iesNeedParse->ieMaxRate != NULL) && GetChanMaxRates(pcmd, iesNeedParse->ieMaxRate)) {
        LOGE("pcmd maxRates is %{public}d.", pcmd->maxRates);
        return;
    }
    if ((iesNeedParse->ieExtMaxRate != NULL) && GetChanExtMaxRates(pcmd, iesNeedParse->ieExtMaxRate)) {
        LOGE("pcmd extMaxRates is %{public}d.", pcmd->extMaxRates);
        return;
    }
    if (iesNeedParse->ieErp != NULL) {
        LOGE("pcmd isErpExist is true.");
        pcmd->isErpExist = 1;
        return;
    }
    LOGE("GetChanWidthCenterFreq fail.");
    return;
}

static void RecordIeNeedParse(unsigned int id, ScanInfoElem* ie, struct NeedParseIe* iesNeedParse)
{
    if (iesNeedParse == NULL) {
        return;
    }
    switch (id) {
        case EXT_EXIST_EID:
            iesNeedParse->ieExtern = ie;
            break;
        case VHT_OPER_EID:
            iesNeedParse->ieVhtOper = ie;
            break;
        case HT_OPER_EID:
            iesNeedParse->ieHtOper = ie;
            break;
        case SUPPORTED_RATES_EID:
            iesNeedParse->ieMaxRate = ie;
            break;
        case ERP_EID:
            iesNeedParse->ieErp = ie;
            break;
        case EXT_SUPPORTED_RATES_EID:
            iesNeedParse->ieExtMaxRate = ie;
            break;
        default:
            break;
    }
}

static void GetInfoElems(int length, int end, char *srcBuf, ScanInfo *pcmd)
{
    int len;
    int start = end + 1;
    int last = end + 1;
    int lenValue = 2;
    int lastLength = 3;
    int remainingLength = length - start;
    int infoElemsSize = 0;
    struct NeedParseIe iesNeedParse = {NULL};
    ScanInfoElem* infoElemsTemp = (ScanInfoElem *)calloc(MAX_INFO_ELEMS_SIZE, sizeof(ScanInfoElem));
    if (infoElemsTemp == NULL) {
        return;
    }
    while (remainingLength > 1 && start < length) {
        if (srcBuf[start] == '[') {
            ++start;
            infoElemsTemp[infoElemsSize].id = atoi(srcBuf + start);
        }
        if (srcBuf[start] != ' ') {
            ++start;
        }
        if (srcBuf[last] != ']') {
            ++last;
            continue;
        }
        len = last - start - 1;
        infoElemsTemp[infoElemsSize].size = len/lenValue;
        infoElemsTemp[infoElemsSize].content = (char *)calloc(len/lenValue+1, sizeof(char));
        if (infoElemsTemp[infoElemsSize].content == NULL) {
            break;
        }
        ++start;
        srcBuf[last] = '\0';
        HexStringToString(srcBuf + start, infoElemsTemp[infoElemsSize].content);
        if ((length - last) > lastLength) { // make sure there is no useless character
            last = last + 1;
        }
        start = last;
        remainingLength = length - last;
        RecordIeNeedParse(infoElemsTemp[infoElemsSize].id, &infoElemsTemp[infoElemsSize], &iesNeedParse);
        ++infoElemsSize;
    }
    GetChanWidthCenterFreq(pcmd, &iesNeedParse);

    // clear old infoElems first
    if (pcmd->infoElems != NULL) {
        for (int i = 0; i < pcmd->ieSize; i++) {
            if (pcmd->infoElems[i].content != NULL) {
                free(pcmd->infoElems[i].content);
                pcmd->infoElems[i].content = NULL;
            }
        }
        free(pcmd->infoElems);
        pcmd->infoElems = NULL;
    }
    pcmd->infoElems = infoElemsTemp;
    pcmd->ieSize = infoElemsSize;
    return;
}
#endif

static int DelScanInfoLine(ScanInfo *pcmd, char *srcBuf, int length)
{
    int columnIndex = 0;
    int start = 0;
    int end = 0;
    int fail = 0;
    while (end < length) {
        if (srcBuf[end] != '\t') {
            ++end;
            continue;
        }
        srcBuf[end] = '\0';
        if (columnIndex == COLUMN_INDEX_ZERO) {
            if (strcpy_s(pcmd->bssid, sizeof(pcmd->bssid), srcBuf + start) != EOK) {
                fail = 1;
                break;
            }
        } else if (columnIndex == COLUMN_INDEX_ONE) {
            pcmd->freq = atoi(srcBuf + start);
        } else if (columnIndex == COLUMN_INDEX_TWO) {
            pcmd->siglv = atoi(srcBuf + start);
        } else if (columnIndex == COLUMN_INDEX_THREE) {
            if (strcpy_s(pcmd->flags, sizeof(pcmd->flags), srcBuf + start) != EOK) {
                fail = 1;
                break;
            }
#ifdef OHOS_ARCH_LITE // The wpa of arch lite don't return "informationElements".
            start = end + 1;
            if (strcpy_s(pcmd->ssid, sizeof(pcmd->ssid), srcBuf + start) != EOK) {
                fail = 1;
                break;
            }
            start = length;
            break;
#else
        } else if (columnIndex == COLUMN_INDEX_FOUR) {
            if (strcpy_s(pcmd->ssid, sizeof(pcmd->ssid), srcBuf + start) != EOK) {
                fail = 1;
                break;
            }
            GetInfoElems(length, end, srcBuf, pcmd);
            start = length;
            break;
#endif
        }
        ++columnIndex;
        ++end;
        start = end;
    }
    if (fail == 0 && start < length) {
        if (strcpy_s(pcmd->flags, sizeof(pcmd->flags), srcBuf + start) != EOK) {
            fail = 1;
        }
    }
    return fail;
}

WifiErrorNo HdiStart()
{
    LOGI("HdiStart enter");
    if (CopyConfigFile("wpa_supplicant.conf") != WIFI_IDL_OPT_OK) {
        LOGE("HdiStart: CopyConfigFile failed!");
        return WIFI_IDL_OPT_FAILED;
    }

    if (HdiWpaStart() != WIFI_IDL_OPT_OK) {
        LOGE("HdiStart: HdiWpaStart failed!");
        return WIFI_IDL_OPT_FAILED;
    }

    if (RegisterEventCallback() != WIFI_IDL_OPT_OK) {
        LOGE("HdiStart: RegisterEventCallback failed!");
        return WIFI_IDL_OPT_FAILED;
    }

    if (HdiAddWpaIface("wlan0", CONFIG_ROOR_DIR"/wpa_supplicant/wpa_supplicant.conf") != WIFI_IDL_OPT_OK) {
        LOGE("HdiStart: HdiAddWpaIface failed!");
        return WIFI_IDL_OPT_FAILED;
    }
    
    LOGI("HdiStart success");
    return WIFI_IDL_OPT_OK;
}

WifiErrorNo HdiStop()
{
    LOGI("HdiStop enter");
    if (UnRegisterEventCallback() != WIFI_IDL_OPT_OK) {
        LOGE("HdiStop: UnRegisterEventCallback failed!");
        return WIFI_IDL_OPT_FAILED;
    }

    if (HdiRemoveWpaIface("wlan0") != WIFI_IDL_OPT_OK) {
        LOGE("HdiStop: HdiRemoveWpaIface failed!");
        return WIFI_IDL_OPT_FAILED;
    }

    if (HdiWpaStop() != WIFI_IDL_OPT_OK) {
        LOGE("HdiStop: HdiWpaStop failed!");
        return WIFI_IDL_OPT_FAILED;
    }
    
    LOGI("HdiStop success");
    return WIFI_IDL_OPT_OK;
}

WifiErrorNo HdiConnect(int networkId)
{
    LOGI("HdiConnect enter, networkId:%{public}d", networkId);
    struct IWpaInterface *wpaObj = GetWpaInterface();
    if (wpaObj == NULL) {
        LOGE("HdiConnect: wpaObj is NULL");
        return WIFI_IDL_OPT_FAILED;
    }

    int32_t result = wpaObj->SelectNetwork(wpaObj, networkId);
    if (result != HDF_SUCCESS) {
        LOGE("HdiConnect: SelectNetwork failed result:%{public}d", result);
        return WIFI_IDL_OPT_FAILED;
    }

    LOGI("HdiConnect success.");
    return WIFI_IDL_OPT_OK;
}

WifiErrorNo HdiReconnect()
{
    LOGI("HdiReconnect enter");
    struct IWpaInterface *wpaObj = GetWpaInterface();
    if (wpaObj == NULL) {
        LOGE("HdiReconnect: wpaObj is NULL");
        return WIFI_IDL_OPT_FAILED;
    }

    int32_t result = wpaObj->Reconnect(wpaObj);
    if (result != HDF_SUCCESS) {
        LOGE("HdiReconnect: Reconnect failed result:%{public}d", result);
        return WIFI_IDL_OPT_FAILED;
    }

    LOGI("HdiReconnect success.");
    return WIFI_IDL_OPT_OK;
}

WifiErrorNo HdiDisconnect()
{
    LOGI("HdiDisconnect enter");
    struct IWpaInterface *wpaObj = GetWpaInterface();
    if (wpaObj == NULL) {
        LOGE("HdiDisconnect: wpaObj is NULL");
        return WIFI_IDL_OPT_FAILED;
    }

    int32_t result = wpaObj->Disconnect(wpaObj);
    if (result != HDF_SUCCESS) {
        LOGE("HdiDisconnect: Disconnect failed result:%{public}d", result);
        return WIFI_IDL_OPT_FAILED;
    }

    LOGI("HdiDisconnect success.");
    return WIFI_IDL_OPT_OK;
}

WifiErrorNo HdiGetDeviceMacAddress(char *macAddr, int macAddrLen)
{
    LOGI("HdiGetDeviceMacAddress enter");
    if (macAddr == NULL) {
        LOGE("HdiGetDeviceMacAddress: invalid parameter!");
        return WIFI_IDL_OPT_INVALID_PARAM;
    }

    struct HdiWpaCmdStatus status;
    if (memset_s(&status, sizeof(status), 0, sizeof(status)) != EOK) {
        LOGE("HdiGetDeviceMacAddress: memset_s failed!");
        return WIFI_IDL_OPT_FAILED;
    }

    struct IWpaInterface *wpaObj = GetWpaInterface();
    if (wpaObj == NULL) {
        LOGE("HdiGetDeviceMacAddress: wpaObj is NULL");
        return WIFI_IDL_OPT_FAILED;
    }

    int32_t result = wpaObj->WifiStatus(wpaObj, &status);
    if (result != HDF_SUCCESS) {
        LOGE("HdiGetDeviceMacAddress: WifiStatus failed result:%{public}d", result);
        return WIFI_IDL_OPT_FAILED;
    }

    if (macAddrLen < status.addressLen) {
        LOGE("Input mac length %{public}d is little than mac address length %{public}d", macAddrLen, status.addressLen);
        return WIFI_IDL_OPT_BUFFER_TOO_LITTLE;
    }

    if (strncpy_s(macAddr, macAddrLen, (const char *)status.address, status.addressLen) != EOK) {
        LOGE("HdiGetDeviceMacAddress: strncpy_s failed!");
        return WIFI_IDL_OPT_FAILED;
    }

    LOGI("HdiGetDeviceMacAddress success.");
    return WIFI_IDL_OPT_OK;
}

WifiErrorNo HdiScan()
{
    LOGI("HdiScan enter");
    struct IWpaInterface *wpaObj = GetWpaInterface();
    if (wpaObj == NULL) {
        LOGE("HdiScan: wpaObj is NULL");
        return WIFI_IDL_OPT_FAILED;
    }

    int32_t result = wpaObj->Scan(wpaObj);
    if (result != HDF_SUCCESS) {
        LOGE("HdiScan: Scan failed result:%{public}d", result);
        return WIFI_IDL_OPT_FAILED;
    }

    LOGI("HdiScan success.");
    return WIFI_IDL_OPT_OK;
}

ScanInfo *HdiGetScanInfos(int *size)
{
    LOGI("HdiGetScanInfos enter");
    if (size == NULL) {
        LOGE("HdiGetScanInfos: invalid parameter!");
        return NULL;
    }

    ScanInfo *results = NULL;
    if (*size > 0) {
        results = (ScanInfo *)calloc(*size, sizeof(ScanInfo));
    }
    if (results == NULL) {
        LOGE("HdiGetScanInfos: calloc scanInfo failed!");
        return NULL;
    }

    unsigned int resultBuffLen = REPLY_BUF_LENGTH;
    unsigned char *resultBuff = (unsigned char *)calloc(resultBuffLen, sizeof(unsigned char));
    if (resultBuff == NULL) {
        free(results);
        LOGE("HdiGetScanInfos: calloc failed!");
        return NULL;
    }

    struct IWpaInterface *wpaObj = GetWpaInterface();
    if (wpaObj == NULL) {
        free(results);
        free(resultBuff);
        LOGE("HdiGetScanInfos: wpaObj is NULL");
        return NULL;
    }

    int32_t result = wpaObj->ScanResult(wpaObj, resultBuff, &resultBuffLen);
    if (result != HDF_SUCCESS) {
        free(results);
        free(resultBuff);
        LOGE("HdiGetScanInfos: ScanResult failed result:%{public}d", result);
        return NULL;
    }

    char *savedPtr = NULL;
    strtok_r((char *)resultBuff, "\n", &savedPtr);
    char *token = strtok_r(NULL, "\n", &savedPtr);
    int j = 0;
    while (token != NULL) {
        if (j >= *size) {
            *size = j;
            LOGE("HdiGetScanInfos: get scan info full!");
            free(results);
            free(resultBuff);
            return NULL;
        }
        int length = strlen(token);
        if (length <= 0) {
            break;
        }
        if (DelScanInfoLine(&results[j], token, length)) {
            LOGE("HdiGetScanInfos: parse scan results line failed!");
            break;
        }
        LOGI("-->>%{public}2d %{private}s %{private}s %{public}d %{public}d %{public}d %{public}d %{public}d %{public}d \
         %{public}d %{public}d %{public}d %{public}d %{public}d",
             j, results[j].ssid, results[j].bssid, results[j].freq, results[j].siglv,
             results[j].centerFrequency0, results[j].centerFrequency1, results[j].channelWidth,
             results[j].isVhtInfoExist, results[j].isHtInfoExist, results[j].isHeInfoExist, results[j].isErpExist,
             results[j].maxRates, results[j].extMaxRates);
        token = strtok_r(NULL, "\n", &savedPtr);
        j++;
    }

    *size = j;
    free(resultBuff);
    LOGI("HdiGetScanInfos success.");
    return results;
}

WifiErrorNo HdiRemoveNetwork(int networkId)
{
    LOGI("HdiRemoveNetwork enter, networkId:%{public}d", networkId);
    struct IWpaInterface *wpaObj = GetWpaInterface();
    if (wpaObj == NULL) {
        LOGE("HdiRemoveNetwork: wpaObj is NULL");
        return WIFI_IDL_OPT_FAILED;
    }

    int32_t result = wpaObj->RemoveNetwork(wpaObj, networkId);
    if (result != HDF_SUCCESS) {
        LOGE("HdiRemoveNetwork: RemoveNetwork failed result:%{public}d", result);
        return WIFI_IDL_OPT_FAILED;
    }

    LOGI("HdiRemoveNetwork success.");
    return WIFI_IDL_OPT_OK;
}

WifiErrorNo HdiAddNetwork(int *networkId)
{
    LOGI("HdiAddNetwork enter");
    if (networkId == NULL) {
        LOGE("HdiAddNetwork: invalid parameter!");
        return WIFI_IDL_OPT_INVALID_PARAM;
    }

    struct IWpaInterface *wpaObj = GetWpaInterface();
    if (wpaObj == NULL) {
        LOGE("HdiAddNetwork: wpaObj is NULL");
        return WIFI_IDL_OPT_FAILED;
    }

    int32_t result = wpaObj->AddNetwork(wpaObj, networkId);
    if (result != HDF_SUCCESS) {
        LOGE("HdiAddNetwork: AddNetwork failed result:%{public}d", result);
        return WIFI_IDL_OPT_FAILED;
    }

    LOGI("HdiAddNetwork success, networkId:%{public}d", *networkId);
    return WIFI_IDL_OPT_OK;
}

WifiErrorNo HdiEnableNetwork(int networkId)
{
    LOGI("HdiEnableNetwork enter, networkId:%{public}d", networkId);
    struct IWpaInterface *wpaObj = GetWpaInterface();
    if (wpaObj == NULL) {
        LOGE("HdiEnableNetwork: wpaObj is NULL");
        return WIFI_IDL_OPT_FAILED;
    }

    int32_t result = wpaObj->EnableNetwork(wpaObj, networkId);
    if (result != HDF_SUCCESS) {
        LOGE("HdiEnableNetwork: EnableNetwork failed result:%{public}d", result);
        return WIFI_IDL_OPT_FAILED;
    }

    LOGI("HdiEnableNetwork success.");
    return WIFI_IDL_OPT_OK;
}

WifiErrorNo HdiDisableNetwork(int networkId)
{
    LOGI("HdiDisableNetwork enter, networkId:%{public}d", networkId);
    struct IWpaInterface *wpaObj = GetWpaInterface();
    if (wpaObj == NULL) {
        LOGE("HdiDisableNetwork: wpaObj is NULL");
        return WIFI_IDL_OPT_FAILED;
    }

    int32_t result = wpaObj->DisableNetwork(wpaObj, networkId);
    if (result != HDF_SUCCESS) {
        LOGE("HdiDisableNetwork: DisableNetwork failed result:%{public}d", result);
        return WIFI_IDL_OPT_FAILED;
    }

    LOGI("HdiDisableNetwork success.");
    return WIFI_IDL_OPT_OK;
}

WifiErrorNo HdiSetNetwork(int networkId, SetNetworkConfig *confs, int size)
{
    LOGI("HdiSetNetwork enter");
    if (confs == NULL) {
        LOGE("HdiSetNetwork: invalid parameter!");
        return WIFI_IDL_OPT_INVALID_PARAM;
    }

    for (int i = 0; i < size; ++i) {
        SetNetwork(networkId, confs[i]);
    }

    return WIFI_IDL_OPT_OK;
}

WifiErrorNo HdiSaveConfig()
{
    LOGI("HdiSaveConfig enter");
    struct IWpaInterface *wpaObj = GetWpaInterface();
    if (wpaObj == NULL) {
        LOGE("HdiSaveConfig: wpaObj is NULL");
        return WIFI_IDL_OPT_FAILED;
    }

    int32_t result = wpaObj->SaveConfig(wpaObj);
    if (result != HDF_SUCCESS) {
        LOGE("HdiSaveConfig: SaveConfig failed result:%{public}d", result);
        return WIFI_IDL_OPT_FAILED;
    }

    LOGI("HdiSaveConfig success.");
    return WIFI_IDL_OPT_OK;
}

WifiErrorNo RegisterHdiWpaStaEventCallback(struct IWpaCallback *callback)
{
    LOGI("RegisterHdiWpaStaEventCallback enter");
    pthread_mutex_lock(&g_hdiCallbackMutex);
    if (callback == NULL || callback->OnEventConnected == NULL) {
        pthread_mutex_unlock(&g_hdiCallbackMutex);
        LOGE("RegisterHdiWpaStaEventCallback: invalid parameter!");
        return WIFI_IDL_OPT_INVALID_PARAM;
    }

    if (g_hdiWpaStaCallbackObj != NULL) {
        pthread_mutex_unlock(&g_hdiCallbackMutex);
        LOGI("RegisterHdiWpaStaEventCallback: already register!");
        return WIFI_IDL_OPT_OK;
    }

    g_hdiWpaStaCallbackObj = (struct IWpaCallback *)malloc(sizeof(struct IWpaCallback ));
    if (g_hdiWpaStaCallbackObj == NULL) {
        pthread_mutex_unlock(&g_hdiCallbackMutex);
        LOGE("RegisterHdiWpaStaEventCallback: IWpaCallback malloc failed!");
        return WIFI_IDL_OPT_FAILED;
    }

    g_hdiWpaStaCallbackObj->OnEventDisconnected = callback->OnEventDisconnected;
    g_hdiWpaStaCallbackObj->OnEventConnected = callback->OnEventConnected;
    g_hdiWpaStaCallbackObj->OnEventBssidChanged = callback->OnEventBssidChanged;
    g_hdiWpaStaCallbackObj->OnEventStateChanged = callback->OnEventStateChanged;
    g_hdiWpaStaCallbackObj->OnEventTempDisabled = callback->OnEventTempDisabled;
    g_hdiWpaStaCallbackObj->OnEventAssociateReject = callback->OnEventAssociateReject;
    g_hdiWpaStaCallbackObj->OnEventWpsOverlap = callback->OnEventWpsOverlap;
    g_hdiWpaStaCallbackObj->OnEventWpsTimeout = callback->OnEventWpsTimeout;
    g_hdiWpaStaCallbackObj->OnEventScanResult = callback->OnEventScanResult;
    g_hdiWpaStaCallbackObj->GetVersion = NULL;
    g_hdiWpaStaCallbackObj->AsObject = NULL;

    pthread_mutex_unlock(&g_hdiCallbackMutex);
    LOGI("RegisterHdiWpaStaEventCallback3 success.");
    return WIFI_IDL_OPT_OK;
}

WifiErrorNo HdiStartWpsPbcMode(WifiWpsParam *config)
{
    LOGI("HdiStartWpsPbcMode enter");
    if (config == NULL) {
        LOGE("HdiStartWpsPbcMode: invalid parameter!");
        return WIFI_IDL_OPT_INVALID_PARAM;
    }

    struct HdiWifiWpsParam wpsParam = {0};
    wpsParam.anyFlag = config->anyFlag;
    wpsParam.multiAp = config->multiAp;
    wpsParam.bssid = (uint8_t *)config->bssid;
    wpsParam.bssidLen = strlen(config->bssid);
    
    struct IWpaInterface *wpaObj = GetWpaInterface();
    if (wpaObj == NULL) {
        LOGE("HdiStartWpsPbcMode: wpaObj is NULL");
        return WIFI_IDL_OPT_FAILED;
    }

    int32_t result = wpaObj->WpsPbcMode(wpaObj, &wpsParam);
    if (result != HDF_SUCCESS) {
        LOGE("HdiStartWpsPbcMode: WpsPbcMode failed result:%{public}d", result);
        return WIFI_IDL_OPT_FAILED;
    }

    LOGI("HdiStartWpsPbcMode success.");
    return WIFI_IDL_OPT_OK;
}

WifiErrorNo HdiStartWpsPinMode(WifiWpsParam *config, int *pinCode)
{
    LOGI("HdiStartWpsPinMode enter");
    if (config == NULL || pinCode == NULL) {
        LOGE("HdiStartWpsPinMode: invalid parameter!");
        return WIFI_IDL_OPT_INVALID_PARAM;
    }

    struct HdiWifiWpsParam wpsParam = {0};
    wpsParam.anyFlag = config->anyFlag;
    wpsParam.multiAp = config->multiAp;
    wpsParam.bssid = (uint8_t *)config->bssid;
    wpsParam.bssidLen = strlen(config->bssid);
    wpsParam.pinCode = (uint8_t *)config->pinCode;
    wpsParam.pinCodeLen = strlen(config->pinCode);
    
    struct IWpaInterface *wpaObj = GetWpaInterface();
    if (wpaObj == NULL) {
        LOGE("HdiStartWpsPinMode: wpaObj is NULL");
        return WIFI_IDL_OPT_FAILED;
    }

    int32_t result = wpaObj->WpsPinMode(wpaObj, &wpsParam, pinCode);
    if (result != HDF_SUCCESS) {
        LOGE("HdiStartWpsPinMode: WpsPbcMode failed result:%{public}d", result);
        return WIFI_IDL_OPT_FAILED;
    }

    LOGI("HdiStartWpsPinMode success.");
    return WIFI_IDL_OPT_OK;
}

WifiErrorNo HdiStopWps()
{
    LOGI("HdiStopWps enter");
    struct IWpaInterface *wpaObj = GetWpaInterface();
    if (wpaObj == NULL) {
        LOGE("HdiStopWps: wpaObj is NULL");
        return WIFI_IDL_OPT_FAILED;
    }

    int32_t result = wpaObj->WpsCancel(wpaObj);
    if (result != HDF_SUCCESS) {
        LOGE("HdiStopWps: WpsCancel failed result:%{public}d", result);
        return WIFI_IDL_OPT_FAILED;
    }

    LOGI("HdiStopWps success.");
    return WIFI_IDL_OPT_OK;
}

WifiErrorNo HdiWpaAutoConnect(int enable)
{
    LOGI("HdiWpaAutoConnect enter, enable:%{public}d", enable);
    struct IWpaInterface *wpaObj = GetWpaInterface();
    if (wpaObj == NULL) {
        LOGE("HdiWpaAutoConnect: wpaObj is NULL");
        return WIFI_IDL_OPT_FAILED;
    }

    int32_t result = wpaObj->AutoConnect(wpaObj, enable);
    if (result != HDF_SUCCESS) {
        LOGE("HdiWpaAutoConnect: AutoConnect failed result:%{public}d", result);
        return WIFI_IDL_OPT_FAILED;
    }

    LOGI("HdiWpaAutoConnect success.");
    return WIFI_IDL_OPT_OK;
}

WifiErrorNo HdiWpaBlocklistClear()
{
    LOGI("HdiWpaBlocklistClear enter");
    struct IWpaInterface *wpaObj = GetWpaInterface();
    if (wpaObj == NULL) {
        LOGE("HdiWpaBlocklistClear: wpaObj is NULL");
        return WIFI_IDL_OPT_FAILED;
    }

    int32_t result = wpaObj->BlocklistClear(wpaObj);
    if (result != HDF_SUCCESS) {
        LOGE("HdiWpaBlocklistClear: BlocklistClear failed result:%{public}d", result);
        return WIFI_IDL_OPT_FAILED;
    }

    LOGI("HdiWpaBlocklistClear success.");
    return WIFI_IDL_OPT_OK;
}

WifiErrorNo HdiSetPowerSave(int enable)
{
    LOGI("HdiSetPowerSave enter, enable:%{public}d", enable);
    struct IWpaInterface *wpaObj = GetWpaInterface();
    if (wpaObj == NULL) {
        LOGE("HdiSetPowerSave: wpaObj is NULL");
        return WIFI_IDL_OPT_FAILED;
    }

    int32_t result = wpaObj->SetPowerSave(wpaObj, enable);
    if (result != HDF_SUCCESS) {
        LOGE("HdiSetPowerSave: SetPowerSave failed result:%{public}d", result);
        return WIFI_IDL_OPT_FAILED;
    }

    LOGI("HdiSetPowerSave success.");
    return WIFI_IDL_OPT_OK;
}

WifiErrorNo HdiWpaSetCountryCode(const char *countryCode)
{
    LOGI("HdiWpaSetCountryCode enter, enable:%{public}s", countryCode);
    struct IWpaInterface *wpaObj = GetWpaInterface();
    if (wpaObj == NULL) {
        LOGE("HdiWpaSetCountryCode: wpaObj is NULL");
        return WIFI_IDL_OPT_FAILED;
    }

    int32_t result = wpaObj->SetCountryCode(wpaObj, countryCode);
    if (result != HDF_SUCCESS) {
        LOGE("HdiWpaSetCountryCode: SetCountryCode failed result:%{public}d", result);
        return WIFI_IDL_OPT_FAILED;
    }

    LOGI("HdiWpaSetCountryCode success.");
    return WIFI_IDL_OPT_OK;
}

WifiErrorNo HdiWpaSetSuspendMode(int mode)
{
    LOGI("HdiWpaSetSuspendMode enter, mode:%{public}d", mode);
    struct IWpaInterface *wpaObj = GetWpaInterface();
    if (wpaObj == NULL) {
        LOGE("HdiWpaSetSuspendMode: wpaObj is NULL");
        return WIFI_IDL_OPT_FAILED;
    }

    int32_t result = wpaObj->SetSuspendMode(wpaObj, mode);
    if (result != HDF_SUCCESS) {
        LOGE("HdiWpaSetSuspendMode: SetSuspendMode failed result:%{public}d", result);
        return WIFI_IDL_OPT_FAILED;
    }

    LOGI("HdiWpaSetSuspendMode success.");
    return WIFI_IDL_OPT_OK;
}
#endif