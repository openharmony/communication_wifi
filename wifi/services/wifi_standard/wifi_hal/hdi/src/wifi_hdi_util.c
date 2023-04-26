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

#include "securec.h"
#include "wifi_common_def.h"
#include "wifi_log.h"
#include "wifi_hdi_util.h"

#undef LOG_TAG
#define LOG_TAG "WifiHdiUtil"

static int HdiParseExtensionInfo(const uint8_t *pos, size_t elen,
                      struct HdiElems *elems,
                      int show_errors)
{
    uint8_t ext_id;

    if (elen < 1) {
        if (show_errors) {
            LOGI("short information HdiElem (Ext)");
        }
        return -1;
    }

    ext_id = *pos++;
    elen--;

    switch (ext_id) {
        case HDI_EID_EXT_ASSOC_DELAY_INFO:
            if (elen != 1)
                break;
            elems->assocDelayInfo = pos;
            break;
        case HDI_EID_EXT_FILS_REQ_PARAMS:
            if (elen < HDI_POS_THIRD)
                break;
            elems->filsReqParams = pos;
            elems->filsReqParamsLen = elen;
            break;
        case HDI_EID_EXT_FILS_KEY_CONFIRM:
            elems->filsKeyConfirm = pos;
            elems->filsKeyConfirmLen = elen;
            break;
        case HDI_EID_EXT_FILS_SESSION:
            if (elen != HDI_FILS_SESSION_LEN)
                break;
            elems->filsSession = pos;
            break;
        case HDI_EID_EXT_FILS_HLP_CONTAINER:
            if (elen < HDI_POS_SECOND * ETH_ALEN)
                break;
            elems->filsHlp = pos;
            elems->filsHlpLen = elen;
            break;
        case HDI_EID_EXT_FILS_IP_ADDR_ASSIGN:
            if (elen < 1)
                break;
            elems->addrAssign = pos;
            elems->filsIpAddrAssignLen = elen;
            break;
        case HDI_EID_EXT_KEY_DELIVERY:
            if (elen < HDI_KEY_RSC_LEN)
                break;
            elems->delivery = pos;
            elems->keyDeliveryLen = elen;
            break;
        case HDI_EID_EXT_FILS_WRAPPED_DATA:
            elems->wrappedData = pos;
            elems->filWrappedDataLen = elen;
            break;
        case HDI_EID_EXT_FILS_PUBLIC_KEY:
            if (elen < 1)
                break;
            elems->filsPk = pos;
            elems->filsPkLen = elen;
            break;
        case HDI_EID_EXT_FILS_NONCE:
            if (elen != HDI_FILS_NONCE_LEN)
                break;
            elems->filsNonce = pos;
            break;
        case HDI_EID_EXT_OWE_DH_PARAM:
            if (elen < HDI_POS_SECOND)
                break;
            elems->oweDh = pos;
            elems->oweDhLen = elen;
            break;
        case HDI_EID_EXT_PASSWORD_IDENTIFIER:
            elems->passwordId = pos;
            elems->passwordIdLen = elen;
            break;
        case HDI_EID_EXT_HE_CAPABILITIES:
            elems->heCapabilities = pos;
            elems->heCapabilitiesLen = elen;
            break;
        case HDI_EID_EXT_HE_OPERATION:
            elems->heOperation = pos;
            elems->heOperationLen = elen;
            break;
        case HDI_EID_EXT_OCV_OCI:
            elems->oci = pos;
            elems->ociLen = elen;
            break;
        default:
            return -1;
    }
    return 0;
}

static int HdiParseVendorSpec(const uint8_t *pos, size_t elen,
                        struct HdiElems *elems,
                        int show_errors)
{
    unsigned int oui;

    /* first 3 bytes in vendor specific information HdiElem are the IEEE
     * OUI of the vendor. The following byte is used a vendor specific
     * sub-type. */
    if (elen < HDI_POS_FOURTH) {
        if (show_errors) {
            LOGI("short vendor specific "
                   "information HdiElem ignored (len=%{public}lu)",
                   (unsigned long) elen);
        }
        return -1;
    }

    oui = HdiGetBe24(pos);
    switch (oui) {
        case HDI_OUI_MICROSOFT:
            /* Microsoft/Wi-Fi information elements are further typed and
            * subtyped */
            switch (pos[HDI_POS_THIRD]) {
                case 1:
                    /* Microsoft OUI (00:50:F2) with OUI Type 1:
                    * real WPA information HdiElem */
                    elems->hdiIe = pos;
                    elems->wpaIeLen = elen;
                    break;
                case HDI_WMM_OUI_TYPE:
                    /* WMM information HdiElem */
                    if (elen < HDI_POS_FIVE) {
                        LOGI("short WMM information HdiElem ignored (len=%{public}lu)",
                            (unsigned long) elen);
                        return -1;
                    }
                    switch (pos[HDI_POS_FOURTH]) {
                        case HDI_WMM_OUI_SUBTYPE_INFORMATION:
                        case HDI_WMM_OUI_SUBTYPE_PARAMETER:
                            /*
                            * Share same pointer since only one of these
                            * is used and they start with same data.
                            * Length field can be used to distinguish the
                            * IEs.
                            */
                            elems->wmm = pos;
                            elems->wmmLen = elen;
                            break;
                        case HDI_WMM_OUI_SUBTYPE_ELEMENT:
                            elems->wmmTspec = pos;
                            elems->wmmTspecLen = elen;
                            break;
                        default:
                            return -1;
                    }
                    break;
                case HDI_POS_FOURTH:
                    /* Wi-Fi Protected Setup (WPS) IE */
                    elems->wpsIe = pos;
                    elems->hdiIeLen = elen;
                    break;
                default:
                    return -1;
            }
            break;

        case HDI_OUI_WFA:
            switch (pos[HDI_POS_THIRD]) {
                case HDI_P2P_OUI_TYPE:
                    /* Wi-Fi Alliance - P2P IE */
                    elems->p2p = pos;
                    elems->p2pLen = elen;
                    break;
                case HDI_WFD_TYPE:
                    /* Wi-Fi Alliance - WFD IE */
                    elems->wfd = pos;
                    elems->wfdLen = elen;
                    break;
                case HDI_HS20_INDICATION_OUI_TYPE:
                    /* Hotspot 2.0 */
                    elems->hs20 = pos;
                    elems->hs20Len = elen;
                    break;
                case HDI_HS20_OSEN_OUI_TYPE:
                    /* Hotspot 2.0 OSEN */
                    elems->osen = pos;
                    elems->osenLen = elen;
                    break;
                case HDI_MBO_OUI_TYPE:
                    /* MBO-OCE */
                    elems->mbo = pos;
                    elems->mboLen = elen;
                    break;
                case HDI_HS20_ROAMING_CONS_SEL_OUI_TYPE:
                    /* Hotspot 2.0 Roaming Consortium Selection */
                    elems->roamingConsSel = pos;
                    elems->roamingConsSelLen = elen;
                    break;
                case HDI_AP_OUI_TYPE:
                    elems->multiAp = pos;
                    elems->multiApLen = elen;
                    break;
                default:
                    return -1;
            }
            break;

        case HDI_OUI_BROADCOM:
            switch (pos[HDI_POS_THIRD]) {
                case HDI_HT_CAPAB_OUI_TYPE:
                    elems->vendorHtCap = pos;
                    elems->vendorHtCapLen = elen;
                    break;
                case HDI_VHT_TYPE:
                    if (elen > HDI_POS_FOURTH &&
                        (pos[HDI_POS_FOURTH] == HDI_VHT_SUBTYPE ||
                        pos[HDI_POS_FOURTH] == HDI_VHT_SUBTYPE2)) {
                        elems->vendorVht = pos;
                        elems->vendorVhtLen = elen;
                    } else
                        return -1;
                    break;
                default:
                    return -1;
            }
            break;

        case HDI_OUI_QCA:
            switch (pos[HDI_POS_THIRD]) {
                case HDI_VENDOR_ELEM_P2P_PREF_CHAN_LIST:
                    elems->prefFreqList = pos;
                    elems->prefFreqListLen = elen;
                    break;
                default:
                    LOGI("Unknown QCA information HdiElem ignored (type=%{public}d len=%{public}lu)",
                        pos[HDI_POS_THIRD], (unsigned long) elen);
                    return -1;
            }
            break;

        default:
            return -1;
    }

    return 0;
}

int HdiCheckExtCap(const uint8_t *ie, unsigned int capab)
{
    if (!ie || ie[1] <= capab / HDI_POS_EIGHT) {
        return 0;
    }
    return !!(ie[HDI_POS_SECOND + capab / HDI_POS_EIGHT] & HDI_BIT(capab % HDI_POS_EIGHT));
}

int HdiCheckBssExtCap(const uint8_t *ies, size_t len, unsigned int capab)
{
    return HdiCheckExtCap(HdiBssGetIe(ies, len, HDI_EID_EXT_CAPAB),
                    capab);
}

int Get80211ElemsFromIE(const uint8_t *start, size_t len, struct HdiElems *elems,
    int show)
{
    const struct HdiElem *elem;
    int unknown = 0;

    (void)memset_s(elems, sizeof(*elems), 0, sizeof(*elems));

    if (!start) {
        return 0;
    }

    HDI_CHECK_ELEMENT(elem, start, len) {
        uint8_t id = elem->id, elen = elem->datalen;
        const uint8_t *pos = elem->data;

        switch (id) {
            case HDI_EID_SSID:
                if (elen > SSID_MAX_LEN) {
                    LOGI("Ignored too long SSID HdiElem (elen=%{public}u)", elen);
                    break;
                }
                elems->ssid = pos;
                elems->ssidLen = elen;
                break;
            case HDI_EID_SUPP_RATES:
                elems->suppRates = pos;
                elems->ratesLen = elen;
                break;
            case HDI_EID_DS_PARAMS:
                if (elen < 1) {
                    break;
                }
                elems->dsParams = pos;
                break;
            case HDI_EID_CF_PARAMS:
            case HDI_EID_TIM:
                break;
            case HDI_EID_CHALLENGE:
                elems->challenge = pos;
                elems->challengeLen = elen;
                break;
            case HDI_EID_ERP_INFO:
                if (elen < 1) {
                    break;
                }
                elems->erpInfo = pos;
                break;
            case HDI_EID_EXT_SUPP_RATES:
                elems->extSuppRates = pos;
                elems->suppRatesLlen = elen;
                break;
            case HDI_EID_VENDOR_SPECIFIC:
                if (HdiParseVendorSpec(pos, elen, elems, show)) {
                    unknown++;
                }
                break;
            case HDI_EID_RSN:
                elems->rsnIe = pos;
                elems->rsnIeLen = elen;
                break;
            case HDI_EID_PWR_CAPABILITY:
                if (elen < HDI_POS_SECOND) {
                    break;
                }
                elems->powerCapab = pos;
                elems->powerCapabLen = elen;
                break;
            case HDI_EID_SUPPORTED_CHANNELS:
                elems->hdiChannels = pos;
                elems->channelsLen = elen;
                break;
            case HDI_EID_MOBILITY_DOMAIN:
                if (elen < sizeof(struct HdiMdie)) {
                    break;
                }
                elems->mdie = pos;
                elems->mdieLen = elen;
                break;
            case HDI_EID_FAST_BSS_TRANSITION:
                if (elen < sizeof(struct HdiFtie)) {
                    break;
                }
                elems->ftie = pos;
                elems->ftieLen = elen;
                break;
            case HDI_EID_TIMEOUT_INTERVAL:
                if (elen != HDI_POS_FIVE)
                    break;
                elems->timeout = pos;
                break;
            case HDI_EID_HT_CAP:
                if (elen < sizeof(struct HdiHtCapabilities)) {
                    break;
                }
                elems->htCapabilities = pos;
                break;
            case HDI_EID_HT_OPERATION:
                if (elen < sizeof(struct HdiHtOperation)) {
                    break;
                }
                elems->htOperation = pos;
                break;
            case HDI_EID_MESH_CONFIG:
                elems->meshCfg = pos;
                elems->meshConfigLen = elen;
                break;
            case HDI_EID_MESH_ID:
                elems->meshId = pos;
                elems->meshIdLen = elen;
                break;
            case HDI_EID_PEER_MGMT:
                elems->peerMgmt = pos;
                elems->peerMgmtLen = elen;
                break;
            case HDI_EID_VHT_CAP:
                if (elen < sizeof(struct HdiVhtCapabilities)) {
                    break;
                }
                elems->vhtCapabilities = pos;
                break;
            case HDI_EID_VHT_OPERATION:
                if (elen < sizeof(struct HdiVhtOperation)) {
                    break;
                }
                elems->vhtOperation = pos;
                break;
            case HDI_EID_VHT_OPERATING_MODE_NOTIFICATION:
                if (elen != 1) {
                    break;
                }
                elems->vhtOpmodeNotif = pos;
                break;
            case HDI_EID_LINK_ID:
                if (elen < HDI_POS_ET) {
                    break;
                }
                elems->linkId = pos;
                break;
            case HDI_EID_INTERWORKING:
                elems->interworking = pos;
                elems->interworkingLen = elen;
                break;
            case HDI_EID_QOS_MAP_SET:
                if (elen < HDI_POS_OT) {
                    break;
                }
                elems->mapSet = pos;
                elems->qosMapSetLen = elen;
                break;
            case HDI_EID_EXT_CAPAB:
                elems->extCapab = pos;
                elems->extCapabLen = elen;
                break;
            case HDI_EID_BSS_MAX_IDLE_PERIOD:
                if (elen < HDI_POS_THIRD) {
                    break;
                }
                elems->maxIdlePeriod = pos;
                break;
            case HDI_EID_SSID_LIST:
                elems->ssidList = pos;
                elems->ssidListLen = elen;
                break;
            case HDI_EID_AMPE:
                elems->ampe = pos;
                elems->ampeLen = elen;
                break;
            case HDI_EID_MIC:
                elems->mic = pos;
                elems->micLen = elen;
                /* after mic everything is encrypted, so stop. */
                goto done;
            case HDI_EID_MULTI_BAND:
                if (elems->hdiIes.nofIes >= HDI_MAX_IES_SUPPORTED) {
                    LOGI("IEEE 802.11 HdiElem parse ignored MB IE (id=%{public}d elen=%{public}d)",
                        id, elen);
                    break;
                }

                elems->hdiIes.ies[elems->hdiIes.nofIes].ie = pos;
                elems->hdiIes.ies[elems->hdiIes.nofIes].ieLen = elen;
                elems->hdiIes.nofIes++;
                break;
            case HDI_EID_SUPPORTED_OPERATING_CLASSES:
                elems->opClasses = pos;
                elems->suppOpClassesLen = elen;
                break;
            case HDI_EID_RRM_ENABLED_CAPABILITIES:
                elems->rrmEnabled = pos;
                elems->rrmEnabledLen = elen;
                break;
            case HDI_EID_CAG_NUMBER:
                elems->cagNumber = pos;
                elems->cagNumberLen = elen;
                break;
            case HDI_EID_AP_CSN:
                if (elen < 1) {
                    break;
                }
                elems->apCsn = pos;
                break;
            case HDI_EID_FILS_INDICATION:
                if (elen < HDI_POS_SECOND) {
                    break;
                }
                elems->filsIndic = pos;
                elems->filsIndicLen = elen;
                break;
            case HDI_EID_DILS:
                if (elen < HDI_POS_SECOND) {
                    break;
                }
                elems->dils = pos;
                elems->dilsLen = elen;
                break;
            case HDI_EID_FRAGMENT:
                break;
            case HDI_EID_EXTENSION:
                if (HdiParseExtensionInfo(pos, elen, elems, show)) {
                    unknown++;
                }
                break;
            default:
                unknown++;
                if (!show) {
                    break;
                }
                break;
        }
    }

    if (!HdiCheckCompleted(elem, start, len)) {
        if (show) {
            LOGI("IEEE 802.11 HdiElem parse failed @%{public}d",
                   (int) (start + len - (const uint8_t *) elem));
        }
        return -1;
    }

done:
    return unknown ? 1 : 0;
}

bool HdiGetRsnCapabLen(const uint8_t *rsnxe, size_t rsnxe_len,
                   unsigned int capab)
{
    const uint8_t *end;
    size_t flen, i;
    uint32_t capabs = 0;

    if (!rsnxe || rsnxe_len == 0) {
        return false;
    }
    end = rsnxe + rsnxe_len;
    flen = (rsnxe[0] & 0x0f) + 1;
    if (rsnxe + flen > end) {
        return false;
    }
    if (flen > HDI_POS_FOURTH) {
        flen = HDI_POS_FOURTH;
    }
    for (i = 0; i < flen; i++) {
        capabs |= rsnxe[i] << (HDI_POS_EIGHT * i);
    }

    return capabs & HDI_BIT(capab);
}

bool HdiGetRsnCapab(const uint8_t *rsnxe, unsigned int capab)
{
    return HdiGetRsnCapabLen(rsnxe ? rsnxe + HDI_POS_SECOND : NULL,
                     rsnxe ? rsnxe[1] : 0, capab);
}

static inline int HdiCheckIsDmg(const int freq)
{
    return freq > HDI_POS_DMG;
}

/* Format one result on one text line into a buffer. */
int GetScanResultText(const struct HdfWifiScanResultExt *scanResult,
    struct HdiElems *elems, char* buf, int bufLen)
{
    char *pos, *end;
    int ret;
    const uint8_t *ie, *ie2, *osen_ie, *p2p, *mesh, *owe, *rsnxe;
    const uint8_t *infoEle;

    mesh = HdiBssGetIe(scanResult->ie, scanResult->ieLen, HDI_EID_MESH_ID);
    p2p = HdiBssGetVendorIe(scanResult->ie, scanResult->ieLen, HDI_P2P_IE_VENDOR_TYPE);
    if (!p2p)
        p2p = HdiBssGetVendorBeacon(scanResult->ie, scanResult->ieLen,
            scanResult->beaconIeLen, HDI_P2P_IE_VENDOR_TYPE);
    if (p2p && elems->ssidLen == HDI_P2P_CARD_SSID_LEN && 
        memcmp(elems->ssid, HDI_P2P_CARD_SSID, HDI_P2P_CARD_SSID_LEN) == 0) {
        return 0;
    }

    pos = buf;
    end = buf + bufLen;

    ret = HdiTxtPrintf(pos, end - pos, MACSTR "\t%d\t%d\t",
              MAC2STR(scanResult->bssid), scanResult->freq, scanResult->level);
    if (HdiCheckError(end - pos, ret)) {
        return -1;
    }
    pos += ret;
    ie = HdiBssGetVendorIe(scanResult->ie, scanResult->ieLen, HDI_IE_VENDOR_TYPE);
    if (ie)
        pos = HdiGetIeTxt(pos, end, "WPA", ie, HDI_POS_SECOND + ie[1]);
    ie2 = HdiBssGetIe(scanResult->ie, scanResult->ieLen, HDI_EID_RSN);
    if (ie2) {
        pos = HdiGetIeTxt(pos, end, mesh ? "RSN" : "WPA2",
                        ie2, HDI_POS_SECOND + ie2[1]);
    }
    rsnxe = HdiBssGetIe(scanResult->ie, scanResult->ieLen, HDI_EID_RSNX);
    if (HdiGetRsnCapab(rsnxe, HDI_RSNX_CAPAB_SAE_H2E)) {
        ret = HdiTxtPrintf(pos, end - pos, "[SAE-H2E]");
        if (HdiCheckError(end - pos, ret)) {
            return -1;
        }
        pos += ret;
    }
    if (HdiGetRsnCapab(rsnxe, HDI_RSNX_CAPAB_SAE_PK)) {
        ret = HdiTxtPrintf(pos, end - pos, "[SAE-PK]");
        if (HdiCheckError(end - pos, ret)) {
            return -1;
        }
        pos += ret;
    }
    osen_ie = HdiBssGetVendorIe(scanResult->ie, scanResult->ieLen, HDI_OSEN_IE_VENDOR_TYPE);
    if (osen_ie)
        pos = HdiGetIeTxt(pos, end, "OSEN",
                        osen_ie, HDI_POS_SECOND + osen_ie[1]);
    owe = HdiBssGetVendorIe(scanResult->ie, scanResult->ieLen, HDI_OWE_VENDOR_TYPE);
    if (owe) {
        ret = HdiTxtPrintf(pos, end - pos,
                  ie2 ? "[OWE-TRANS]" : "[OWE-TRANS-OPEN]");
        if (HdiCheckError(end - pos, ret)) {
            return -1;
        }
        pos += ret;
    }
    if (!ie && !ie2 && !osen_ie && (scanResult->caps & HDI_CAP_PRIVACY)) {
        ret = HdiTxtPrintf(pos, end - pos, "[WEP]");
        if (HdiCheckError(end - pos, ret)) {
            return -1;
        }
        pos += ret;
    }
    if (mesh) {
        ret = HdiTxtPrintf(pos, end - pos, "[MESH]");
        if (HdiCheckError(end - pos, ret)) {
            return -1;
        }
        pos += ret;
    }
    if (HdiCheckIsDmg(scanResult->freq)) {
        const char *s;

        if (HdiBssGetIeExt(scanResult->ie, scanResult->ieLen, HDI_EID_EXT_EDMG_OPERATION)) {
            ret = HdiTxtPrintf(pos, end - pos, "[EDMG]");
            if (HdiCheckError(end - pos, ret))
                return -1;
            pos += ret;
        }

        ret = HdiTxtPrintf(pos, end - pos, "[DMG]");
        if (HdiCheckError(end - pos, ret))
            return -1;
        pos += ret;
        switch (scanResult->caps & HDI_CAP_DMG_MASK) {
            case HDI_CAP_DMG_IBSS:
                s = "[IBSS]";
                break;
            case HDI_CAP_DMG_AP:
                s = "[ESS]";
                break;
            case HDI_CAP_DMG_PBSS:
                s = "[PBSS]";
                break;
            default:
                s = "";
                break;
        }
        ret = HdiTxtPrintf(pos, end - pos, "%s", s);
        if (HdiCheckError(end - pos, ret)) {
            return -1;
        }
        pos += ret;
    } else {
        if (scanResult->caps & HDI_CAP_IBSS) {
            ret = HdiTxtPrintf(pos, end - pos, "[IBSS]");
            if (HdiCheckError(end - pos, ret))
                return -1;
            pos += ret;
        }
        if (scanResult->caps & HDI_CAP_ESS) {
            ret = HdiTxtPrintf(pos, end - pos, "[ESS]");
            if (HdiCheckError(end - pos, ret))
                return -1;
            pos += ret;
        }
    }
    if (p2p) {
        ret = HdiTxtPrintf(pos, end - pos, "[P2P]");
        if (HdiCheckError(end - pos, ret))
            return -1;
        pos += ret;
    }

    if (HdiCheckBssExtCap(scanResult->ie, scanResult->ieLen, HDI_EXT_CAPAB_UTF_8_SSID)) {
        ret = HdiTxtPrintf(pos, end - pos, "[UTF-8]");
        if (HdiCheckError(end - pos, ret))
            return -1;
        pos += ret;
    }

    ret = HdiTxtPrintf(pos, end - pos, "\t%s\t", HdiSSid2Txt(elems->ssid, elems->ssidLen));
    if (HdiCheckError(end - pos, ret))
        return -1;
    pos += ret;

    for (int j = 0; j < HDI_EID_EXTENSION; j++) {
        if ((j != HDI_EID_VHT_OPERATION) && (j != HDI_EID_HT_OPERATION) &&
            (j != HDI_EID_SUPPORTED_CHANNELS) && (j != HDI_EID_COUNTRY)) {
            continue;
        }
        infoEle = HdiBssGetIe(scanResult->ie, scanResult->ieLen, j);
        if (infoEle && infoEle[1] > 0) {
            ret = HdiTxtPrintf(pos, end - pos, "[%d ", j);
            if (HdiCheckError(end - pos, ret))
                return -1;
            pos += ret;
            for (uint8_t i = 0; i < infoEle[1]; i++) {
                ret = HdiTxtPrintf(pos, end - pos, "%02x", infoEle[i + HDI_POS_SECOND]);
                if (HdiCheckError(end - pos, ret))
                    return -1;
                pos += ret;
            }
            ret = HdiTxtPrintf(pos, end - pos, "]");
            if (HdiCheckError(end - pos, ret))
                return -1;
            pos += ret;
        }
    }

    infoEle = HdiBssGetIe(scanResult->ie, scanResult->ieLen, HDI_EID_EXTENSION);
    if (infoEle) {
        unsigned int len = infoEle[1];
        if (len > 1 && infoEle[HDI_POS_SECOND] == HDI_EID_EXT_HE_OPERATION) {
            ret = HdiTxtPrintf(pos, end - pos, "[%d %d ",
                HDI_EID_EXTENSION, HDI_EID_EXT_HE_OPERATION);
            if (HdiCheckError(end - pos, ret))
                return -1;
            pos += ret;
            for (size_t i = 0; i < len; i++) {
                ret = HdiTxtPrintf(pos, end - pos, "%02x", infoEle[i + HDI_POS_THIRD]);
                if (HdiCheckError(end - pos, ret))
                    return -1;
                pos += ret;
            }
            ret = HdiTxtPrintf(pos, end - pos, "]");
            if (HdiCheckError(end - pos, ret))
                return -1;
            pos += ret;
        }
    }

    ret = HdiTxtPrintf(pos, end - pos, "\n");
    if (HdiCheckError(end - pos, ret)) {
        return -1;
    }
    pos += ret;

    return pos - buf;
}


#endif
