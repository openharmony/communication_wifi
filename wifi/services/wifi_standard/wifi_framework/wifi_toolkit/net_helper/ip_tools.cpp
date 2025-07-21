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

#include "ip_tools.h"
#include "wifi_common_util.h"

namespace OHOS {
namespace Wifi {
std::string IpTools::ConvertIpv4Address(unsigned int addressIpv4)
{
    std::string address;
    if (addressIpv4 == 0) {
        return address;
    }

    std::ostringstream stream;
    stream<<((addressIpv4>>BITS_24) & 0xFF)<<"."<<((addressIpv4>>BITS_16) & 0xFF)<<"."
    <<((addressIpv4>>BITS_8) & 0xFF)<<"."<<(addressIpv4 & 0xFF);
    address = stream.str();

    return address;
}

unsigned int IpTools::ConvertIpv4Address(const std::string &address)
{
    std::string tmpAddress = address;
    unsigned int addrInt = 0;
    unsigned int i = 0;
    for (i = 0; i < IPV4_DOT_NUM; i++) {
        std::string::size_type npos = tmpAddress.find(".");
        if (npos == std::string::npos) {
            break;
        }
        std::string value = tmpAddress.substr(0, npos);
        unsigned int tmp = CheckDataToUint(value);
        if ((tmp < MIN_BYTE) || (tmp > MAX_BYTE)) {
            break;
        }
        addrInt += tmp << ((IPV4_DOT_NUM - i) * BIT_NUM_BYTE);
        tmpAddress = tmpAddress.substr(npos + 1);
    }

    if (i != IPV4_DOT_NUM) {
        return 0;
    }
    int tmp = CheckDataLegal(tmpAddress);
    if ((tmp < MIN_BYTE) || (tmp > MAX_BYTE)) {
        return 0;
    }
    addrInt += tmp;

    return addrInt;
}

std::string IpTools::ConvertIpv6Address(const std::vector<unsigned char> &addressIpv6)
{
    std::string address;
    if (addressIpv6.size() != IPV6_BYTE_NUM) {
        return address;
    }

    std::ostringstream stream;
    stream << std::hex << std::setw(POS_2) << std::setfill('0') << static_cast<int>(addressIpv6[0]);
    stream << std::hex << std::setw(POS_2) << std::setfill('0') << static_cast<int>(addressIpv6[1]);
    for (int i = POS_2; i < IPV6_BYTE_NUM; i += POS_2) {
        stream << ":";
        stream << std::hex << std::setw(POS_2) << std::setfill('0') << static_cast<int>(addressIpv6[i]);
        stream << std::hex << std::setw(POS_2) << std::setfill('0') << static_cast<int>(addressIpv6[i + 1]);
    }
    address = stream.str();

    return address;
}

void IpTools::ConvertIpv6Address(const std::string &address, std::vector<unsigned char> &addressIpv6)
{
    std::string tmpAddress = address;
    addressIpv6.clear();
    std::vector<unsigned char> ipv6;
    int i = 0;
    for (i = 0; i < IPV6_COLON_NUM; i++) {
        std::string::size_type npos = tmpAddress.find(":");
        if (npos == std::string::npos) {
            break;
        }

        std::string value = tmpAddress.substr(0, npos);
        if (value.size() != IPV6_DIGIT_NUM_PER_SEG) {
            break;
        }
        std::string valueFromPos0 = value.substr(POS_0, HEX_BYTE_DIGIT_NUM);
        std::string valueFromPos2 = value.substr(POS_2, HEX_BYTE_DIGIT_NUM);
        ipv6.push_back(CheckDataLegalHex(valueFromPos0));
        ipv6.push_back(CheckDataLegalHex(valueFromPos2));
        tmpAddress = tmpAddress.substr(npos + 1);
    }

    if (i != IPV6_COLON_NUM) {
        return;
    }
    if (tmpAddress.size() != IPV6_DIGIT_NUM_PER_SEG) {
        return;
    }
    std::string addressFromPos0 = tmpAddress.substr(POS_0, HEX_BYTE_DIGIT_NUM);
    std::string addressFromPos2 = tmpAddress.substr(POS_2, HEX_BYTE_DIGIT_NUM);
    ipv6.push_back(CheckDataLegalHex(addressFromPos0));
    ipv6.push_back(CheckDataLegalHex(addressFromPos2));

    addressIpv6.assign(ipv6.begin(), ipv6.end());
    return;
}

std::string IpTools::ConvertIpv4Mask(int prefixLength)
{
    std::string netMask;
    if (prefixLength <= MIN_PREFIX_LEN || prefixLength > MAX_PREFIX_LEN) {
        const int defaultPrefix = 24;
        prefixLength = defaultPrefix;
    }

    int mask[IPV4_BYTE_NUM] = {0, 0, 0, 0};
    int quot = prefixLength / BIT_NUM_PER_BYTE;
    int remain = prefixLength % BIT_NUM_PER_BYTE;
    for (int i = 0; i < quot; i++) {
        mask[i] = MAX_IPV4_MASK_BYTE;
    }
    if (quot < IPV4_BYTE_NUM) {
        mask[quot] = (MAX_BYTE + 1) - (1 << (BIT_NUM_PER_BYTE - remain));
    }
    std::ostringstream stream;
    stream << mask[POS_0] << "." << mask[POS_1] << "." << mask[POS_2] << "." << mask[POS_3];
    netMask = stream.str();

    return netMask;
}

std::string IpTools::ConvertIpv6Mask(int prefixLength)
{
    if (prefixLength < MIN_PREFIX_LEN || prefixLength > MAX_IPV6_PREFIX_LEN) {
        return "";
    }
    // 初始化 16 字节的 IPv6 掩码（全 0）
    uint8_t mask[16];
    memset_s(mask, sizeof(mask), 0, sizeof(mask));

    // 逐字节设置掩码
    uint8_t bytesLen = 8;
    uint8_t ipv6Bytes = 16;
    for (unsigned int i = 0; i < ipv6Bytes; i++) {
        if (prefixLength >= bytesLen) {
            mask[i] = 0xFF;  // 当前字节全 1
            prefixLength -= bytesLen;
        } else if (prefixLength > 0) {
            mask[i] = 0xFF << (bytesLen - prefixLength);  // 部分 1
            prefixLength = 0;
        }
        // 剩余字节保持 0
    }

    // 转换为 IPv6 字符串格式（压缩形式，如 "ffff::"）
    char buffer[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, mask, buffer, INET6_ADDRSTRLEN);
    return std::string(buffer);
}

int IpTools::GetMaskLength(std::string mask)
{
    int netMask = 0;
    const unsigned int constMask = 0x80000000;
    unsigned int maskTmp = ntohl(static_cast<int>(inet_addr(mask.c_str())));
    while (maskTmp & constMask) {
        netMask++;
        maskTmp = (maskTmp << 1);
    }

    return netMask;
}

/**
    * @Description : Obtains the length based on the subnet mask.
    *
    * @param mask - The mask.[in]
    * @return int
*/
int IpTools::GetIPV6MaskLength(std::string ip)
{
    constexpr int32_t LENGTH_8 = 8;
    constexpr int32_t LENGTH_7 = 7;
    constexpr int32_t LENGTH_6 = 6;
    constexpr int32_t LENGTH_5 = 5;
    constexpr int32_t LENGTH_4 = 4;
    constexpr int32_t LENGTH_3 = 3;
    constexpr int32_t LENGTH_2 = 2;
    constexpr int32_t LENGTH_1 = 1;
    if (ip.empty()) {
        return 0;
    }
    in6_addr addr{};
    inet_pton(AF_INET6, ip.c_str(), &addr);
    int32_t prefixLen = 0;
    for (int32_t i = 0; i < BITS_16; ++i) {
        if (addr.s6_addr[i] == 0xFF) {
            prefixLen += LENGTH_8;
        } else if (addr.s6_addr[i] == 0xFE) {
            prefixLen += LENGTH_7;
            break;
        } else if (addr.s6_addr[i] == 0xFC) {
            prefixLen += LENGTH_6;
            break;
        } else if (addr.s6_addr[i] == 0xF8) {
            prefixLen += LENGTH_5;
            break;
        } else if (addr.s6_addr[i] == 0xF0) {
            prefixLen += LENGTH_4;
            break;
        } else if (addr.s6_addr[i] == 0xE0) {
            prefixLen += LENGTH_3;
            break;
        } else if (addr.s6_addr[i] == 0xC0) {
            prefixLen += LENGTH_2;
            break;
        } else if (addr.s6_addr[i] == 0x80) {
            prefixLen += LENGTH_1;
            break;
        } else {
            break;
        }
    }
    return prefixLen;
}

void IpTools::GetExclusionObjectList(const std::string &exclusionObjectList, std::vector<std::string> &exclusionList)
{
    std::string tmpExclusionList = exclusionObjectList;
    std::vector<std::string> list;
    int listNum = count(tmpExclusionList.begin(), tmpExclusionList.end(), ',');
    int i = 0;
    for (i = 0; i < listNum; ++i) {
        std::string::size_type npos = tmpExclusionList.find(",");
        if (npos == std::string::npos) {
            break;
        }

        std::string exclusionOne = tmpExclusionList.substr(0, npos);
        /* Do you need to check whether the format of this website is correct? */
        list.push_back(exclusionOne);
        tmpExclusionList = tmpExclusionList.substr(npos + 1);
    }
    if (i != listNum) {
        return;
    }
    list.push_back(tmpExclusionList);
    exclusionList.assign(list.begin(), list.end());
    return;
}

std::string IpTools::ConvertIpv6AddressToCompleted(const std::string &address)
{
    size_t dblColonPos = address.find("::");
    bool hasDblColon = (dblColonPos != std::string::npos);
    std::vector<std::string> parts;
    std::string firstPart = address.substr(0, dblColonPos);
    std::string secondPart = hasDblColon ? address.substr(dblColonPos + 2) : "";
 
    std::istringstream firstStream(firstPart);
    std::string segment;
    while (getline(firstStream, segment, ':')) {
        parts.push_back(segment);
    }
 
    std::istringstream secondStream(secondPart);
    std::vector<std::string> secondParts;
    while (getline(secondStream, segment, ':')) {
        secondParts.push_back(segment);
    }
 
    size_t totalParts = 8;
    size_t existingParts = parts.size() + secondParts.size();
    size_t zeroPartsToInsert = totalParts - existingParts;
    int8_t bitNum = 4;
    parts.insert(parts.end(), zeroPartsToInsert, "0");
    parts.insert(parts.end(), secondParts.begin(), secondParts.end());
    std::ostringstream stream;
    for (size_t i = 0; i < parts.size(); i++) {
        if (i != 0) {
            stream << ":";
        }
        std::string seg = parts[i];
        if (seg.empty()) {
            seg = "0";
        }
        int value = CheckDataLegalHex(seg);
        stream << std::setw(bitNum) << std::setfill('0') << std::hex << value;
    }
    return stream.str();
}
}  // namespace Wifi
}  // namespace OHOS