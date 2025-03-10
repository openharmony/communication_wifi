/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
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

#include "wifi_randommac_helper.h"

#if defined(FEATURE_ENCRYPTION_SUPPORT) || defined(SUPPORT_LOCAL_RANDOM_MAC)
#include "wifi_encryption_util.h"
#endif
#include "wifi_logger.h"

static const std::string STA_RANDOMMAC_KEY_ALIAS = "WiFiRandMacSecret";

namespace OHOS {
namespace Wifi {
DEFINE_WIFILOG_LABEL("WifiRandomMacHelper");
const unsigned long long MAC_ADDRESS_VALID_LONG_MASK = (1ULL << 48) - 1;
const unsigned long long MAC_ADDRESSS_AIASSIGNED_MASK = 1ULL << 43;
const unsigned long long MAC_ADDRESS_ELIASSIGNED_MASK = 1ULL << 42;
const unsigned long long MAC_ADDRESS_LOCALLY_ASSIGNED_MASK = 1ULL << 41;
const unsigned long long MAC_ADDRESS_MULTICAST_MASK = 1ULL << 40;
constexpr int MAX_MAC_SIZE = 18;
constexpr int LONG_TO_BYTE_SIZE = 8;
constexpr int MAC_ADDRESS_ETHER_ADDR_LEN = 6;
constexpr unsigned int WIFI2_RANDOM_MAC_CHANGE_POS = 9;
constexpr unsigned int WIFI2_RANDOM_MAC_CHANGE_LEN = 2;
constexpr unsigned int WIFI2_RANDOM_MAC_MASK = 0x80;

constexpr int OFFSET_VALUE_56 = 56;
constexpr int OFFSET_VALUE_48 = 48;
constexpr int OFFSET_VALUE_40 = 40;
constexpr int OFFSET_VALUE_32 = 32;
constexpr int OFFSET_VALUE_24 = 24;
constexpr int OFFSET_VALUE_16 = 16;
constexpr int OFFSET_VALUE_8 = 8;
constexpr int OFFSET_VALUE_7 = 7;
constexpr int OFFSET_VALUE_6 = 6;
constexpr int OFFSET_VALUE_5 = 5;
constexpr int OFFSET_VALUE_4 = 4;
constexpr int OFFSET_VALUE_3 = 3;
constexpr int OFFSET_VALUE_2 = 2;
constexpr int OFFSET_VALUE_1 = 1;
constexpr int OFFSET_VALUE_0 = 0;

#ifdef SUPPORT_LOCAL_RANDOM_MAC
int WifiRandomMacHelper::CalculateRandomMacForWifiDeviceConfig(const std::string &content, std::string &randomMacAddr)
{
    WIFI_LOGI("%{public}s enter", __func__);
    std::vector<uint8_t> outPlant = {};
    int ret = WifiGenerateMacRandomizationSecret(STA_RANDOMMAC_KEY_ALIAS, content, outPlant);
    if (ret != 0) {
        WIFI_LOGE("%{public}s WifiGenerateMacRandomizationSecret failed %{public}d", __func__, ret);
        return -1;
    }
    if (outPlant.size() < LONG_TO_BYTE_SIZE) {
        WIFI_LOGE("%{public}s WifiGenerateMacRandomizationSecret size is illeage", __func__);
        return -1;
    }
    std::vector<uint8_t> bytesToLong = {};
    bytesToLong.assign(outPlant.begin(), outPlant.begin() + LONG_TO_BYTE_SIZE);
    unsigned long long data = WifiRandomMacHelper::BytesToLonglong(bytesToLong);
    ret = GenerateRandomMacAddressByLong(data, randomMacAddr);
    if (ret != 0) {
        WIFI_LOGE("%{public}s GenerateRandomMacAddressByLong failed:%{public}d", __func__, ret);
        return -1;
    }
    return 0;
}
#endif

void WifiRandomMacHelper::GenerateRandomMacAddressByBssid(std::string peerBssid, std::string &randomMacAddr)
{
    WIFI_LOGD("enter %{public}s", __func__);
    constexpr int arraySize = 4;
    constexpr int macBitSize = 12;
    constexpr int firstBit = 1;
    constexpr int lastBit = 11;
    constexpr int two = 2;
    constexpr int hexBase = 16;
    constexpr int octBase = 8;
    int ret = 0;
    char strMacTmp[arraySize] = {0};
    unsigned long long hashSeed = std::hash<std::string>{}(peerBssid);
    unsigned long long genSeed = std::chrono::high_resolution_clock::now().time_since_epoch().count();
    if (std::numeric_limits<unsigned long long>::max() - genSeed > hashSeed) {
        genSeed += hashSeed;
    } else {
        WIFI_LOGW("%{public}s hashSeed Value beyond max limit!", __func__);
    }
    std::mt19937_64 gen(genSeed);
    for (int i = 0; i < macBitSize; i++) {
        if (i != firstBit) {
            std::uniform_int_distribution<> distribution(0, hexBase - 1);
            ret = sprintf_s(strMacTmp, arraySize, "%x", distribution(gen));
        } else {
            std::uniform_int_distribution<> distribution(0, octBase - 1);
            ret = sprintf_s(strMacTmp, arraySize, "%x", two * distribution(gen));
        }
        if (ret == -1) {
            WIFI_LOGE("%{public}s failed, sprintf_s return -1!", __func__);
        }
        randomMacAddr += strMacTmp;
        if ((i % two) != 0 && (i != lastBit)) {
            randomMacAddr.append(":");
        }
    }
    WIFI_LOGD("exit %{public}s, randomMacAddr:%{private}s", __func__, randomMacAddr.c_str());
}

long int WifiRandomMacHelper::GetRandom()
{
    long random = 0;
    do {
        int fd = open("/dev/random", O_RDONLY);
        if (fd >= 0) {
            read(fd, &random, sizeof(random));
            close(fd);
        } else {
            WIFI_LOGW("%{public}s: failed to open, try again", __func__);
        }
        if (random == 0) {
            fd = open("/dev/random", O_RDONLY);
            if (fd >= 0) {
                read(fd, &random, sizeof(random));
                close(fd);
            } else {
                WIFI_LOGE("%{public}s: retry failed", __func__);
            }
        }
    } while (0);
    return (random >= 0 ? random : -random);
}

void WifiRandomMacHelper::GenerateRandomMacAddress(std::string &randomMacAddr)
{
    GenerateRandomMacAddressByBssid("", randomMacAddr);
    return;
}

void WifiRandomMacHelper::LongLongToBytes(unsigned long long value, std::vector<uint8_t> &outPlant)
{
    outPlant.clear();
    outPlant.emplace_back((value >> OFFSET_VALUE_56) & 0xFF);
    outPlant.emplace_back((value >> OFFSET_VALUE_48) & 0xFF);
    outPlant.emplace_back((value >> OFFSET_VALUE_40) & 0xFF);
    outPlant.emplace_back((value >> OFFSET_VALUE_32) & 0xFF);
    outPlant.emplace_back((value >> OFFSET_VALUE_24) & 0xFF);
    outPlant.emplace_back((value >> OFFSET_VALUE_16) & 0xFF);
    outPlant.emplace_back((value >> OFFSET_VALUE_8)  & 0xFF);
    outPlant.emplace_back(value & 0xFF);
    return;
}

unsigned long long WifiRandomMacHelper::BytesToLonglong(const std::vector<uint8_t> &byte)
{
    if (byte.size() != LONG_TO_BYTE_SIZE) {
        WIFI_LOGI("%{public}s byte size is invalid :%{public}zu", __func__, byte.size());
        return 0;
    }
    unsigned long long value = 0;
    value = (
        (((unsigned long long)byte[OFFSET_VALUE_0] << OFFSET_VALUE_56) & 0xFF00000000000000L) |
        (((unsigned long long)byte[OFFSET_VALUE_1] << OFFSET_VALUE_48) & 0xFF000000000000L) |
        (((unsigned long long)byte[OFFSET_VALUE_2] << OFFSET_VALUE_40) & 0xFF0000000000L) |
        (((unsigned long long)byte[OFFSET_VALUE_3] << OFFSET_VALUE_32) & 0xFF00000000L) |
        (((unsigned long long)byte[OFFSET_VALUE_4] << OFFSET_VALUE_24) & 0xFF000000L)|
        (((unsigned long long)byte[OFFSET_VALUE_5] << OFFSET_VALUE_16) & 0xFF0000L)|
        (((unsigned long long)byte[OFFSET_VALUE_6] << OFFSET_VALUE_8) & 0xFF00L)|
        ((unsigned long long)byte[OFFSET_VALUE_7] & 0xFFL));
    return value;
}

std::string WifiRandomMacHelper::BytesArrayToString(const std::vector<uint8_t> &bytes)
{
    if (bytes.empty()) {
        return "size:0 []";
    }
    size_t size = bytes.size();
    std::string str = "size:" + std::to_string(size) + " [";
    for (size_t i = 0; i < size; i++) {
        str += std::to_string(bytes[i]);
        if (i != size - 1) {
            str += ",";
        }
    }
    str += "]";
    return str;
}

int WifiRandomMacHelper::StringAddrFromLongAddr(unsigned long long addr, std::string &randomMacAddr)
{
    WIFI_LOGD("%{public}s %{public}llu 0x%{public}02llx:0x%{public}02llx:0x%{public}02llx:0x%{public}02llx"
        ":0x%{public}02llx:0x%{public}02llx", __func__, addr,
        (addr >> OFFSET_VALUE_40) & 0XFF,
        (addr >> OFFSET_VALUE_32) & 0XFF,
        (addr >> OFFSET_VALUE_24) & 0XFF,
        (addr >> OFFSET_VALUE_16) & 0XFF,
        (addr >> OFFSET_VALUE_8) & 0XFF,
        addr & 0XFF);
    char strMac[MAX_MAC_SIZE] = { 0 };
    int ret = sprintf_s(strMac, MAX_MAC_SIZE, "%02llx:%02llx:%02llx:%02llx:%02llx:%02llx",
        (addr >> OFFSET_VALUE_40) & 0XFF,
        (addr >> OFFSET_VALUE_32) & 0XFF,
        (addr >> OFFSET_VALUE_24) & 0XFF,
        (addr >> OFFSET_VALUE_16) & 0XFF,
        (addr >> OFFSET_VALUE_8) & 0XFF,
        addr & 0XFF);
    if (ret < 0) {
        WIFI_LOGI("%{public}s: failed to sprintf_s", __func__);
        return -1;
    }
    randomMacAddr = strMac;
    return 0;
}

unsigned long long WifiRandomMacHelper::LongAddrFromByteAddr(std::vector<uint8_t> &addr)
{
    if (addr.size() != MAC_ADDRESS_ETHER_ADDR_LEN) {
        WIFI_LOGE("%{public}s %{public}s is not a valid MAC address", __func__,
            BytesArrayToString(addr).c_str());
        return 0;
    }
    unsigned long long longAddr = 0;
    for (auto &b : addr) {
        uint32_t uint8Byte = b & 0xff;
        longAddr = (longAddr << OFFSET_VALUE_8) + uint8Byte;
    }
    return longAddr;
}


int WifiRandomMacHelper::GenerateRandomMacAddressByLong(unsigned long long random, std::string &randomMacAddr)
{
    if (random == 0) {
        WIFI_LOGI("%{public}s: random is invalid :%{public}llu!", __func__, random);
        return -1;
    }

    WIFI_LOGD("%{public}s: calculate start is 0x%{public}llx==%{public}llu", __func__, random, random);
    random &= MAC_ADDRESS_VALID_LONG_MASK;
    random &= ~MAC_ADDRESSS_AIASSIGNED_MASK;
    random &= ~MAC_ADDRESS_ELIASSIGNED_MASK;
    random |= MAC_ADDRESS_LOCALLY_ASSIGNED_MASK;
    random &= ~MAC_ADDRESS_MULTICAST_MASK;
    WIFI_LOGD("%{public}s: calculate end is 0x%{public}llx==%{public}llu", __func__, random, random);

    std::vector<uint8_t> bytes = {};
    WifiRandomMacHelper::LongLongToBytes(random, bytes);
    if (bytes.size() != LONG_TO_BYTE_SIZE) {
        WIFI_LOGE("%{public}s LongLongToBytes failed size:%{public}zu", __func__, bytes.size());
        return -1;
    }
    std::vector<uint8_t> addrBytes = {};
    addrBytes.assign(bytes.begin() + OFFSET_VALUE_2, bytes.end());
    unsigned long long lngAddr = WifiRandomMacHelper::LongAddrFromByteAddr(addrBytes);

    int ret = StringAddrFromLongAddr(lngAddr, randomMacAddr);
    WIFI_LOGD("%{public}s: StringAddrFromLongAddr: %{public}llu -> %{public}s", __func__,
        lngAddr, MacAnonymize(randomMacAddr).c_str());
    return ret;
}

bool WifiRandomMacHelper::GetWifi2RandomMac(std::string &wifi2RandomMac)
{
    std::string inputStrMac = wifi2RandomMac.substr(WIFI2_RANDOM_MAC_CHANGE_POS, WIFI2_RANDOM_MAC_CHANGE_LEN);
    std::stringstream inputSsMac;
    inputSsMac << std::hex <<inputStrMac;
    unsigned int inputHexMac;
    if (inputSsMac >> inputHexMac) {
        WIFI_LOGD("%{public}s conver pos 3 mac to hex success", __func__);
    } else {
        WIFI_LOGE("%{public}s conver pos 3 mac to hex fail", __func__);
        return false;
    }
    unsigned int outputHexMac = inputHexMac ^ WIFI2_RANDOM_MAC_MASK;
    std::stringstream outSsMac;
    outSsMac << std::hex <<outputHexMac;
    wifi2RandomMac.replace(WIFI2_RANDOM_MAC_CHANGE_POS, WIFI2_RANDOM_MAC_CHANGE_LEN, outSsMac.str());
    return true;
}

}   // Wifi
} // OHOS
