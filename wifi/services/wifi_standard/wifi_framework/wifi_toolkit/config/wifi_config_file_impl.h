/*
 * Copyright (C) 2021-2022 Huawei Device Co., Ltd.
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

#ifndef OHOS_WIFI_CONFIG_FILE_IMPL_H
#define OHOS_WIFI_CONFIG_FILE_IMPL_H
#include <fstream>
#include <sstream>
#include <string>
#include <unistd.h>
#include <vector>
#include <mutex>
#include "wifi_config_file_spec.h"
#include "wifi_log.h"
#ifdef FEATURE_ENCRYPTION_SUPPORT
#include "wifi_encryption_util.h"
#endif

namespace OHOS {
namespace Wifi {
constexpr int WIFI_CONFIG_FILE_LINE_MAX_LENGTH = 4096;
/**
 * @Description Remove head and tail space
 *
 * @param str - String
 */
static inline void TrimString(std::string &str)
{
    int i = 0;
    int j = static_cast<int>(str.length()) - 1;
    while (i < static_cast<int>(str.length()) && str[i] == ' ') {
        ++i;
    }
    while (j >= 0 && str[j] == ' ') {
        --j;
    }
    str = ((i > j) ? "" : str.substr(i, j - i + 1));
}

/**
 * @Description Delete comment message begin with ; and #
 *
 * @param str - String
 */
static inline void DelComment(std::string &str)
{
    std::string::size_type i = 0;
    for (; i < str.length(); ++i) {
        if (str[i] == ';' || str[i] == '#') {
            str = str.substr(0, i);
            break;
        }
    }
    return;
}

template<typename T>
class WifiConfigFileImpl {
public:
    /**
     * @Description Set the config file path
     *
     * @param fileName - file name
     * @return int - 0 success
     */
    int SetConfigFilePath(const std::string &fileName);

    /**
     * @Description Set the Encryption info and Encryption tag
     *
     * @param key - key
     * @param iv - iv
     * @return int - 0 success
     */
    int SetEncryptionInfo(const std::string &key, const std::string &iv);

    /**
     * @Description Unset the Encryption info: delete the key loaded in hks
     *
     * @return int - 0 success
     */
    int UnsetEncryptionInfo();

    /**
     * @Description read and parses the network section of ini config file, need call SetConfigFilePath first
     *
     * @return int - 0 Success; >0 parse failed
     */
    int ReadNetworkSection(T &item, std::istream &fs, std::string &line);

    /**
     * @Description read and parses the networks of ini config file, need call SetConfigFilePath first
     *
     * @return int - 0 Success; >0 parse failed
     */
    int ReadNetwork(T &item, std::istream &fs, std::string &line);

    /**
     * @Description read ini config file, need call SetConfigFilePath first
     */
    void ReadFile(std::istream &fs)
    {
        std::lock_guard<std::mutex> lock(valueMutex_);
        mValues.clear();
        T item;
        std::string line;
        int configError;
        while (std::getline(fs, line)) {
            TrimString(line);
            if (line.empty()) {
                continue;
            }
            if (line[0] == '[' && line[line.length() - 1] == '{') {
                ClearTClass(item); /* template function, needing specialization */
                configError = ReadNetwork(item, fs, line);
                if (configError > 0) {
                    LOGE("Parse network failed.");
                    continue;
                }
                mValues.push_back(item);
            }
        }
    }

    /**
     * @Description use temp file to write ini config file
     *
     * @param results - output config values
     * @return int - 0 Success
     */
    int WriteFile(const std::string &content)
    {
        if (mFileName.empty()) {
            LOGE("File name is empty.");
            return -1;
        }
        std::string tempFileName = mFileName + ".temp";
        FILE* fp = fopen(tempFileName.c_str(), "w");
        if (!fp) {
            LOGE("Save config file: %{public}s, fopen() failed!", tempFileName.c_str());
            return -1;
        }
        size_t ret = fwrite(content.c_str(), 1, content.length(), fp);
        if (ret != content.length()) {
            LOGE("Save config file: %{public}s, fwrite() failed!", tempFileName.c_str());
            (void)fclose(fp);
            remove(tempFileName.c_str());
            return -1;
        }
        (void)fflush(fp);
        (void)fsync(fileno(fp));
        (void)fclose(fp);

        if (rename(tempFileName.c_str(), mFileName.c_str()) != 0) {
            LOGE("Save config file: %{public}s, rename() failed!", mFileName.c_str());
            remove(tempFileName.c_str());
            return -1;
        }
        remove(tempFileName.c_str());
        return 0;
    }

    /**
     * @Description read and parses the ini config file, need call SetConfigFilePath first
     * need call SetEncryptionInfo first when load encrypted config file
     *
     * @return int - 0 Success; -1 file not exist
     */
    int LoadConfig();

    /**
     * @Description Save config to file
     * need call SetEncryptionInfo first when save encrypted config file
     *
     * @return int - 0 Success; -1 Failed
     */
    int SaveConfig()
    {
        std::string content;
        std::lock_guard<std::mutex> lock(valueMutex_);
        {
            std::ostringstream ss;
            LOGI("Save config:%{public}s size:%{public}d", GetTClassName<T>().c_str(),
                static_cast<int>(mValues.size()));
            for (std::size_t i = 0; i < mValues.size(); ++i) {
                T &item = mValues[i];
                /*
                * here use template function GetTClassName OutTClassString, needing
                * specialization.
                */
                ss << "[" << GetTClassName<T>() << "_" << (i + 1) << "] {" << std::endl;
                ss << OutTClassString(item) << std::endl;
                ss << "}" << std::endl;
            }
            content = ss.str();
        }
#ifdef FEATURE_ENCRYPTION_SUPPORT
        if (mSetEncryption) {
            WifiLoopEncrypt(mEncryptionInfo, content, mEncry);
            std::fill(content.begin(), content.end(), 0);
            content = mEncry.encryptedPassword;
        }
#endif
        mValues.clear(); /* clear values */
        if (WriteFile(content) != 0) {
            return -1;
        }
        return 0;
    }

    /**
     * @Description Get config values
     *
     * @param results - output config values
     * @return int - 0 Success, -1 Failed
     */
    int GetValue(std::vector<T> &results)
    {
        std::lock_guard<std::mutex> lock(valueMutex_);
        std::swap(results, mValues);
        return 0;
    }

    /**
     * @Description Get config values
     *
     * @return config values
     */
    const std::vector<T>& GetValue()
    {
        std::lock_guard<std::mutex> lock(valueMutex_);
        return mValues;
    }

    /**
     * @Description Set the config value
     *
     * @param values - input config values
     * @return int - 0 Success, -1 Failed
     */
    int SetValue(const std::vector<T> &values)
    {
        std::lock_guard<std::mutex> lock(valueMutex_);
        mValues = values;
        return 0;
    }

private:
    std::string mFileName;
    std::vector<T> mValues;
    bool mSetEncryption;
    std::mutex valueMutex_;
#ifdef FEATURE_ENCRYPTION_SUPPORT
    WifiEncryptionInfo mEncryptionInfo;
    EncryptedData mEncry;
#endif
};

template<typename T>
int WifiConfigFileImpl<T>::SetConfigFilePath(const std::string &fileName)
{
    mFileName = fileName;
    mSetEncryption = false;
    return 0;
}

template<typename T>
int WifiConfigFileImpl<T>::SetEncryptionInfo(const std::string &key, const std::string &iv)
{
#ifdef FEATURE_ENCRYPTION_SUPPORT
    mSetEncryption = true;
    mEncryptionInfo.SetFile(GetTClassName<T>());
    if (!key.empty()) {
        ImportKey(mEncryptionInfo, key);
    }
    mEncry.IV = iv;
#endif
    return 0;
}

template<typename T>
int WifiConfigFileImpl<T>::UnsetEncryptionInfo()
{
#ifdef FEATURE_ENCRYPTION_SUPPORT
    DeleteKey(mEncryptionInfo);
#endif
    return 0;
}

template<typename T>
int WifiConfigFileImpl<T>::ReadNetworkSection(T &item, std::istream &fs, std::string &line)
{
    int sectionError = 0;
    while (std::getline(fs, line)) {
        TrimString(line);
        if (line.empty()) {
            continue;
        }
        if (line.length() > WIFI_CONFIG_FILE_LINE_MAX_LENGTH) {
            LOGE("%{public}s %{public}s line length is too big.", __func__, GetTClassName<T>().c_str());
            sectionError++;
            break;
        }
        if (line[0] == '<' && line[line.length() - 1] == '>') {
            return sectionError;
        }
        std::string::size_type npos = line.find("=");
        if (npos == std::string::npos) {
            LOGE("Invalid config line");
            sectionError++;
            continue;
        }
        std::string key = line.substr(0, npos);
        std::string value = line.substr(npos + 1);
        TrimString(key);
        TrimString(value);
        /* template function, needing specialization */
        sectionError += SetTClassKeyValue(item, key, value);
        std::fill(value.begin(), value.end(), 0);
    }
    LOGE("Section config not end correctly");
    sectionError++;
    return sectionError;
}

template<typename T>
int WifiConfigFileImpl<T>::ReadNetwork(T &item, std::istream &fs, std::string &line)
{
    int networkError = 0;
    while (std::getline(fs, line)) {
        TrimString(line);
        if (line.empty()) {
            continue;
        }
        if (line[0] == '<' && line[line.length() - 1] == '>') {
            networkError += ReadNetworkSection(item, fs, line);
        } else if (line.compare("}") == 0) {
            return networkError;
        } else {
            LOGE("Invalid config line");
            networkError++;
        }
    }
    LOGE("Network config not end correctly");
    networkError++;
    return networkError;
}

template<typename T>
int WifiConfigFileImpl<T>::LoadConfig()
{
    if (mFileName.empty()) {
        LOGE("File name is empty.");
        return -1;
    }
    std::ifstream fs(mFileName.c_str());
    if (!fs.is_open()) {
        LOGE("Loading config file: %{public}s, fs.is_open() failed!", mFileName.c_str());
        return -1;
    }
#ifdef FEATURE_ENCRYPTION_SUPPORT
    if (mSetEncryption) {
        std::string content((std::istreambuf_iterator<char>(fs)), std::istreambuf_iterator<char>());
        mEncry.encryptedPassword = content;
        WifiLoopDecrypt(mEncryptionInfo, mEncry, content);
        std::stringstream strStream(content);
        ReadFile(strStream);
        std::fill(content.begin(), content.end(), 0);
    } else {
        ReadFile(fs);
    }
#else
    ReadFile(fs);
#endif
    fs.close();
    return 0;
}
}  // namespace Wifi
}  // namespace OHOS
#endif