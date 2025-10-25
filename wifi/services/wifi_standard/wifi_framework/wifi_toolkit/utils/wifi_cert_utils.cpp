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

#include "wifi_cert_utils.h"
#include <unistd.h>
#include "cert_manager_api.h"
#include "securec.h"
#include "wifi_log.h"
#include "wifi_global_func.h"
#include "cm_type.h"

#ifdef HAS_ACCOUNT_PART
#include "os_account_manager.h"
#endif

namespace OHOS {
namespace Wifi {
constexpr int MAX_ALIAS_LEN = 128;
constexpr int RETRY_INTERVAL = 5 * 100 * 1000; // wait for the remote sa to be ready
constexpr int IPC_ERROR_REMOTE_SA_DIE = 29189; // means the remote sa is dead
constexpr int DEFAULT_USER_ID = 100;

static bool CheckParamters(const std::vector<uint8_t>& certEntry, const std::string& pwd,
    std::string& alias)
{
    if (certEntry.size() == 0 || (pwd.size() + 1) > MAX_ALIAS_LEN ||
            (alias.size() + 1) > MAX_ALIAS_LEN) {
        LOGE("InstallCert, certEntry.size: %{public}zu, pwd.size: %{public}zu, alias.size: %{public}zu.",
            certEntry.size(), pwd.size(), alias.size());
        return false;
    }
    return true;
}

int WifiCertUtils::InstallCert(const std::vector<uint8_t>& certEntry, const std::string& pwd,
    std::string& alias, std::string& uri)
{
    if (!CheckParamters(certEntry, pwd, alias)) {
        return -1;
    }
    struct CmBlob appCert;
    struct CmBlob appCertPwd;
    struct CmBlob certAlias;
    char certPwdBuf[MAX_ALIAS_LEN] = { 0 };
    char certAliasBuf[MAX_ALIAS_LEN] = { 0 };
    uint8_t *data = reinterpret_cast<uint8_t*>(malloc(certEntry.size()));
    if (data == nullptr) {
        LOGE("InstallCert, malloc return null.");
        return -1;
    }

    if (memcpy_s(data, certEntry.size(), certEntry.data(), certEntry.size()) != EOK) {
        LOGE("memcpy_s certEntry.data() error.");
        free(data);
        data = nullptr;
        return -1;
    }
    if (memcpy_s(certPwdBuf, sizeof(certPwdBuf), pwd.c_str(), pwd.size()) != EOK) {
        LOGE("memcpy_s pwd.c_str() error.");
        free(data);
        data = nullptr;
        return -1;
    }
    if (memcpy_s(certAliasBuf, sizeof(certAliasBuf), alias.c_str(), alias.size()) != EOK) {
        LOGE("memcpy_s alias.c_str() error.");
        free(data);
        data = nullptr;
        return -1;
    }

    appCert.size = certEntry.size();
    appCert.data = data;
    appCertPwd.size = strlen(certPwdBuf) + 1;
    appCertPwd.data = reinterpret_cast<uint8_t*>(certPwdBuf);
    certAlias.size = strlen(certAliasBuf) + 1;
    certAlias.data = reinterpret_cast<uint8_t*>(certAliasBuf);

    char retUriBuf[MAX_ALIAS_LEN] = { 0 };
    struct CmBlob keyUri = { sizeof(retUriBuf), reinterpret_cast<uint8_t*>(retUriBuf) };
    int ret = 0;
#ifdef HAS_ACCOUNT_PART
    if (GetDeviceType() == ProductDeviceType::PC) {
        uint32_t store = CM_SYS_CREDENTIAL_STORE;
        int userId = DEFAULT_USER_ID;
        OHOS::AccountSA::OsAccountManager::GetForegroundOsAccountLocalId(userId);
        struct CmAppCertParam appCertParam = {&appCert, &appCertPwd, &certAlias, store, static_cast<uint32_t>(userId)};
        ret = CmInstallSystemAppCert(&appCertParam, &keyUri);
        if (ret == IPC_ERROR_REMOTE_SA_DIE) {
            LOGE("CmInstallSystemAppCert fail, remote sa die, code:%{public}d, retry after %{public}d",
                ret,
                RETRY_INTERVAL);
            usleep(RETRY_INTERVAL);
            ret = CmInstallSystemAppCert(&appCertParam, &keyUri);
        }
    } else {
        uint32_t store = CM_PRI_CREDENTIAL_STORE;
        ret = CmInstallAppCert(&appCert, &appCertPwd, &certAlias, store, &keyUri);
        if (ret == IPC_ERROR_REMOTE_SA_DIE) {
            LOGE("CmInstallAppCert fail, remote sa die, code:%{public}d, retry after %{public}d", ret, RETRY_INTERVAL);
            usleep(RETRY_INTERVAL);
            ret = CmInstallAppCert(&appCert, &appCertPwd, &certAlias, store, &keyUri);
        }
    }
#else
    uint32_t store = CM_PRI_CREDENTIAL_STORE;
    ret = CmInstallAppCert(&appCert, &appCertPwd, &certAlias, store, &keyUri);
    if (ret == IPC_ERROR_REMOTE_SA_DIE) {
        LOGE("CmInstallAppCert fail, remote sa die, code:%{public}d, retry after %{public}d", ret, RETRY_INTERVAL);
        usleep(RETRY_INTERVAL);
        ret = CmInstallAppCert(&appCert, &appCertPwd, &certAlias, store, &keyUri);
    }
#endif
    free(data);
    data = nullptr;
    if (ret == CM_SUCCESS) {
        uri = reinterpret_cast<char*>(keyUri.data);
    }

    return ret;
}

int WifiCertUtils::UninstallCert(std::string& uri)
{
    if (uri.size() >= MAX_ALIAS_LEN) {
        LOGE("UninstallCert, uri.size: %{public}zu.", uri.size());
        return -1;
    }

    uint32_t store = CM_PRI_CREDENTIAL_STORE;
    struct CmBlob keyUri;
    char keyUriBuf[MAX_ALIAS_LEN] = { 0 };

    if (memcpy_s(keyUriBuf, sizeof(keyUriBuf), uri.c_str(), uri.size()) != EOK) {
        LOGE("memcpy_s uri.c_str() error.");
        return -1;
    }

    if (strncmp(keyUriBuf, "oh:t=sk", strlen("oh:t=sk")) == 0) {
        store = CM_SYS_CREDENTIAL_STORE;
    }

    keyUri.size = strlen(keyUriBuf) + 1;
    keyUri.data = reinterpret_cast<uint8_t*>(keyUriBuf);
    return CmUninstallAppCert(&keyUri, store);
}
}
}
