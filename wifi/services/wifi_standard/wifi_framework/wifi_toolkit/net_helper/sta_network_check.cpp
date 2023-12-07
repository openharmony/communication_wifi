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

#include "sta_network_check.h"
#include "wifi_logger.h"
#include "wifi_settings.h"
#ifndef OHOS_ARCH_LITE
#include "http_client_request.h"
#include "http_client.h"
#endif

DEFINE_WIFILOG_LABEL("StaNetworkCheck");

namespace OHOS {
namespace Wifi {
constexpr int NET_ERR_OK = 200;
constexpr int NET_ERR_CREATED = 201;
constexpr int NET_ERR_NO_CONTENT = 204;
constexpr int NET_ERR_BAD_REQUEST = 400;

constexpr int NET_ERR_REDIRECT_CLASS_MAX = 399;
constexpr int NET_ERR_REQUEST_ERROR_CLASS_MAX = 499;
constexpr int MAX_ARP_DNS_CHECK_INTERVAL = 5;
constexpr int MAX_ARP_DNS_CHECK_TIME = 1000;
constexpr int MAX_RESULT_NUM = 2;
constexpr int PORTAL_CONTENT_LENGTH_MIN = 4;
constexpr int TIME_OUT_COUNT = 4000;

StaNetworkCheck::StaNetworkCheck(NetStateHandler nethandle, ArpStateHandler arpHandle, DnsStateHandler dnsHandle,
    int instId)
{
    WIFI_LOGI("StaNetworkCheck constructor\n");
    pDealNetCheckThread = nullptr;
    netStateHandler = nethandle;
    arpStateHandler = arpHandle;
    dnsStateHandler = dnsHandle;
    lastNetState = NETWORK_STATE_UNKNOWN;
    isStopNetCheck = true;
    isExitNetCheckThread = false;
    isExited = true;
    lastArpDnsCheckTime = std::chrono::steady_clock::now();
    WifiSettings::GetInstance().GetPortalUri(mUrlInfo);
    m_instId = instId;
    WIFI_LOGI("HttpPortalDetection http=%{public}s, https=%{public}s, httpbak=%{public}s, httpsbak=%{public}s,",
        mUrlInfo.portalHttpUrl.c_str(), mUrlInfo.portalHttpsUrl.c_str(), mUrlInfo.portalBakHttpUrl.c_str(),
        mUrlInfo.portalBakHttpsUrl.c_str());
}

StaNetworkCheck::~StaNetworkCheck()
{
    WIFI_LOGI("StaNetworkCheck::~StaNetworkCheck enter\n");
    ExitNetCheckThread();
    WIFI_LOGI("StaNetworkCheck::~StaNetworkCheck complete\n");
}

void StaNetworkCheck::SetHttpResultInfo(std::string url, int codeNum, int codeLenNum)
{
    bool isHttps = (url == mUrlInfo.portalHttpsUrl || url == mUrlInfo.portalBakHttpsUrl);
    if (isHttps) {
        httpsUrl = url;
        httpsCodeNum = codeNum;
        httpsResultLen = codeLenNum;
    } else {
        httpUrl = url;
        httpCodeNum = codeNum;
        httpResultLen = codeLenNum;
    }
}

void StaNetworkCheck::DnsDetection(std::string url)
{
    if (dnsStateHandler) {
        if (!dnsChecker.DoDnsCheck(url, MAX_ARP_DNS_CHECK_TIME)) {
            WIFI_LOGE("RunNetCheckThreadFunc dns check unreachable.");
            dnsStateHandler(StaDnsState::DNS_STATE_UNREACHABLE);
        } else {
            WIFI_LOGI("RunNetCheckThreadFunc dns check normal.");
            dnsStateHandler(StaDnsState::DNS_STATE_WORKING);
        }
    }
}

void StaNetworkCheck::CheckResponseCode(std::string url, int codeNum, int contLenNum)
{
    bool isHttps = (url == mUrlInfo.portalHttpsUrl || url == mUrlInfo.portalBakHttpsUrl);
    if (isHttps && codeNum == NET_ERR_NO_CONTENT) {
        WIFI_LOGE("This network is normal!");
        if (lastNetState.load() != NETWORK_STATE_WORKING) {
            netStateHandler(StaNetState::NETWORK_STATE_WORKING, "");
        }
        lastNetState = NETWORK_STATE_WORKING;
    } else if (!isHttps && codeNum != NET_ERR_NO_CONTENT &&
        (codeNum >= NET_ERR_CREATED && codeNum <= NET_ERR_REDIRECT_CLASS_MAX)) {
        /* Callback result to InterfaceService. */
        WIFI_LOGI("This network is portal AP, need certification1!");
        netStateHandler(StaNetState::NETWORK_CHECK_PORTAL, url);
        lastNetState = NETWORK_CHECK_PORTAL;
    } else if (!isHttps &&
        (codeNum == NET_ERR_OK || (codeNum >= NET_ERR_BAD_REQUEST && codeNum <= NET_ERR_REQUEST_ERROR_CLASS_MAX)) &&
        contLenNum > PORTAL_CONTENT_LENGTH_MIN) {
        WIFI_LOGI("This network is portal AP, need certification!");
        netStateHandler(StaNetState::NETWORK_CHECK_PORTAL, url);
        lastNetState = NETWORK_CHECK_PORTAL;
    } else if (isHttps && (lastNetState.load() != NETWORK_STATE_NOINTERNET) &&
        (lastNetState.load() != NETWORK_CHECK_PORTAL)) {
        WIFI_LOGE("http detect network not working!");
        lastNetState = NETWORK_STATE_NOINTERNET;
    } else {
        WIFI_LOGE("http detect unknow network!");
    }
}
#ifndef OHOS_ARCH_LITE
int StaNetworkCheck::HttpPortalDetection(const std::string &url)
{
    NetStack::HttpClient::HttpClientRequest httpReq;
    httpReq.SetURL(url);
    std::string method = "GET";
    httpReq.SetMethod(method);
    httpReq.SetHeader("Accept", "*/*");
    httpReq.SetHeader("Accept-Language", "cn");
    httpReq.SetHeader("User-Agent", "Mozilla/4.0");
    httpReq.SetHeader("Host", "connectivitycheck.platform.hicloud.com");
    httpReq.SetHeader("Cache-Control", "no-cache");
    httpReq.SetHeader("Connection", "Keep-Alive");
    httpReq.SetTimeout(HTTP_DETECTION_TIMEOUT);
    NetStack::HttpClient::HttpSession &session = NetStack::HttpClient::HttpSession::GetInstance();
    auto task = session.CreateTask(httpReq);
    if (task == nullptr || task->GetCurlHandle() == nullptr) {
        WIFI_LOGE("http create task failed !");
        return -1;
    }

    task->OnSuccess([task, this](const NetStack::HttpClient::HttpClientRequest &request,
        const NetStack::HttpClient::HttpClientResponse &response) {
        std::string url = request.GetURL();
        int codeNum = response.GetResponseCode();
        int contLenNum = 0;
        std::map<std::string, std::string> headers = response.GetHeaders();
        auto iter = headers.find("content-length");
        if (iter == headers.end()) {
            WIFI_LOGI("http can not find content-length!");
        } else {
            contLenNum = std::atoi(iter->second.c_str());
        }
        detectResultNum++;
        SetHttpResultInfo(url, codeNum, contLenNum);
        if (detectResultNum >= MAX_RESULT_NUM) {
            WIFI_LOGI("http detect result collect ok!");
            isStopNetCheck = false;
            mCondition.notify_one();
        }
        WIFI_LOGI("HttpPortalDetection OnSuccess,url:%{public}s, codeNum:%{public}d, contLenNum:%{public}d",
            url.c_str(), codeNum, contLenNum);
    });

    task->OnFail([this](const NetStack::HttpClient::HttpClientRequest &request,
        const NetStack::HttpClient::HttpClientResponse &response, const NetStack::HttpClient::HttpClientError &error) {
        std::string url = request.GetURL();
        int codeNum = response.GetResponseCode();
        SetHttpResultInfo(url, codeNum, 0);
        detectResultNum++;
        if (detectResultNum >= MAX_RESULT_NUM) {
            WIFI_LOGI("http detect result collect!");
            isStopNetCheck = false;
            mCondition.notify_one();
        }
        WIFI_LOGE("HttpPortalDetection OnFailed, url:%{public}s, responseCode:%{public}d", url.c_str(), codeNum);
    });
    
    task->Start();
    return 0;
}
#endif
void StaNetworkCheck::RunNetCheckThreadFunc()
{
    WIFI_LOGI("enter RunNetCheckThreadFunc!\n");
    isExited = false;
    for (;;) {
        while (isStopNetCheck && !isExitNetCheckThread) {
            WIFI_LOGI("waiting for signal.\n");
            std::unique_lock<std::mutex> lck(mMutex);
            mCondition.wait(lck);
        }
        if (isExitNetCheckThread) {
            WIFI_LOGI("break the loop\n");
            isExited = true;
            break;
        }
#ifndef OHOS_ARCH_LITE
        if (mainDetectFinsh && mainNetState != NETWORK_CHECK_PORTAL && mainNetState != NETWORK_STATE_WORKING) {
            WIFI_LOGE("http bak detect start!");
            HttpPortalDetection(mUrlInfo.portalBakHttpUrl);
            HttpPortalDetection(mUrlInfo.portalBakHttpsUrl);
            DnsDetection(mUrlInfo.portalBakHttpUrl);
        }
#endif
        if (detectResultNum >= MAX_RESULT_NUM) {
            CheckResponseCode(httpUrl, httpCodeNum, httpResultLen);
            if (lastNetState != NETWORK_CHECK_PORTAL) {
                CheckResponseCode(httpsUrl, httpsCodeNum, httpsResultLen);
            }
            detectResultNum = 0;
            if (httpUrl == mUrlInfo.portalHttpUrl) {
                mainNetState = lastNetState;
                mainDetectFinsh = true;
            } else {
                bakNetState = lastNetState;
                bakDetectFinsh = true;
            }
        }
        if (lastNetState == NETWORK_CHECK_PORTAL || lastNetState == NETWORK_STATE_WORKING) {
            isStopNetCheck = true;
        }
        WIFI_LOGD("http detect mainDetectFinsh:%{public}d, mainDetectFinsh:%{public}d bakNetState:%{public}d "
                  "mainNetState:%{public}d!",
            static_cast<int>(mainDetectFinsh), static_cast<int>(bakDetectFinsh), static_cast<int>(mainNetState),
            static_cast<int>(bakNetState));
        if (bakDetectFinsh && mainDetectFinsh &&
            ((mainNetState != NETWORK_CHECK_PORTAL && mainNetState != NETWORK_STATE_WORKING &&
            bakNetState == NETWORK_STATE_NOINTERNET) ||
            (bakNetState != NETWORK_CHECK_PORTAL && bakNetState != NETWORK_STATE_WORKING &&
            mainNetState == NETWORK_STATE_NOINTERNET))) {
            WIFI_LOGE("http detect result is not working!");
            netStateHandler(StaNetState::NETWORK_STATE_NOINTERNET, "");
            if (!arpChecker.DoArpCheck(MAX_ARP_DNS_CHECK_TIME, true)) {
                LOGI("RunNetCheckThreadFunc arp check failed.");
                arpStateHandler(StaArpState::ARP_STATE_UNREACHABLE);
            }
            isStopNetCheck = true;
        }

        std::chrono::steady_clock::time_point current = std::chrono::steady_clock::now();
        if (static_cast<int>((lastArpDnsCheckTime - current).count()) >= MAX_ARP_DNS_CHECK_INTERVAL) {
            DnsDetection(mUrlInfo.portalHttpUrl);
            lastArpDnsCheckTime = current;
        }

        if (!isExitNetCheckThread) {
            std::unique_lock<std::mutex> lck(mMutex);
            if (mCondition_timeout.wait_for(lck, std::chrono::milliseconds(HTTP_BACKUP_TIMEOUT)) ==
                std::cv_status::timeout) {
                WIFI_LOGI("mCondition_timeout timeout.\n");
            } else {
                WIFI_LOGI("Wake up, break the loop.\n");
                isExited = true;
                break;
            }
        }
    }
}

ErrCode StaNetworkCheck::InitNetCheckThread()
{
    pDealNetCheckThread = new (std::nothrow) std::thread(&StaNetworkCheck::RunNetCheckThreadFunc, this);
    if (pDealNetCheckThread == nullptr) {
        WIFI_LOGE("In StaNetworkCheck start NetCheck thread failed!\n");
        return ErrCode::WIFI_OPT_FAILED;
    }
    pthread_setname_np(pDealNetCheckThread->native_handle(), "NetCheckThread");
    return ErrCode::WIFI_OPT_SUCCESS;
}

void StaNetworkCheck::StopNetCheckThread()
{
    WIFI_LOGI("enter StopNetCheckThread!\n");
    isStopNetCheck = true;
}

void StaNetworkCheck::SignalNetCheckThread()
{
    WIFI_LOGI("enter SignalNetCheckThread!\n");
    if (isStopNetCheck == false) {
        WIFI_LOGI("detection is now running!\n");
        return;
    }
    // get mac address
    std::string macAddress;
    WifiSettings::GetInstance().GetMacAddress(macAddress, m_instId);
    // get ip,gateway address
    WifiLinkedInfo linkedInfo;
    WifiSettings::GetInstance().GetLinkedInfo(linkedInfo, m_instId);
    std::string ipAddress = IpTools::ConvertIpv4Address(linkedInfo.ipAddress);
    std::string ifname = "wlan" + std::to_string(m_instId);
    // get dns address
    IpInfo ipinfo;
    WifiSettings::GetInstance().GetIpInfo(ipinfo, m_instId);
    std::string priDns = IpTools::ConvertIpv4Address(ipinfo.primaryDns);
    std::string secondDns = IpTools::ConvertIpv4Address(ipinfo.secondDns);
    std::string gateway = IpTools::ConvertIpv4Address(ipinfo.gateway);
    dnsChecker.Start(priDns, secondDns);
    arpChecker.Start(ifname, macAddress, ipAddress, gateway);
    lastNetState = NETWORK_STATE_UNKNOWN;
    isStopNetCheck = false;
    detectResultNum = 0;
    mainDetectFinsh = false;
    bakDetectFinsh = false;
    httpUrl = "";
    httpsUrl = "";
    httpCodeNum = 0;
    httpsCodeNum = 0;
    httpResultLen = 0;
    httpsResultLen = 0;
    bakNetState = NETWORK_STATE_UNKNOWN;
    mainNetState = NETWORK_STATE_UNKNOWN;
    lastArpDnsCheckTime = std::chrono::steady_clock::now();
    mCondition.notify_one();
#ifndef OHOS_ARCH_LITE
    HttpPortalDetection(mUrlInfo.portalHttpUrl);
    HttpPortalDetection(mUrlInfo.portalHttpsUrl);
#endif
}

void StaNetworkCheck::ExitNetCheckThread()
{
    WIFI_LOGI("enter StaNetworkCheck::ExitNetCheckThread");
    int timeout = TIME_OUT_COUNT;
    isStopNetCheck = false;
    isExitNetCheckThread = true;
    while (!isExited) {
        timeout--;
        if (timeout < 0) {
            if (pDealNetCheckThread != nullptr) {
                delete pDealNetCheckThread;
                pDealNetCheckThread = nullptr;
            }
            WIFI_LOGI("StaNetworkCheck::ExitNetCheckThread TimeOut Exit");
            return;
        }
        isExitNetCheckThread = true;
        mCondition.notify_one();
        mCondition_timeout.notify_one();
        std::this_thread::sleep_for(std::chrono::milliseconds(1)); // sleep 1 ms
    }
    if (pDealNetCheckThread != nullptr) {
        if (pDealNetCheckThread->joinable()) {
            WIFI_LOGI("Exit net check join()");
            pDealNetCheckThread->join();
        }
        delete pDealNetCheckThread;
        pDealNetCheckThread = nullptr;
        WIFI_LOGI("Exit net check done");
    }
}
}  // namespace Wifi
}  // namespace OHOS
