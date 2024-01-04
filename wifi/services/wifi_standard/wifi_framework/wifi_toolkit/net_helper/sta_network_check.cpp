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
#include "wifi_hisysevent.h"
#include "define.h"
#ifndef OHOS_ARCH_LITE
#include <curl/curl.h>
#include <curl/easy.h>
#include "http_client_request.h"
#include "http_client.h"
#include "wifi_common_util.h"
#endif

DEFINE_WIFILOG_LABEL("StaNetworkCheck");
const static std::string IFNAME = "wlan";
namespace OHOS {
namespace Wifi {
using TimeOutCallback = std::function<void()>;
constexpr int NET_ERR_OK = 200;
constexpr int NET_ERR_NO_CONTENT = 204;

constexpr int NET_ERR_REDIRECT_CLASS_MAX = 399;
constexpr int MAX_ARP_DNS_CHECK_TIME = 1000;
constexpr int MAX_RESULT_NUM = 2;
constexpr int TIME_OUT_COUNT = 4000;
const std::string CA_CERT_PATH = "/etc/ssl/certs/cacert.pem";

StaNetworkCheck::StaNetworkCheck(NetStateHandler nethandle, ArpStateHandler arpHandle, DnsStateHandler dnsHandle,
    int instId)
{
    WIFI_LOGI("StaNetworkCheck constructor\n");
    pDealNetCheckThread = nullptr;
    netStateHandler = nethandle;
    arpStateHandler = arpHandle;
    dnsStateHandler = dnsHandle;
    isStopNetCheck = true;
    isExitNetCheckThread = false;
    isExited = true;
    m_timerId = 0;
    m_screenState = MODE_STATE_OPEN;
#ifndef OHOS_ARCH_LITE
    mDetectionEventHandler = std::make_unique<WifiEventHandler>("DnsArpDetectionThread");
#endif
    WifiSettings::GetInstance().GetPortalUri(mUrlInfo);
    m_instId = instId;
    WIFI_LOGI("HttpPortalDetection http=%{public}s, https=%{public}s, httpbak=%{public}s, httpsbak=%{public}s,",
        mUrlInfo.portalHttpUrl.c_str(), mUrlInfo.portalHttpsUrl.c_str(), mUrlInfo.portalBakHttpUrl.c_str(),
        mUrlInfo.portalBakHttpsUrl.c_str());
}

StaNetworkCheck::~StaNetworkCheck()
{
    WIFI_LOGI("StaNetworkCheck::~StaNetworkCheck enter\n");
#ifndef OHOS_ARCH_LITE
    if (mDetectionEventHandler) {
        mDetectionEventHandler.reset();
    }
#endif
    ExitNetCheckThread();
    WIFI_LOGI("StaNetworkCheck::~StaNetworkCheck complete\n");
}

void StaNetworkCheck::ClearHttpResultInfo()
{
    mainHttpResult.HttpClear();
    mainHttpResult.httpUrl = mUrlInfo.portalHttpUrl;
    mainHttpsResult.HttpClear();
    mainHttpsResult.httpUrl = mUrlInfo.portalHttpsUrl;
    bakHttpResult.HttpClear();
    bakHttpResult.httpUrl = mUrlInfo.portalBakHttpUrl;
    bakHttpsResult.HttpClear();
    bakHttpsResult.httpUrl = mUrlInfo.portalBakHttpsUrl;
}

void StaNetworkCheck::SetHttpResultInfo(std::string url, int codeNum, int codeLenNum, StaNetState netState)
{
    bool isHttps = (url == mUrlInfo.portalHttpsUrl || url == mUrlInfo.portalBakHttpsUrl);
    bool isMain = (url == mUrlInfo.portalHttpUrl || url == mUrlInfo.portalHttpsUrl);
    HttpResult* httpResult = &mainHttpResult;
    if (isHttps && isMain) {
        httpResult = &mainHttpsResult;
    } else if (!isHttps && isMain) {
        httpResult = &mainHttpResult;
    } else if (isHttps && !isMain) {
        httpResult = &bakHttpsResult;
    } else {
        httpResult = &bakHttpResult;
    }
    httpResult->httpUrl = url;
    httpResult->httpCodeNum = codeNum;
    httpResult->httpResultLen = codeLenNum;
    httpResult->netState = netState;
    httpResult->hasResult = true;
}

void StaNetworkCheck::DnsDetection(std::string url)
{
    if (dnsStateHandler) {
#ifndef OHOS_ARCH_LITE
        if (mDetectionEventHandler) {
            mDetectionEventHandler->PostSyncTask(
                [this, &url]() {
                    if (!dnsChecker.DoDnsCheck(url, MAX_ARP_DNS_CHECK_TIME)) {
                        WIFI_LOGE("RunNetCheckThreadFunc dns check unreachable.");
                        dnsStateHandler(StaDnsState::DNS_STATE_UNREACHABLE);
                    } else {
                        WIFI_LOGI("RunNetCheckThreadFunc dns check normal.");
                        dnsStateHandler(StaDnsState::DNS_STATE_WORKING);
                    }
                });
        }
#endif
    }
}

void StaNetworkCheck::ArpDetection()
{
    if (arpStateHandler) {
#ifndef OHOS_ARCH_LITE
        if (mDetectionEventHandler) {
            mDetectionEventHandler->PostSyncTask(
                [this]() {
                    if (!arpChecker.DoArpCheck(MAX_ARP_DNS_CHECK_TIME, true)) {
                        LOGI("RunNetCheckThreadFunc arp check failed.");
                        arpStateHandler(StaArpState::ARP_STATE_UNREACHABLE);
                        WriteWifiAccessIntFailedHiSysEvent(ARP_OPT, StaArpState::ARP_STATE_UNREACHABLE);
                    }
                });
        }
#endif
    }
}

void StaNetworkCheck::NetWorkCheckSetScreenState(int state)
{
    m_screenState = state;
}
StaNetState StaNetworkCheck::CheckResponseCode(std::string url, int codeNum)
{
    lastNetState = NETWORK_STATE_UNKNOWN;
    bool isHttps = (url == mUrlInfo.portalHttpsUrl || url == mUrlInfo.portalBakHttpsUrl);
    if (isHttps && codeNum == NET_ERR_NO_CONTENT) {
        WIFI_LOGE("This network is normal!");
        lastNetState = NETWORK_STATE_WORKING;
    } else if (!isHttps && codeNum != NET_ERR_NO_CONTENT &&
        (codeNum >= NET_ERR_OK && codeNum <= NET_ERR_REDIRECT_CLASS_MAX)) {
        /* Callback result to InterfaceService. */
        WIFI_LOGI("This network is portal AP, need certification1!");
        lastNetState = NETWORK_CHECK_PORTAL;
    } else if (isHttps && (lastNetState.load() != NETWORK_STATE_NOINTERNET) &&
        (lastNetState.load() != NETWORK_CHECK_PORTAL)) {
        WIFI_LOGE("http detect network not working!");
        lastNetState = NETWORK_STATE_NOINTERNET;
        WriteWifiAccessIntFailedHiSysEvent(DETECT_NOT_NETWORK, NETWORK_STATE_NOINTERNET);
    } else {
        WIFI_LOGE("http detect unknow network!");
    }
    return lastNetState;
}
#ifndef OHOS_ARCH_LITE
int StaNetworkCheck::HttpPortalDetection(const std::string &url) __attribute__((no_sanitize("cfi")))
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
    httpReq.SetCaPath(CA_CERT_PATH);
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
        StaNetState netState = CheckResponseCode(url, codeNum);
        SetHttpResultInfo(url, codeNum, contLenNum, netState);
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
        StaNetState netState = CheckResponseCode(url, codeNum);
        SetHttpResultInfo(url, codeNum, 0, netState);
        detectResultNum++;
        if (detectResultNum >= MAX_RESULT_NUM) {
            WIFI_LOGI("http detect result collect!");
            isStopNetCheck = false;
            mCondition.notify_one();
        }
        WIFI_LOGE("HttpPortalDetection OnFailed, url:%{public}s, responseCode:%{public}d", url.c_str(), codeNum);
    });
    CURLcode errCode = CURLE_OK;
    errCode = curl_easy_setopt(task->GetCurlHandle(), CURLOPT_INTERFACE, (IFNAME + std::to_string(m_instId)).c_str());
    if (errCode != CURLE_OK) {
        WIFI_LOGE("CURLOPT_INTERFACE failed errCode:%{public}d", errCode);
        return -1;
    }
    task->Start();
    return 0;
}
#endif

void StaNetworkCheck::HttpProbeTimeout() __attribute__((no_sanitize("cfi")))
{
    WIFI_LOGE("HttpProbeTimeout http bak detect start!");
#ifndef OHOS_ARCH_LITE
    DnsDetection(mUrlInfo.portalBakHttpUrl);
    HttpPortalDetection(mUrlInfo.portalBakHttpUrl);
    HttpPortalDetection(mUrlInfo.portalBakHttpsUrl);
    StopHttpProbeTimer();
#endif
}

void StaNetworkCheck::StopHttpProbeTimer()
{
#ifndef OHOS_ARCH_LITE
    WIFI_LOGI("StopHttpProbeTimer! m_timerId:%{public}u", m_timerId);
    WifiTimer::GetInstance()->UnRegister(m_timerId);
    m_timerId = 0;
    return;
#endif
}

void StaNetworkCheck::RunNetCheckThreadFunc()
{
    WIFI_LOGI("enter RunNetCheckThreadFunc!\n");
    int maxCount = 20;
    int curCount = 0;
    isExited = false;
    for (;;) {
        while (isStopNetCheck && !isExitNetCheckThread) {
            WIFI_LOGI("waiting for signal.\n");
            curCount = 0;
            std::unique_lock<std::mutex> lck(mMutex);
            mCondition.wait(lck);
        }
        if (isExitNetCheckThread) {
            WIFI_LOGI("break the loop\n");
            isExited = true;
            break;
        }
        WIFI_LOGD("http detect mainHttpResult:%{public}d, mainHttpsResult:%{public}d bakHttpResult:%{public}d "
                  "bakHttpsResult:%{public}d!", static_cast<int>(mainHttpResult.hasResult), 
                  static_cast<int>(mainHttpsResult.hasResult), static_cast<int>(bakHttpResult.hasResult),
                  static_cast<int>(bakHttpsResult.hasResult));

        if ((mainHttpResult.hasResult && mainHttpResult.netState == NETWORK_CHECK_PORTAL) ||
        (bakHttpResult.hasResult && bakHttpResult.netState == NETWORK_CHECK_PORTAL)) {
            isStopNetCheck = true;
            StopHttpProbeTimer();
            if (mainHttpResult.netState == NETWORK_CHECK_PORTAL) {
                netStateHandler(NETWORK_CHECK_PORTAL, mainHttpResult.httpUrl);
            } else {
                netStateHandler(NETWORK_CHECK_PORTAL, bakHttpResult.httpUrl);
            }
            continue;
        }
        if ((mainHttpsResult.hasResult && mainHttpsResult.netState == NETWORK_STATE_WORKING) ||
        (bakHttpsResult.hasResult && bakHttpsResult.netState == NETWORK_STATE_WORKING)) {
            isStopNetCheck = true;
            StopHttpProbeTimer();
            netStateHandler(NETWORK_STATE_WORKING, mainHttpResult.httpUrl);
            continue;
        }

        if (mainHttpsResult.hasResult && bakHttpsResult.hasResult &&
            (mainHttpsResult.netState == NETWORK_STATE_NOINTERNET && bakHttpsResult.netState == NETWORK_STATE_NOINTERNET)) {
            WIFI_LOGE("http detect result is not working!");
            netStateHandler(StaNetState::NETWORK_STATE_NOINTERNET, "");
            ArpDetection();
            StopHttpProbeTimer();
            isStopNetCheck = true;
            WriteWifiAccessIntFailedHiSysEvent(HTTP_OPT, NETWORK_STATE_NOINTERNET);
            continue;
        }

        curCount++;
        if (curCount > maxCount) {
            isStopNetCheck = true;
            netStateHandler(StaNetState::NETWORK_STATE_UNKNOWN, "");
            WIFI_LOGE("http detect times over max counts!");
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
    if (isStopNetCheck == false || m_screenState == MODE_STATE_CLOSE) {
        WIFI_LOGI("detection is now running or screen %{public}d!\n", m_screenState);
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
    isStopNetCheck = false;
    detectResultNum = 0;
    ClearHttpResultInfo();
    mCondition.notify_one();
#ifndef OHOS_ARCH_LITE
    HttpPortalDetection(mUrlInfo.portalHttpUrl);
    HttpPortalDetection(mUrlInfo.portalHttpsUrl);
    DnsDetection(mUrlInfo.portalHttpUrl);
    TimeOutCallback timeoutCallback = std::bind(&StaNetworkCheck::HttpProbeTimeout, this);
    WifiTimer::GetInstance()->Register(timeoutCallback, m_timerId, HTTP_BACKUP_TIMEOUT);
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
