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

#include "dhcp_client_service_impl.h"

#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "dhcp_func.h"
#include "securec.h"
#include "wifi_logger.h"

DEFINE_WIFILOG_DHCP_LABEL("DhcpClientServiceImpl");

namespace OHOS {
namespace Wifi {
DhcpClientServiceImpl::DhcpClientServiceImpl()
{
    isExitDhcpResultHandleThread = false;
    pDhcpResultHandleThread = nullptr;
    m_mapDhcpRecvMsgThread.clear();

    m_mapDhcpInfo.clear();
    m_mapDhcpResult.clear();
    m_mapDhcpResultNotify.clear();

    InitDhcpMgrThread();
}

DhcpClientServiceImpl::~DhcpClientServiceImpl()
{
    ExitDhcpMgrThread();
}

int DhcpClientServiceImpl::InitDhcpMgrThread()
{
    pDhcpResultHandleThread = new std::thread(&DhcpClientServiceImpl::RunDhcpResultHandleThreadFunc, this);
    if (pDhcpResultHandleThread == nullptr) {
        WIFI_LOGE("DhcpClientServiceImpl::InitDhcpMgrThread() init pDhcpResultHandleThread failed!\n");
        return DHCP_OPT_FAILED;
    }

    return DHCP_OPT_SUCCESS;
}

void DhcpClientServiceImpl::ExitDhcpMgrThread()
{
    isExitDhcpResultHandleThread = true;

    if (pDhcpResultHandleThread != nullptr) {
        pDhcpResultHandleThread->join();
        delete pDhcpResultHandleThread;
        pDhcpResultHandleThread = nullptr;
    }

    if (!m_mapDhcpResultNotify.empty()) {
        WIFI_LOGE("ExitDhcpMgrThread() error, m_mapDhcpResultNotify is not empty!\n");
        m_mapDhcpResultNotify.clear();
    }

    if (!m_mapDhcpRecvMsgThread.empty()) {
        WIFI_LOGE("ExitDhcpMgrThread() error, m_mapDhcpRecvMsgThread is not empty!\n");
        for (auto &mapThread : m_mapDhcpRecvMsgThread) {
            int nStatus = GetDhcpStatus(mapThread.first);
            WIFI_LOGE("ExitDhcpMgrThread() ifname:%{public}s, status:%{public}d!\n",
                (mapThread.first).c_str(), nStatus);
        }
    }
}

void DhcpClientServiceImpl::CheckTimeout()
{
    uint32_t tempTime = 0;
    uint32_t curTime = (uint32_t)time(NULL);
    for (auto &itemNotify : m_mapDhcpResultNotify) {
        std::string ifname = itemNotify.first;
        WIFI_LOGI("CheckTimeout() ifname:%{public}s, notify1 second size:%{public}d.\n",
            ifname.c_str(),
            (int)itemNotify.second.size());
        auto iterReq = itemNotify.second.begin();
        while (iterReq != itemNotify.second.end()) {
            if ((*iterReq == nullptr) || ((*iterReq)->pResultNotify == nullptr)) {
                WIFI_LOGE("DhcpClientServiceImpl::CheckTimeout() error, *iterReq or pResultNotify is nullptr!\n");
                return;
            }
            tempTime = (*iterReq)->getTimestamp + (*iterReq)->timeouts;
            if (tempTime <= curTime) {
                /* get dhcp result timeout */
                WIFI_LOGW("CheckTimeout() ifname:%{public}s get timeout, getTime:%{public}u,timeout:%{public}d, "
                          "curTime:%{public}u!\n",
                    ifname.c_str(),
                    (*iterReq)->getTimestamp,
                    (*iterReq)->timeouts,
                    curTime);
                (*iterReq)->pResultNotify->OnFailed(DHCP_OPT_TIMEOUT, ifname, "get dhcp result timeout!");
                delete *iterReq;
                iterReq = itemNotify.second.erase(iterReq);
            } else {
                ++iterReq;
            }
        }
    }
}

void DhcpClientServiceImpl::DhcpResultHandle(uint32_t &second)
{
    std::unique_lock<std::mutex> lock(mResultNotifyMutex);
    if (m_mapDhcpResultNotify.empty()) {
        second = SLEEP_TIME_200_MS;
        return;
    }

    /* Check timeout */
    CheckTimeout();
    auto iterNotify = m_mapDhcpResultNotify.begin();
    while (iterNotify != m_mapDhcpResultNotify.end()) {
        /* Check dhcp result notify size */
        std::string ifname = iterNotify->first;
        if (iterNotify->second.size() <= 0) {
            iterNotify = m_mapDhcpResultNotify.erase(iterNotify);
            WIFI_LOGI("DhcpResultHandle() ifname:%{public}s, dhcp result notify size:0, erase!\n", ifname.c_str());
            continue;
        }

        /* Check dhcp result */
        auto iterDhcpResult = m_mapDhcpResult.find(ifname);
        if (iterDhcpResult == m_mapDhcpResult.end()) {
            WIFI_LOGI("DhcpResultHandle() ifname:%{public}s, dhcp result is getting...\n", ifname.c_str());
            ++iterNotify;
            continue;
        }

        auto iterReq = iterNotify->second.begin();
        while (iterReq != iterNotify->second.end()) {
            if ((*iterReq == nullptr) || ((*iterReq)->pResultNotify == nullptr)) {
                WIFI_LOGE("DhcpResultHandle() %{public}s iterReq or pResultNotify is nullptr!\n", ifname.c_str());
                second = SLEEP_TIME_500_MS;
                return;
            }

            /* Handle dhcp result notify */
            WIFI_LOGI("DhcpResultHandle() ifname:%{public}s, isOptSuc:%{public}d.\n",
                ifname.c_str(), (iterDhcpResult->second).isOptSuc);
            if ((iterDhcpResult->second).isOptSuc) {
                /* get dhcp result success */
                WIFI_LOGI("DhcpResultHandle() ifname:%{public}s get dhcp result success!\n", ifname.c_str());
                (*iterReq)->pResultNotify->OnSuccess(DHCP_OPT_SUCCESS, ifname, iterDhcpResult->second);
            } else {
                /* get dhcp result failed */
                WIFI_LOGE("DhcpResultHandle() ifname:%{public}s get dhcp result failed!\n", ifname.c_str());
                (*iterReq)->pResultNotify->OnFailed(DHCP_OPT_FAILED, ifname, "get dhcp result failed!");
            }
            delete *iterReq;
            iterReq = iterNotify->second.erase(iterReq);
        }

        ++iterNotify;
    }

    WIFI_LOGI("DhcpResultHandle() dhcp result notify finished.\n");
    second = SLEEP_TIME_500_MS;
}

void DhcpClientServiceImpl::RunDhcpResultHandleThreadFunc()
{
    for (; ;) {
        if (isExitDhcpResultHandleThread) {
            WIFI_LOGI("RunDhcpResultHandleThreadFunc() isExitDhcpResultHandleThread:1, break!\n");
            break;
        }

        uint32_t uSleepSec = SLEEP_TIME_500_MS;
        DhcpResultHandle(uSleepSec);
        usleep(uSleepSec);
    }

    WIFI_LOGI("DhcpClientServiceImpl::RunDhcpResultHandleThreadFunc() end!\n");
}

void DhcpClientServiceImpl::RunDhcpRecvMsgThreadFunc(const std::string &ifname)
{
    if (ifname.empty()) {
        WIFI_LOGE("DhcpClientServiceImpl::RunDhcpRecvMsgThreadFunc() error, ifname is empty!\n");
        return;
    }

    struct DhcpPacketResult result;
    std::string strResultFile = DHCP_WORK_DIR + ifname + DHCP_RESULT_FILETYPE;
    for (; ;) {
        /* Check break condition. */
        auto iter = this->m_mapDhcpInfo.find(ifname);
        if ((iter != this->m_mapDhcpInfo.end()) && ((iter->second).clientRunStatus) != 1) {
            WIFI_LOGI("RunDhcpRecvMsgThreadFunc() Status != 1, need break, ifname:%{public}s.\n", ifname.c_str());
            break;
        }

        /* Check dhcp result file is or not exist. */
        if (!DhcpFunc::IsExistFile(strResultFile)) {
            usleep(SLEEP_TIME_200_MS);
            continue;
        }

        if (memset_s(&result, sizeof(result), 0, sizeof(result)) != EOK) {
            return;
        }
        int nGetRet = DhcpFunc::GetDhcpPacketResult(strResultFile, result);
        if (nGetRet == DHCP_OPT_SUCCESS) {
            /* Get success, add or reload dhcp packet info. */
            this->DhcpPacketInfoHandle(ifname, result);
            usleep(SLEEP_TIME_500_MS);
        } else if (nGetRet == DHCP_OPT_FAILED) {
            /* Get failed, print dhcp packet info. */
            this->DhcpPacketInfoHandle(ifname, result, false);
            usleep(SLEEP_TIME_500_MS);
        } else {
            /* Get null, continue get dhcp packet info. */
            WIFI_LOGI("RunDhcpRecvMsgThreadFunc() GetDhcpPacketResult NULL, ifname:%{public}s.\n", ifname.c_str());
            usleep(SLEEP_TIME_200_MS);
        }

        continue;
    }
}

void DhcpClientServiceImpl::DhcpPacketInfoHandle(
    const std::string &ifname, struct DhcpPacketResult &packetResult, bool success)
{
    if (ifname.empty()) {
        WIFI_LOGE("DhcpClientServiceImpl::DhcpPacketInfoHandle() error, ifname is empty!\n");
        return;
    }

    DhcpResult result;
    auto iterResult = m_mapDhcpResult.find(ifname);
    if (!success) {
        /* get failed */
        if (iterResult != m_mapDhcpResult.end()) {
            iterResult->second = result;
        } else {
            m_mapDhcpResult.emplace(std::make_pair(ifname, result));
        }
        return;
    }

    /* Check dhcp result add time */
    if ((iterResult != m_mapDhcpResult.end()) && ((iterResult->second).uAddTime == packetResult.uAddTime)) {
        return;
    }
    WIFI_LOGI("DhcpPacketInfoHandle() DhcpResult %{public}s old %{public}u no equal new %{public}u, need update...\n",
        ifname.c_str(), (iterResult->second).uAddTime, packetResult.uAddTime);

    /* get success, add or reload dhcp packet info */
    auto iterInfo = m_mapDhcpInfo.find(ifname);
    if (iterInfo != m_mapDhcpInfo.end()) {
        m_mapDhcpInfo[ifname].serverIp = packetResult.strOptServerId;
        WIFI_LOGI("DhcpPacketInfoHandle() m_mapDhcpInfo find ifname:%{public}s.\n", ifname.c_str());
    }

    result.iptype = 0;
    result.isOptSuc = true;
    result.strYourCli = packetResult.strYiaddr;
    result.strServer = packetResult.strOptServerId;
    result.strSubnet = packetResult.strOptSubnet;
    result.strDns1 = packetResult.strOptDns1;
    result.strDns2 = packetResult.strOptDns2;
    result.strRouter1 = packetResult.strOptRouter1;
    result.strRouter2 = packetResult.strOptRouter2;
    result.strVendor = packetResult.strOptVendor;
    result.uLeaseTime = packetResult.uOptLeasetime;
    result.uAddTime = packetResult.uAddTime;
    result.uGetTime = (uint32_t)time(NULL);

    if (iterResult != m_mapDhcpResult.end()) {
        iterResult->second = result;
    } else {
        m_mapDhcpResult.emplace(std::make_pair(ifname, result));
    }
    WIFI_LOGI("DhcpPacketInfoHandle %{public}s, type:%{public}d, opt:%{public}d, cli:%{public}s, server:%{public}s, "
        "strSubnet:%{public}s, strDns1:%{public}s, strDns2:%{public}s, strRouter1:%{public}s, strRouter2:%{public}s, "
        "strVendor:%{public}s, uLeaseTime:%{public}u, uAddTime:%{public}u, uGetTime:%{public}u.\n",
        ifname.c_str(), result.iptype, result.isOptSuc, result.strYourCli.c_str(), result.strServer.c_str(),
        result.strSubnet.c_str(), result.strDns1.c_str(), result.strDns2.c_str(), result.strRouter1.c_str(),
        result.strRouter2.c_str(), result.strVendor.c_str(), result.uLeaseTime, result.uAddTime, result.uGetTime);
}

int DhcpClientServiceImpl::ForkExecChildProcess(const std::string &ifname, bool bIpv6, bool bStart)
{
    if (bIpv6) {
        /* get ipv4 and ipv6 */
        if (bStart) {
            const char *args[DHCP_CLI_ARGSNUM] = {DHCP_CLIENT_FILE.c_str(), "start", ifname.c_str(), "-a", nullptr};
            if (execv(args[0], const_cast<char *const *>(args)) == -1) {
                WIFI_LOGE("execv start v4 v6 failed,strerror(errno):%{public}s,ifname:%{public}s\n",
                    strerror(errno), ifname.c_str());
            }
        } else {
            const char *args[DHCP_CLI_ARGSNUM] = {DHCP_CLIENT_FILE.c_str(), "stop", ifname.c_str(), "-a", nullptr};
            if (execv(args[0], const_cast<char *const *>(args)) == -1) {
                WIFI_LOGE("execv stop v4 v6 failed,strerror(errno):%{public}s,ifname:%{public}s\n",
                    strerror(errno), ifname.c_str());
            }
        }
    } else {
        /* only get ipv4 */
        if (bStart) {
            const char *args[DHCP_CLI_ARGSNUM] = {DHCP_CLIENT_FILE.c_str(), "start", ifname.c_str(), "-4", nullptr};
            if (execv(args[0], const_cast<char *const *>(args)) == -1) {
                WIFI_LOGE("execv start v4 failed,strerror(errno):%{public}s,ifname:%{public}s\n",
                    strerror(errno), ifname.c_str());
            }
        } else {
            const char *args[DHCP_CLI_ARGSNUM] = {DHCP_CLIENT_FILE.c_str(), "stop", ifname.c_str(), "-4", nullptr};
            if (execv(args[0], const_cast<char *const *>(args)) == -1) {
                WIFI_LOGE("execv stop v4 failed,strerror(errno):%{public}s,ifname:%{public}s\n",
                    strerror(errno), ifname.c_str());
            }
        }
    }
    _exit(-1);
}

int DhcpClientServiceImpl::ForkExecParentProcess(const std::string &ifname, bool bIpv6, bool bStart, pid_t pid)
{
    if (bStart) {
        /* check and new receive dhcp packet msg thread */
        std::unique_lock<std::mutex> lock(mRecvMsgThreadMutex);
        auto iterRecvMsgThread = m_mapDhcpRecvMsgThread.find(ifname);
        if (iterRecvMsgThread != m_mapDhcpRecvMsgThread.end()) {
            WIFI_LOGE("ForkExecParentProcess() RecvMsgThread exist ifname:%{public}s, need erase!\n", ifname.c_str());
            return DHCP_OPT_FAILED;
        }
        std::thread *pThread = new std::thread(&DhcpClientServiceImpl::RunDhcpRecvMsgThreadFunc, this, ifname);
        if (pThread == nullptr) {
            WIFI_LOGE("ForkExecParentProcess() init pThread failed, ifname:%{public}s.\n", ifname.c_str());
            return DHCP_OPT_FAILED;
        }
        m_mapDhcpRecvMsgThread.emplace(std::make_pair(ifname, pThread));
        /* normal started, update dhcp client service running status */
        auto iter = m_mapDhcpInfo.find(ifname);
        if (iter != m_mapDhcpInfo.end()) {
            m_mapDhcpInfo[ifname].enableIPv6 = bIpv6;
            m_mapDhcpInfo[ifname].clientRunStatus = 1;
            m_mapDhcpInfo[ifname].clientProPid = pid;
        } else {
            DhcpServiceInfo dhcpInfo;
            dhcpInfo.enableIPv6 = bIpv6;
            dhcpInfo.clientRunStatus = 1;
            dhcpInfo.clientProPid = pid;
            m_mapDhcpInfo.emplace(std::make_pair(ifname, dhcpInfo));
        }
    } else {
        /* destroy recv msg thread */
        auto iter = m_mapDhcpInfo.find(ifname);
        if (iter != m_mapDhcpInfo.end()) {
            /* not start */
            m_mapDhcpInfo[ifname].clientRunStatus = 0;
            m_mapDhcpInfo[ifname].clientProPid = 0;
            std::unique_lock<std::mutex> lock(mRecvMsgThreadMutex);
            auto iterRecvMsgThreadMap = m_mapDhcpRecvMsgThread.find(ifname);
            if (iterRecvMsgThreadMap == m_mapDhcpRecvMsgThread.end()) {
                WIFI_LOGI("ForkExecParentProcess() RecvMsgThread already del ifname:%{public}s.\n", ifname.c_str());
                return DHCP_OPT_SUCCESS;
            }
            if (iterRecvMsgThreadMap->second != nullptr) {
                iterRecvMsgThreadMap->second->join();
                delete iterRecvMsgThreadMap->second;
                iterRecvMsgThreadMap->second = nullptr;
                WIFI_LOGI("ForkExecParentProcess() destroy RecvThread success, ifname:%{public}s.\n", ifname.c_str());
            }
            WIFI_LOGI("ForkExecParentProcess() m_mapDhcpRecvMsgThread erase ifname:%{public}s.\n", ifname.c_str());
            m_mapDhcpRecvMsgThread.erase(iterRecvMsgThreadMap);
        }
    }

    return DHCP_OPT_SUCCESS;
}

pid_t DhcpClientServiceImpl::GetDhcpClientProPid(const std::string& ifname)
{
    if (ifname.empty()) {
        WIFI_LOGE("GetDhcpClientProPid() error, ifname is empty!\n");
        return 0;
    }

    auto iter = m_mapDhcpInfo.find(ifname);
    if (iter == m_mapDhcpInfo.end()) {
        WIFI_LOGI("GetDhcpClientProPid() m_mapDhcpInfo no find ifname:%{public}s.\n", ifname.c_str());
        return 0;
    }

    std::string pidFile = DHCP_WORK_DIR + ifname + DHCP_CLIENT_PID_FILETYPE;
    pid_t newPid = DhcpFunc::GetPID(pidFile);
    if ((newPid > 0) && (newPid != (iter->second).clientProPid)) {
        WIFI_LOGI("GetDhcpClientProPid() GetPID %{public}s new pid:%{public}d, old pid:%{public}d, need update.\n",
            pidFile.c_str(), newPid, (iter->second).clientProPid);
        m_mapDhcpInfo[ifname].clientProPid = newPid;
    }

    WIFI_LOGI("GetDhcpClientProPid() m_mapDhcpInfo find ifname:%{public}s, pid:%{public}d.\n",
        ifname.c_str(), m_mapDhcpInfo[ifname].clientProPid);
    return m_mapDhcpInfo[ifname].clientProPid;
}

int DhcpClientServiceImpl::StartDhcpClient(const std::string &ifname, bool bIpv6)
{
    if (ifname.empty()) {
        WIFI_LOGE("DhcpClientServiceImpl::StartDhcpClient() error, ifname is empty!\n");
        return DHCP_OPT_FAILED;
    }

    WIFI_LOGI("enter StartDhcpClient()...ifname:%{public}s, bIpv6:%{public}d.\n", ifname.c_str(), bIpv6);

    /* check config */
    /* check dhcp client service running status */
    int nStatus = GetDhcpStatus(ifname);
    if (nStatus == 1) {
        WIFI_LOGI("StartDhcpClient() running status:%{public}d, service already started, ifname:%{public}s.\n",
            nStatus, ifname.c_str());
        /* reload config */
        return DHCP_OPT_SUCCESS;
    }

    /* start dhcp client service */
    pid_t pid;
    if ((pid = vfork()) < 0) {
        WIFI_LOGE("StartDhcpClient() vfork() failed, pid:%{public}d.\n", pid);
        return DHCP_OPT_FAILED;
    }
    if (pid == 0) {
        /* Child process */
        ForkExecChildProcess(ifname, bIpv6, true);
    } else {
        /* Parent process */
        WIFI_LOGI("StartDhcpClient() vfork %{public}d success, parent:%{public}d, begin waitpid...\n", pid, getpid());
        pid_t pidRet = waitpid(pid, nullptr, 0);
        if (pidRet == pid) {
            WIFI_LOGI("StartDhcpClient() waitpid child:%{public}d success.\n", pid);
        } else {
            WIFI_LOGE("StartDhcpClient() waitpid child:%{public}d failed, pidRet:%{public}d!\n", pid, pidRet);
        }

        return ForkExecParentProcess(ifname, bIpv6, true, pid);
    }

    return DHCP_OPT_SUCCESS;
}

int DhcpClientServiceImpl::StopDhcpClient(const std::string &ifname, bool bIpv6)
{
    if (ifname.empty()) {
        WIFI_LOGE("DhcpClientServiceImpl::StopDhcpClient() error, ifname is empty!\n");
        return DHCP_OPT_FAILED;
    }

    WIFI_LOGI("enter StopDhcpClient()...ifname:%{public}s, bIpv6:%{public}d.\n", ifname.c_str(), bIpv6);

    /* check dhcp client service running status */
    bool bExecParentProcess = true;
    int nStatus = GetDhcpStatus(ifname);
    if (nStatus == 0) {
        WIFI_LOGI("StopDhcpClient() status:%{public}d, service already stopped, ifname:%{public}s.\n",
            nStatus, ifname.c_str());
        return DHCP_OPT_SUCCESS;
    } else if (nStatus == -1) {
        WIFI_LOGI("StopDhcpClient() status:%{public}d, service not start or started, not need ExecParentProcess, "
                  "ifname:%{public}s.\n", nStatus, ifname.c_str());
        bExecParentProcess = false;
    }

    /* stop dhcp client service */
    pid_t pid;
    if ((pid = vfork()) < 0) {
        WIFI_LOGE("StopDhcpClient() vfork() failed, pid:%{public}d.\n", pid);
        return DHCP_OPT_FAILED;
    }
    if (pid == 0) {
        /* Child process */
        ForkExecChildProcess(ifname, bIpv6);
        return DHCP_OPT_SUCCESS;
    } else {
        /* Parent process */
        WIFI_LOGI("StopDhcpClient() vfork %{public}d success, parent:%{public}d, begin waitpid...\n", pid, getpid());
        pid_t pidRet = waitpid(pid, nullptr, 0);
        if (pidRet == pid) {
            WIFI_LOGI("StopDhcpClient() waitpid child:%{public}d success.\n", pid);
        } else {
            WIFI_LOGE("StopDhcpClient() waitpid child:%{public}d failed, pidRet:%{public}d!\n", pid, pidRet);
        }

        return bExecParentProcess ? ForkExecParentProcess(ifname, bIpv6) : DHCP_OPT_SUCCESS;
    }
}

int DhcpClientServiceImpl::GetDhcpStatus(const std::string &ifname)
{
    if (ifname.empty()) {
        WIFI_LOGE("DhcpClientServiceImpl::GetDhcpStatus() error, ifname is empty!\n");
        return -1;
    }

    auto iter = m_mapDhcpInfo.find(ifname);
    if (iter == m_mapDhcpInfo.end()) {
        WIFI_LOGI("DhcpClientServiceImpl::GetDhcpStatus() m_mapDhcpInfo no find ifname:%{public}s.\n", ifname.c_str());
        return -1;
    }

    WIFI_LOGI("GetDhcpStatus() m_mapDhcpInfo find ifname:%{public}s, clientRunStatus:%{public}d.\n",
        ifname.c_str(),
        (iter->second).clientRunStatus);
    return (iter->second).clientRunStatus;
}

int DhcpClientServiceImpl::GetDhcpResult(const std::string &ifname, IDhcpResultNotify *pResultNotify, int timeouts)
{
    if (ifname.empty()) {
        WIFI_LOGE("DhcpClientServiceImpl::GetDhcpResult() error, ifname is empty!\n");
        return DHCP_OPT_FAILED;
    }

    if (pResultNotify == nullptr) {
        WIFI_LOGE("GetDhcpResult() ifname:%{public}s error, pResultNotify is nullptr!\n", ifname.c_str());
        return DHCP_OPT_FAILED;
    }

    DhcpResultReq *pResultReq = new DhcpResultReq;
    pResultReq->timeouts = timeouts;
    pResultReq->getTimestamp = (uint32_t)time(NULL);
    pResultReq->pResultNotify = pResultNotify;

    std::unique_lock<std::mutex> lock(mResultNotifyMutex);
    auto iter = m_mapDhcpResultNotify.find(ifname);
    if (iter != m_mapDhcpResultNotify.end()) {
        iter->second.push_back(pResultReq);
    } else {
        std::list<DhcpResultReq *> listDhcpResultReq;
        listDhcpResultReq.push_back(pResultReq);
        m_mapDhcpResultNotify.emplace(std::make_pair(ifname, listDhcpResultReq));
    }

    WIFI_LOGI("GetDhcpResult() ifname:%{public}s,timeouts:%{public}d, result push_back!\n", ifname.c_str(), timeouts);

    return DHCP_OPT_SUCCESS;
}

int DhcpClientServiceImpl::GetDhcpInfo(const std::string &ifname, DhcpServiceInfo &dhcp)
{
    if (ifname.empty()) {
        WIFI_LOGE("DhcpClientServiceImpl::GetDhcpInfo() error, ifname is empty!\n");
        return DHCP_OPT_FAILED;
    }

    auto iter = m_mapDhcpInfo.find(ifname);
    if (iter != m_mapDhcpInfo.end()) {
        dhcp = iter->second;
    } else {
        WIFI_LOGE("GetDhcpInfo() failed, m_mapDhcpInfo no find ifname:%{public}s.\n", ifname.c_str());
    }

    return DHCP_OPT_SUCCESS;
}

int DhcpClientServiceImpl::RenewDhcpClient(const std::string &ifname)
{
    WIFI_LOGI("enter DhcpClientServiceImpl::RenewDhcpClient()...ifname:%{public}s.\n", ifname.c_str());
    int nStatus = GetDhcpStatus(ifname);
    if (nStatus != 1) {
        WIFI_LOGW("RenewDhcpClient() dhcp client service not started, now start ifname:%{public}s.\n", ifname.c_str());

        /* Start dhcp client service */
        return StartDhcpClient(ifname, m_mapDhcpInfo[ifname].enableIPv6);
    }

    /* Send dhcp renew packet : kill -USR2 <pid> */
    pid_t pid = GetDhcpClientProPid(ifname);
    if (pid <= 0) {
        WIFI_LOGW("RenewDhcpClient() dhcp client process pid:%{public}d error, ifname:%{public}s!\n",
            pid, ifname.c_str());
        return DHCP_OPT_FAILED;
    }

    if (kill(pid, SIGUSR2) == -1) {
        WIFI_LOGE("RenewDhcpClient() kill [%{public}d] failed:%{public}s, ifname:%{public}s!\n",
            pid, strerror(errno), ifname.c_str());
        return DHCP_OPT_FAILED;
    }
    WIFI_LOGI("RenewDhcpClient() kill [%{public}d] success, ifname:%{public}s.\n", pid, ifname.c_str());
    return DHCP_OPT_SUCCESS;
}

int DhcpClientServiceImpl::ReleaseDhcpClient(const std::string &ifname)
{
    WIFI_LOGI("enter DhcpClientServiceImpl::ReleaseDhcpClient()...ifname:%{public}s.\n", ifname.c_str());
    int nStatus = GetDhcpStatus(ifname);
    if (nStatus != 1) {
        WIFI_LOGE("ReleaseDhcpClient() failed, dhcp client service not started, ifname:%{public}s!\n", ifname.c_str());
        return DHCP_OPT_FAILED;
    }

    /* Send dhcp release packet : kill -USR1 <pid> */
    pid_t pid = GetDhcpClientProPid(ifname);
    if (pid <= 0) {
        WIFI_LOGW("ReleaseDhcpClient() dhcp client process pid:%{public}d error, ifname:%{public}s!\n",
            pid, ifname.c_str());
        return DHCP_OPT_FAILED;
    }

    if (kill(pid, SIGUSR1) == -1) {
        WIFI_LOGE("ReleaseDhcpClient() kill [%{public}d] failed:%{public}s, ifname:%{public}s!\n",
            pid, strerror(errno), ifname.c_str());
        return DHCP_OPT_FAILED;
    }
    WIFI_LOGI("ReleaseDhcpClient() kill [%{public}d] success, ifname:%{public}s.\n", pid, ifname.c_str());
    return DHCP_OPT_SUCCESS;
}
}  // namespace Wifi
}  // namespace OHOS
