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

#include "dhcp_server_service_impl.h"

#include <unistd.h>

#include "dhcp_func.h"
#include "wifi_logger.h"

DEFINE_WIFILOG_DHCP_LABEL("DhcpServerServiceImpl");

namespace OHOS {
namespace Wifi {
bool DhcpServerServiceImpl::mProExitSig = false;
bool DhcpServerServiceImpl::mStopServer = false;
pid_t DhcpServerServiceImpl::mPidDhcpServer = 0;

DhcpServerServiceImpl::DhcpServerServiceImpl()
{
    WIFI_LOGI("DhcpServerServiceImpl::DhcpServerServiceImpl()...\n");
    m_setInterfaces.clear();
    m_mapTagDhcpRange.clear();
    m_mapInfDhcpRange.clear();
    m_mapDhcpSerExitNotify.clear();
    bDhcpSerProExitThread = false;
    pDhcpSerProExitThread = nullptr;
}

DhcpServerServiceImpl::~DhcpServerServiceImpl()
{
    WIFI_LOGI("DhcpServerServiceImpl::~DhcpServerServiceImpl()...\n");
    auto iterInterfaces = m_setInterfaces.begin();
    while (iterInterfaces != m_setInterfaces.end()) {
        if (StopDhcpServer(*iterInterfaces) != DHCP_OPT_SUCCESS) {
            WIFI_LOGE("~StartDhcpServer() StopDhcpServer ifname:%{public}s failed!\n", (*iterInterfaces).c_str());
        } else {
            WIFI_LOGW("~StartDhcpServer() StopDhcpServer ifname:%{public}s success.\n", (*iterInterfaces).c_str());
        }
        m_setInterfaces.erase(iterInterfaces++);
    }

    ExitDhcpMgrThreadFunc();
}

int DhcpServerServiceImpl::StartDhcpServer(const std::string &ifname)
{
    if (ifname.empty()) {
        WIFI_LOGE("DhcpServerServiceImpl::StartDhcpServer() error, ifname is empty!\n");
        return DHCP_OPT_FAILED;
    }

    WIFI_LOGI("enter DhcpServerServiceImpl::StartDhcpServer()...ifname:%{public}s.\n", ifname.c_str());

    /* check and update interface config file */
    if (CheckAndUpdateConf(ifname) != DHCP_OPT_SUCCESS) {
        WIFI_LOGE("StartDhcpServer() CheckAndUpdateConf failed, ifname:%{public}s.\n", ifname.c_str());
        return DHCP_OPT_FAILED;
    }

    /* Add the specified interface. */
    if (AddSpecifiedInterface(ifname) != DHCP_OPT_SUCCESS) {
        WIFI_LOGE("StartDhcpServer() AddSpecifiedInterface failed, ifname:%{public}s.\n", ifname.c_str());
        return DHCP_OPT_FAILED;
    }

    if (mPidDhcpServer != 0) {
        WIFI_LOGI("StartDhcpServer() ifname:%{public}s, pro:%{public}s already started, pid:%{public}d, reload config.",
            ifname.c_str(),
            DHCP_SERVER_FILE.c_str(),
            mPidDhcpServer);

        /* reload dhcp server config */
        return ReConf();
    }

    /* start dhcp server process */
    pid_t pid_server;
    if ((pid_server = vfork()) < 0) {
        WIFI_LOGE("StartDhcpServer() vfork() failed, pid_server:%{public}d!\n", pid_server);
        return DHCP_OPT_FAILED;
    }
    if (pid_server == 0) {
        /* Child process */
        ForkExecProcess(ifname);
    } else {
        /* Parent process */
        mProExitSig = false;
        mStopServer = false;
        mPidDhcpServer = pid_server;
        ForkParentProcess();
    }

    return DHCP_OPT_SUCCESS;
}

int DhcpServerServiceImpl::StopDhcpServer(const std::string &ifname)
{
    if (ifname.empty()) {
        WIFI_LOGE("StopDhcpServer() error, ifname is empty!\n");
        return DHCP_OPT_FAILED;
    }
    if (mPidDhcpServer == 0) {
        WIFI_LOGI("StopDhcpServer() %{public}s, %{public}s already stop.\n", ifname.c_str(), DHCP_SERVER_FILE.c_str());
        return DHCP_OPT_SUCCESS;
    }
    bool bStopDhcpServer = false;
    bool bReloadServerCfg = false;
    if (m_mapInfDhcpRange.empty()) {
        bStopDhcpServer = true;
    } else {
        auto iterRangeMap = m_mapInfDhcpRange.find(ifname);
        if (iterRangeMap != m_mapInfDhcpRange.end()) {
            std::string strInfFile = DHCP_SERVER_CONFIG_DIR + ifname + ".conf";
            if (DeleteInfConf(strInfFile) != DHCP_OPT_SUCCESS) {
                WIFI_LOGE("StopDhcpServer() DeleteInfConf failed, ifname:%{public}s.\n", ifname.c_str());
                return DHCP_OPT_FAILED;
            }

            if (m_mapInfDhcpRange.size() == 1) {
                WIFI_LOGI("StopDhcpServer() ifname:%{public}s, only the if service, now StopServer.\n", ifname.c_str());
                bStopDhcpServer = true;
            } else {
                bReloadServerCfg = true;
            }
            m_mapInfDhcpRange.erase(iterRangeMap);
        }
    }
    if (RemoveAllDhcpRange(ifname) != DHCP_OPT_SUCCESS) {
        return DHCP_OPT_FAILED;
    }
    if (bStopDhcpServer) {
        if (StopServer(mPidDhcpServer) != DHCP_OPT_SUCCESS) {
            return DHCP_OPT_FAILED;
        }
        mPidDhcpServer = 0;
    } else {
        /* reload dhcp server config */
        if (bReloadServerCfg && (ReConf() != DHCP_OPT_SUCCESS)) {
            WIFI_LOGE("StopDhcpServer() ReConf failed, ifname:%{public}s.\n", ifname.c_str());
            return DHCP_OPT_FAILED;
        }
    }

    /* Del the specified interface. */
    if (DelSpecifiedInterface(ifname) != DHCP_OPT_SUCCESS) {
        return DHCP_OPT_FAILED;
    }
    return DHCP_OPT_SUCCESS;
}

int DhcpServerServiceImpl::GetServerStatus()
{
    if (mPidDhcpServer == 0) {
        WIFI_LOGI("GetServerStatus() pro:%{public}s not start.\n", DHCP_SERVER_FILE.c_str());
        return 0;
    }
    WIFI_LOGI("GetServerStatus() pro:%{public}s normal started.\n", DHCP_SERVER_FILE.c_str());
    return 1;
}

int DhcpServerServiceImpl::PutDhcpRange(const std::string &tagName, const DhcpRange &range)
{
    if (tagName.empty()) {
        WIFI_LOGE("DhcpServerServiceImpl::PutDhcpRange() error, tagName is empty!\n");
        return DHCP_OPT_FAILED;
    }
    if ((range.iptype == -1) || range.strStartip.empty() || range.strEndip.empty()) {
        WIFI_LOGE("PutDhcpRange() tagName:%{public}s failed, range.iptype:%{public}d or strStartip:%{public}s or "
                  "strEndip:%{public}s error!\n",
            tagName.c_str(),
            range.iptype,
            range.strStartip.c_str(),
            range.strEndip.c_str());
        return DHCP_OPT_FAILED;
    }

    WIFI_LOGI("enter PutDhcpRange() tagName:%{public}s.\n", tagName.c_str());

    /* check invalid and already exist in dhcp range */
    if (!CheckIpAddrRange(range)) {
        WIFI_LOGE("PutDhcpRange() CheckIpAddrRange failed, tagName:%{public}s!\n", tagName.c_str());
        return DHCP_OPT_FAILED;
    }

    /* add dhcp range */
    auto iterRangeMap = m_mapTagDhcpRange.find(tagName);
    if (iterRangeMap != m_mapTagDhcpRange.end()) {
        for (auto iterRange : iterRangeMap->second) {
            if ((iterRange.iptype == range.iptype) && (iterRange.strStartip == range.strStartip) &&
                (iterRange.strEndip == range.strEndip)) {
                WIFI_LOGE("PutDhcpRange() tagName:%{public}s failed, "
                          "range.iptype:%{public}d,strStartip:%{public}s,strEndip:%{public}s already exist!\n",
                    tagName.c_str(),
                    range.iptype,
                    range.strStartip.c_str(),
                    range.strEndip.c_str());
                return DHCP_OPT_FAILED;
            }
        }
        iterRangeMap->second.push_back(range);
        WIFI_LOGI("PutDhcpRange() m_mapTagDhcpRange find tagName:%{public}s, need push_back.\n", tagName.c_str());
    } else {
        std::list<DhcpRange> listDhcpRange;
        listDhcpRange.push_back(range);
        m_mapTagDhcpRange.emplace(std::make_pair(tagName, listDhcpRange));
        WIFI_LOGI("PutDhcpRange() m_mapTagDhcpRange no find tagName:%{public}s, need emplace.\n", tagName.c_str());
    }

    return DHCP_OPT_SUCCESS;
}

int DhcpServerServiceImpl::RemoveDhcpRange(const std::string &tagName, const DhcpRange &range)
{
    if (tagName.empty()) {
        WIFI_LOGE("DhcpServerServiceImpl::RemoveDhcpRange() error, tagName is empty!\n");
        return DHCP_OPT_FAILED;
    }
    if ((range.iptype == -1) || range.strStartip.empty() || range.strEndip.empty()) {
        WIFI_LOGE("RemoveDhcpRange() tagName:%{public}s failed, range.iptype:%{public}d or strStartip:%{public}s or "
                  "strEndip:%{public}s error!\n",
            tagName.c_str(),
            range.iptype,
            range.strStartip.c_str(),
            range.strEndip.c_str());
        return DHCP_OPT_FAILED;
    }

    /* remove dhcp range */
    auto iterRangeMap = m_mapTagDhcpRange.find(tagName);
    if (iterRangeMap != m_mapTagDhcpRange.end()) {
        auto iterRange = m_mapTagDhcpRange[tagName].begin();
        while (iterRange != m_mapTagDhcpRange[tagName].end()) {
            if ((iterRange->iptype == range.iptype) && (iterRange->strStartip == range.strStartip) &&
                (iterRange->strEndip == range.strEndip)) {
                m_mapTagDhcpRange[tagName].erase(iterRange++);
                WIFI_LOGI("RemoveDhcpRange() find tagName:%{public}s, "
                          "range.iptype:%{public}d,strStartip:%{public}s,strEndip:%{public}s, erase.\n",
                    tagName.c_str(),
                    range.iptype,
                    range.strStartip.c_str(),
                    range.strEndip.c_str());
                return DHCP_OPT_SUCCESS;
            }
            iterRange++;
        }
        WIFI_LOGE("RemoveDhcpRange() find tagName:%{public}s, second no find range, erase failed!\n", tagName.c_str());
    } else {
        WIFI_LOGE("RemoveDhcpRange no find tagName:%{public}s, erase failed!\n", tagName.c_str());
    }

    return DHCP_OPT_FAILED;
}

int DhcpServerServiceImpl::RemoveAllDhcpRange(const std::string &tagName)
{
    if (tagName.empty()) {
        WIFI_LOGE("DhcpServerServiceImpl::RemoveAllDhcpRange() error, tagName is empty!\n");
        return DHCP_OPT_FAILED;
    }

    /* remove all dhcp range */
    auto iterRangeMap = m_mapTagDhcpRange.find(tagName);
    if (iterRangeMap != m_mapTagDhcpRange.end()) {
        m_mapTagDhcpRange.erase(iterRangeMap);
        WIFI_LOGI("RemoveAllDhcpRange() find tagName:%{public}s, erase success.\n", tagName.c_str());
    } else {
        WIFI_LOGI("RemoveAllDhcpRange() no find tagName:%{public}s, not need erase!\n", tagName.c_str());
    }

    return DHCP_OPT_SUCCESS;
}

int DhcpServerServiceImpl::SetDhcpRange(const std::string &ifname, const DhcpRange &range)
{
    if (ifname.empty()) {
        WIFI_LOGE("DhcpServerServiceImpl::SetDhcpRange() error, ifname is empty!\n");
        return DHCP_OPT_FAILED;
    }
    if ((range.iptype == -1) || range.strStartip.empty() || range.strEndip.empty()) {
        WIFI_LOGE("SetDhcpRange() ifname:%{public}s failed, range.iptype:%{public}d or strStartip:%{public}s or "
                  "strEndip:%{public}s error!\n",
            ifname.c_str(), range.iptype, range.strStartip.c_str(), range.strEndip.c_str());
        return DHCP_OPT_FAILED;
    }

    /* check dhcp server service status */
    int nStatus = GetServerStatus();
    if (nStatus != 1) {
        WIFI_LOGE("SetDhcpRange() ifname:%{public}s failed, dhcp status:%{public}d error!\n", ifname.c_str(), nStatus);
        return DHCP_OPT_FAILED;
    }

    /* put dhcp range */
    if (PutDhcpRange(ifname, range) != DHCP_OPT_SUCCESS) {
        WIFI_LOGE("SetDhcpRange() PutDhcpRange failed, ifname:%{public}s.\n", ifname.c_str());
        return DHCP_OPT_FAILED;
    }

    /* check and add dhcp range */
    auto iterRangeMap = m_mapInfDhcpRange.find(ifname);
    if (iterRangeMap != m_mapInfDhcpRange.end()) {
        for (auto iterRange : iterRangeMap->second) {
            if ((iterRange.iptype == range.iptype) && (iterRange.strStartip == range.strStartip) &&
                (iterRange.strEndip == range.strEndip)) {
                WIFI_LOGE("SetDhcpRange() ifname:%{public}s failed, "
                          "range.iptype:%{public}d,strStartip:%{public}s,strEndip:%{public}s already exist!\n",
                    ifname.c_str(), range.iptype, range.strStartip.c_str(), range.strEndip.c_str());
                return DHCP_OPT_FAILED;
            }
        }
        iterRangeMap->second.push_back(range);
        WIFI_LOGI("SetDhcpRange() m_mapInfDhcpRange find ifname:%{public}s, second need push_back.\n", ifname.c_str());
    } else {
        std::list<DhcpRange> listDhcpRange;
        listDhcpRange.push_back(range);
        m_mapInfDhcpRange.emplace(std::make_pair(ifname, listDhcpRange));
        WIFI_LOGI("SetDhcpRange() m_mapInfDhcpRange no find ifname:%{public}s, need emplace.\n", ifname.c_str());
    }

    /* update or reload interface config file */
    if (CheckAndUpdateConf(ifname) != DHCP_OPT_SUCCESS) {
        WIFI_LOGE("SetDhcpRange() CheckAndUpdateConf failed, ifname:%{public}s.\n", ifname.c_str());
        return DHCP_OPT_FAILED;
    }

    /* reload dhcp server config */
    return ReConf();
}

int DhcpServerServiceImpl::SetDhcpRange(const std::string &ifname, const std::string &tagName)
{
    if (ifname.empty() || tagName.empty()) {
        WIFI_LOGE("SetDhcpRange() failed, ifname or tagName is empty!\n");
        return DHCP_OPT_FAILED;
    }
    auto iterTag = m_mapTagDhcpRange.find(tagName);
    if (iterTag == m_mapTagDhcpRange.end()) {
        WIFI_LOGE("SetDhcpRange() failed, m_mapTagDhcpRange no find tagName:%{public}s.\n", tagName.c_str());
        return DHCP_OPT_FAILED;
    }
    if ((iterTag->second).empty()) {
        WIFI_LOGE("SetDhcpRange() failed, m_mapTagDhcpRange second is empty, tagName:%{public}s.\n", tagName.c_str());
        return DHCP_OPT_FAILED;
    }

    /* check dhcp server service status */
    int nStatus = GetServerStatus();
    if (nStatus != 1) {
        WIFI_LOGE("SetDhcpRange() ifname:%{public}s,tagName:%{public}s failed,dhcp status:%{public}d!\n",
            ifname.c_str(), tagName.c_str(), nStatus);
        return DHCP_OPT_FAILED;
    }

    /* check and add dhcp range */
    auto iterRangeMap = m_mapInfDhcpRange.find(ifname);
    if (iterRangeMap != m_mapInfDhcpRange.end()) {
        /* check dhcp range is already exist */
        if (CheckTagDhcpRange(iterTag->second, iterRangeMap->second)) {
            WIFI_LOGE("SetDhcpRange() ifname:%{public}s,tagName:%{public}s failed, dhcp range is same!\n",
                ifname.c_str(), tagName.c_str());
            return DHCP_OPT_FAILED;
        }

        for (auto iterTagValue : iterTag->second) {
            iterRangeMap->second.push_back(iterTagValue);
            WIFI_LOGI("SetDhcpRange() find ifname:%{public}s, second need push tagName:%{public}s.\n",
                ifname.c_str(), tagName.c_str());
        }
    } else {
        m_mapInfDhcpRange.emplace(std::make_pair(ifname, iterTag->second));
        WIFI_LOGI("SetDhcpRange() no find ifname:%{public}s,tagName:%{public}s, need emplace.\n",
            ifname.c_str(), tagName.c_str());
    }

    /* update or reload interface config file */
    if (CheckAndUpdateConf(ifname) != DHCP_OPT_SUCCESS) {
        WIFI_LOGE("SetDhcpRange() CheckAndUpdateConf failed, ifname:%{public}s,tagName:%{public}s!\n",
            ifname.c_str(), tagName.c_str());
        return DHCP_OPT_FAILED;
    }

    /* reload dhcp server config */
    return ReConf();
}

int DhcpServerServiceImpl::GetLeases(std::vector<std::string> &leases)
{
    if (!DhcpFunc::IsExistFile(DHCP_SERVER_LEASES_FILE)) {
        WIFI_LOGE("GetLeases() failed, dhcp leasefile:%{public}s no exist!\n", DHCP_SERVER_LEASES_FILE.c_str());
        return DHCP_OPT_FAILED;
    }

    leases.clear();

    std::ifstream inFile;
    inFile.open(DHCP_SERVER_LEASES_FILE);
    std::string strTemp = "";
    char tmpLineData[FILE_LINE_MAX_SIZE] = {0};
    while (inFile.getline(tmpLineData, sizeof(tmpLineData))) {
        strTemp = tmpLineData;
        leases.push_back(strTemp);
    }
    inFile.close();

    WIFI_LOGI("GetLeases() leases.size:%{public}d.\n", (int)leases.size());
    return DHCP_OPT_SUCCESS;
}

int DhcpServerServiceImpl::GetDhcpSerProExit(const std::string &ifname, IDhcpResultNotify *pResultNotify)
{
    if (ifname.empty()) {
        WIFI_LOGE("DhcpServerServiceImpl::GetDhcpSerProExit() error, ifname is empty!\n");
        return DHCP_OPT_FAILED;
    }

    if (pResultNotify == nullptr) {
        WIFI_LOGE("DhcpServerServiceImpl::GetDhcpSerProExit() error, pResultNotify = nullptr!\n");
        return DHCP_OPT_FAILED;
    }

    auto iterExitNotify = m_mapDhcpSerExitNotify.find(ifname);
    if (iterExitNotify == m_mapDhcpSerExitNotify.end()) {
        WIFI_LOGI("GetDhcpSerProExit() SerExitNotify no find ifname:%{public}s, need emplace.\n", ifname.c_str());
        m_mapDhcpSerExitNotify.emplace(std::make_pair(ifname, pResultNotify));
    } else {
        WIFI_LOGW("GetDhcpSerProExit() SerExitNotify find ifname:%{public}s, not need emplace!\n", ifname.c_str());
    }

    if (pDhcpSerProExitThread == nullptr) {
        pDhcpSerProExitThread = new std::thread(&DhcpServerServiceImpl::RunDhcpSerProExitThreadFunc, this);
        if (pDhcpSerProExitThread == nullptr) {
            WIFI_LOGE("DhcpServerServiceImpl::GetDhcpSerProExit() init pDhcpSerProExitThread failed!\n");
            return DHCP_OPT_FAILED;
        }
        WIFI_LOGI("DhcpServerServiceImpl::GetDhcpSerProExit() init pDhcpSerProExitThread success.\n");
    }

    return DHCP_OPT_SUCCESS;
}

int DhcpServerServiceImpl::ReConf()
{
    if (mPidDhcpServer == 0) {
        WIFI_LOGE("ReConf() failed, %{public}s not start, config can not reload!\n", DHCP_SERVER_FILE.c_str());
        return DHCP_OPT_FAILED;
    }

    WIFI_LOGI("enter ReConf(), now restart server:[ %{public}s ], mPidDhcpServer:%{public}d.\n",
        DHCP_SERVER_FILE.c_str(), mPidDhcpServer);

    /* stop dhcp server process */
    if (StopServer(mPidDhcpServer) != DHCP_OPT_SUCCESS) {
        WIFI_LOGE("ReConf() failed, StopServer mPidDhcpServer:%{public}d error!\n", mPidDhcpServer);
        return DHCP_OPT_FAILED;
    }
    mPidDhcpServer = 0;

    sleep(DHCP_NUMBER_ONE);

    /* restart dhcp server process for load config */
    pid_t pid_server;
    if ((pid_server = vfork()) < 0) {
        WIFI_LOGE("ReConf() failed, vfork() pid_server:%{public}d error!\n", pid_server);
        return DHCP_OPT_FAILED;
    }
    if (pid_server == 0) {
        /* Child process */
        ForkExecProcess();
    } else {
        /* Parent process */
        mProExitSig = false;
        mStopServer = false;
        mPidDhcpServer = pid_server;
        ForkParentProcess();
    }

    return DHCP_OPT_SUCCESS;
}

int DhcpServerServiceImpl::ForkParentProcess()
{
    WIFI_LOGI("enter ForkParentProcess() server:[ %{public}s ], mPidDhcpServer:%{public}d.\n",
        DHCP_SERVER_FILE.c_str(), mPidDhcpServer);
    RegisterSignal();
    return DHCP_OPT_SUCCESS;
}

int DhcpServerServiceImpl::ForkExecProcess(const std::string &ifname)
{
    WIFI_LOGI("enter ForkExecProcess() server:[ %{public}s ], ifname:%{public}s.\n",
        DHCP_SERVER_FILE.c_str(), ifname.c_str());
    const char *args[DHCP_SER_ARGSNUM] = {
        DHCP_SERVER_FILE.c_str(),
        "--keep-in-foreground",
        "--bind-interfaces",
        "-C",
        DHCP_SERVER_CONFIG_FILE.c_str(),
        nullptr
    };
    if (execv(args[0], const_cast<char *const *>(args)) == -1) {
        WIFI_LOGE("execv start failed,errno:%{public}d,strerror(errno):%{public}s,ifname:%{public}s!\n",
            errno, strerror(errno), ifname.c_str());
    } else {
        WIFI_LOGI("execv start success, ifname:%{public}s!\n", ifname.c_str());
    }
    _exit(-1);

    return DHCP_OPT_SUCCESS;
}

int DhcpServerServiceImpl::StopServer(const pid_t &server_pid)
{
    mStopServer = true;
    UnregisterSignal();
    if (kill(server_pid, SIGTERM) == -1) {
        if (ESRCH == errno) {
            /* Normal. The subprocess is dead. The SIGCHLD signal triggers the stop hotspot. */
            WIFI_LOGI("StopServer() kill [%{public}d] success, pro pid no exist, pro:%{public}s.\n",
                server_pid, DHCP_SERVER_FILE.c_str());
            return DHCP_OPT_SUCCESS;
        }
        WIFI_LOGE("StopServer() kill [%{public}d] failed, strerror(errno):%{public}s!\n", server_pid, strerror(errno));
        return DHCP_OPT_FAILED;
    }
    if (waitpid(server_pid, nullptr, 0) == -1) {
        WIFI_LOGE("StopServer() waitpid [%{public}d] failed, strerror(errno):%{public}s!\n",
            server_pid, strerror(errno));
        return DHCP_OPT_FAILED;
    }
    WIFI_LOGI("StopServer() waitpid [%{public}d] success, pro:%{public}s!\n", server_pid, DHCP_SERVER_FILE.c_str());
    return DHCP_OPT_SUCCESS;
}

int DhcpServerServiceImpl::CheckAndUpdateConf(const std::string &ifname)
{
    if (ifname.empty()) {
        WIFI_LOGE("DhcpServerServiceImpl::CheckAndUpdateConf() error, ifname is empty!\n");
        return DHCP_OPT_FAILED;
    }

    /* delete temp interface config */
    std::string strInfFile = DHCP_SERVER_CONFIG_DIR + ifname + ".conf";
    if (DeleteInfConf(strInfFile) != DHCP_OPT_SUCCESS) {
        WIFI_LOGE("CheckAndUpdateConf() DeleteInfConf failed, ifname:%{public}s!\n", ifname.c_str());
        return DHCP_OPT_FAILED;
    }

    auto iterRangeMap = m_mapInfDhcpRange.find(ifname);
    if ((iterRangeMap == m_mapInfDhcpRange.end()) || (iterRangeMap->second).empty()) {
        return DHCP_OPT_SUCCESS;
    }

    std::string strMac = "";
    if (DhcpFunc::GetLocalMac(ifname.c_str(), strMac) != 0) {
        WIFI_LOGE("CheckAndUpdateConf() ifname:%{public}s failed, GetLocalMac error!\n", ifname.c_str());
        return DHCP_OPT_FAILED;
    }

    std::string strIpv4 = "";
    std::string strIpv6 = "";
    bool bValidRange = false;
    for (auto iterRange : iterRangeMap->second) {
        if (((iterRange.iptype != 0) && (iterRange.iptype != 1)) || (iterRange.leaseHours <= 0) ||
            (iterRange.strStartip.length() <= 0) || (iterRange.strEndip.length() <= 0)) {
            WIFI_LOGE("CheckAndUpdateConf() failed, "
                      "iptype:%{public}d,leaseHours:%{public}d,strStartip:%{public}s,strEndip:%{public}s error!\n",
                iterRange.iptype, iterRange.leaseHours, iterRange.strStartip.c_str(), iterRange.strEndip.c_str());
            continue;
        }

        std::string strTag = "";
        if (iterRange.strTagName.length() > 0) {
            strTag = "set:" + iterRange.strTagName + ",";
        }
        if (iterRange.iptype == 0) {
            strIpv4 += "dhcp-range=" + strTag + iterRange.strStartip + "," + iterRange.strEndip + ",";
            strIpv4 += std::to_string(iterRange.leaseHours) + "h" + "\n";
        } else {
            strIpv6 += "dhcp-range=" + strTag + iterRange.strStartip + "," + iterRange.strEndip + ",";
            strIpv6 += std::to_string(iterRange.leaseHours) + "h" + "\n";
        }
        bValidRange = true;
    }

    if (bValidRange) {
        /* interface data */
        std::string strInf = "interface=" + ifname + "\n" + "dhcp-host=" + strMac + "," + ifname + "\n\n";
        strInf += DHCP_SERVER_CFG_IPV4 + "\n" + strIpv4 + "\n" + DHCP_SERVER_CFG_IPV6 + "\n" + strIpv6 + "\n";
        DhcpFunc::CreateFile(strInfFile, strInf);
    }

    return DHCP_OPT_SUCCESS;
}

int DhcpServerServiceImpl::DeleteInfConf(const std::string &if_filename)
{
    if (if_filename.empty()) {
        WIFI_LOGE("DhcpServerServiceImpl::DeleteInfConf() error, if_filename is empty!\n");
        return DHCP_OPT_FAILED;
    }
    if (DhcpFunc::IsExistFile(if_filename)) {
        return DhcpFunc::RemoveFile(if_filename) ? DHCP_OPT_SUCCESS : DHCP_OPT_FAILED;
    }
    WIFI_LOGI("DeleteInfConf() if_filename:%{public}s no exist, not need delete.\n", if_filename.c_str());
    return DHCP_OPT_SUCCESS;
}

bool DhcpServerServiceImpl::CheckIpAddrRange(const DhcpRange &range)
{
    if (((range.iptype != 0) && (range.iptype != 1)) || range.strStartip.empty() || range.strEndip.empty()) {
        WIFI_LOGE("CheckIpAddrRange() range.iptype:%{public}d,strStartip:%{public}s,strEndip:%{public}s error!\n",
            range.iptype, range.strStartip.c_str(), range.strEndip.c_str());
        return false;
    }

    if (range.iptype == 0) {
        uint32_t uStartIp = 0;
        if (!DhcpFunc::Ip4StrConToInt(range.strStartip, uStartIp)) {
            WIFI_LOGE("CheckIpAddrRange() Ip4StrConToInt failed, range.iptype:%{public}d,strStartip:%{public}s!\n",
                range.iptype, range.strStartip.c_str());
            return false;
        }
        uint32_t uEndIp = 0;
        if (!DhcpFunc::Ip4StrConToInt(range.strEndip, uEndIp)) {
            WIFI_LOGE("CheckIpAddrRange() Ip4StrConToInt failed, range.iptype:%{public}d,strEndip:%{public}s!\n",
                range.iptype, range.strEndip.c_str());
            return false;
        }
        /* check ip4 start and end ip */
        if (uStartIp >= uEndIp) {
            WIFI_LOGE("CheckIpAddrRange() failed, uStartIp:%{public}u not less uEndIp:%{public}u!\n", uStartIp, uEndIp);
            return false;
        }
    } else {
        uint8_t uStartIp6[sizeof(struct in6_addr)] = {0};
        if (!DhcpFunc::Ip6StrConToChar(range.strStartip, uStartIp6, sizeof(struct in6_addr))) {
            return false;
        }
        uint8_t uEndIp6[sizeof(struct in6_addr)] = {0};
        if (!DhcpFunc::Ip6StrConToChar(range.strEndip, uEndIp6, sizeof(struct in6_addr))) {
            return false;
        }
        /* check ip6 start and end ip */
    }

    /* check range already exist in m_mapTagDhcpRange */
    for (auto tagRange : m_mapTagDhcpRange) {
        for (auto dhcpRange : tagRange.second) {
            if (dhcpRange.iptype != range.iptype) {
                continue;
            }

            if (CheckDhcpRangeConflict(dhcpRange, range)) {
                WIFI_LOGE("CheckIpAddrRange() Conflict yes, type:%{public}d,Start:%{public}s,End:%{public}s error!\n",
                    range.iptype, range.strStartip.c_str(), range.strEndip.c_str());
                return false;
            }
        }
    }

    return true;
}

bool DhcpServerServiceImpl::CheckDhcpRangeConflict(const DhcpRange &srcRange, const DhcpRange &addRange)
{
    if (srcRange.iptype != addRange.iptype) {
        WIFI_LOGI("CheckDhcpRangeConflict() no, src:%{public}d,add:%{public}d.\n", srcRange.iptype, addRange.iptype);
        return false;
    }

    if (addRange.iptype == 0) {
        /* check ip4 */
        uint32_t uSrcStartIp = 0;
        if (!DhcpFunc::Ip4StrConToInt(srcRange.strStartip, uSrcStartIp)) {
            return false;
        }
        uint32_t uSrcEndIp = 0;
        if (!DhcpFunc::Ip4StrConToInt(srcRange.strEndip, uSrcEndIp)) {
            return false;
        }
        if (uSrcStartIp >= uSrcEndIp) {
            WIFI_LOGE("CheckDhcpRangeConflict() Start:%{public}u not less End:%{public}u!\n", uSrcStartIp, uSrcEndIp);
            return false;
        }

        uint32_t uAddStartIp = 0;
        if (!DhcpFunc::Ip4StrConToInt(addRange.strStartip, uAddStartIp)) {
            WIFI_LOGE("CheckDhcpRangeConflict() Ip4StrConToInt failed, iptype:%{public}d,strStartip:%{public}s!\n",
                addRange.iptype, addRange.strStartip.c_str());
            return false;
        }
        uint32_t uAddEndIp = 0;
        if (!DhcpFunc::Ip4StrConToInt(addRange.strEndip, uAddEndIp)) {
            WIFI_LOGE("CheckDhcpRangeConflict() Ip4StrConToInt failed, iptype:%{public}d,strEndip:%{public}s!\n",
                addRange.iptype, addRange.strEndip.c_str());
            return false;
        }
        if (uAddStartIp >= uAddEndIp) {
            WIFI_LOGE("CheckDhcpRangeConflict() Start:%{public}u not less End:%{public}u!\n", uAddStartIp, uAddEndIp);
            return false;
        }

        if (!((uAddStartIp > uSrcEndIp) || (uAddEndIp < uSrcStartIp))) {
            WIFI_LOGI("CheckDhcpRangeConflict yes,srcRange.iptype:%{public}d, "
                "strStartip:%{public}s-uSrcStartIp:%{public}u, strEndip:%{public}s-uSrcEndIp:%{public}u, "
                "addRange.strStartip:%{public}s-uAddStartIp:%{public}u, strEndip:%{public}s-uAddEndIp:%{public}u.\n",
                srcRange.iptype, srcRange.strStartip.c_str(), uSrcStartIp, srcRange.strEndip.c_str(),
                uSrcEndIp, addRange.strStartip.c_str(), uAddStartIp, addRange.strEndip.c_str(), uAddEndIp);
            return true;
        }
        WIFI_LOGI("CheckDhcpRangeConflict() no, srcRange.iptype:%{public}d.\n", srcRange.iptype);
    } else {
        /* check ip6 */
    }

    return false;
}

bool DhcpServerServiceImpl::CheckTagDhcpRange(std::list<DhcpRange> &tagRange, std::list<DhcpRange> &infRange)
{
    for (auto iterTagValue : tagRange) {
        for (auto iterInfValue : infRange) {
            if ((iterInfValue.iptype == iterTagValue.iptype) && (iterInfValue.strStartip == iterTagValue.strStartip) &&
                (iterInfValue.strEndip == iterTagValue.strEndip)) {
                WIFI_LOGE("CheckTagDhcpRange() failed, iterTagValue.iptype:%{public}d, strStartip:%{public}s, "
                          "strEndip:%{public}s already exist!\n",
                    iterTagValue.iptype,
                    iterTagValue.strStartip.c_str(),
                    iterTagValue.strEndip.c_str());
                return true;
            }
        }
    }
    return false;
}

void DhcpServerServiceImpl::RunDhcpSerProExitThreadFunc()
{
    for (;;) {
        if (bDhcpSerProExitThread) {
            WIFI_LOGI("RunDhcpSerProExitThreadFunc() bDhcpSerProExitThread:true, break!\n");
            break;
        }
        if (m_mapDhcpSerExitNotify.empty()) {
            sleep(DHCP_NUMBER_ONE);
            continue;
        }
        if (!mProExitSig || mStopServer) {
            WIFI_LOGI("RunDhcpSerProExitThreadFunc() has notify reqs, but sig:%{public}d, stop:%{public}d.",
                mProExitSig, mStopServer);
            usleep(SLEEP_TIME_500_MS);
            continue;
        }

        /* If the dhcp server process exits abnormally, notify other modules. */
        WIFI_LOGI("RunDhcpSerProExitThreadFunc() other modules have notify reqs, now begin notify...\n");
        auto iterNotify = m_mapDhcpSerExitNotify.begin();
        while (iterNotify != m_mapDhcpSerExitNotify.end()) {
            std::string ifname = iterNotify->first;
            if (iterNotify->second == nullptr) {
                WIFI_LOGE("RunDhcpSerProExitThreadFunc() ifname:%{public}s error, ptr is nullptr!\n", ifname.c_str());
                iterNotify = m_mapDhcpSerExitNotify.erase(iterNotify);
                continue;
            }

            /* notify other modules */
            WIFI_LOGI("RunDhcpSerProExitThreadFunc() notify other modules.\n");
            iterNotify->second->OnSerExitNotify(ifname);
            iterNotify = m_mapDhcpSerExitNotify.erase(iterNotify);
        }

        WIFI_LOGI("RunDhcpSerProExitThreadFunc() dhcp ser pro exit notify finished.\n");
        sleep(DHCP_NUMBER_ONE);
        continue;
    }

    WIFI_LOGI("DhcpServerServiceImpl::RunDhcpSerProExitThreadFunc() end!\n");
}

void DhcpServerServiceImpl::ExitDhcpMgrThreadFunc()
{
    bDhcpSerProExitThread = true;
    if (pDhcpSerProExitThread != nullptr) {
        pDhcpSerProExitThread->join();
        delete pDhcpSerProExitThread;
        pDhcpSerProExitThread = nullptr;
    }

    if (!m_mapDhcpSerExitNotify.empty()) {
        m_mapDhcpSerExitNotify.clear();
    }
}

void DhcpServerServiceImpl::RegisterSignal() const
{
    struct sigaction newAction {};

    if (sigfillset(&newAction.sa_mask) == -1) {
        WIFI_LOGE("DhcpServerServiceImpl::RegisterSignal() failed, sigfillset error:%{public}s!", strerror(errno));
    }

    if (sigdelset(&newAction.sa_mask, SIGCHLD) == -1) {
        WIFI_LOGE("DhcpServerServiceImpl::RegisterSignal() sigdelset SIGCHLD error:%{public}s!", strerror(errno));
    }

    newAction.sa_handler = SigChildHandler;
    newAction.sa_flags = SA_RESTART;
    newAction.sa_restorer = nullptr;

    if (sigaction(SIGCHLD, &newAction, nullptr) == -1) {
        WIFI_LOGE("DhcpServerServiceImpl::RegisterSignal() sigaction SIGCHLD error:%{public}s!", strerror(errno));
    }
}

void DhcpServerServiceImpl::UnregisterSignal() const
{
    struct sigaction newAction {};

    if (sigemptyset(&newAction.sa_mask) == -1) {
        WIFI_LOGE("DhcpServerServiceImpl::UnregisterSignal() failed, sigemptyset error:%{public}s!", strerror(errno));
    }

    newAction.sa_handler = SIG_DFL;
    newAction.sa_flags = SA_RESTART;
    newAction.sa_restorer = nullptr;

    if (sigaction(SIGCHLD, &newAction, nullptr) == -1) {
        WIFI_LOGE("DhcpServerServiceImpl::UnregisterSignal() sigaction SIGCHLD error:%{public}s!", strerror(errno));
    }
}

int DhcpServerServiceImpl::AddSpecifiedInterface(const std::string& ifname)
{
    if (ifname.empty()) {
        WIFI_LOGE("AddSpecifiedInterface() error, ifname is empty!\n");
        return DHCP_OPT_FAILED;
    }

    if (m_setInterfaces.find(ifname) == m_setInterfaces.end()) {
        m_setInterfaces.insert(ifname);
        WIFI_LOGI("AddSpecifiedInterface() m_setInterfaces add ifname:%{public}s success.\n", ifname.c_str());
    } else {
        WIFI_LOGI("AddSpecifiedInterface() m_setInterfaces already exists ifname:%{public}s.\n", ifname.c_str());
    }

    return DHCP_OPT_SUCCESS;
}

int DhcpServerServiceImpl::DelSpecifiedInterface(const std::string& ifname)
{
    if (ifname.empty()) {
        WIFI_LOGE("DelSpecifiedInterface() error, ifname is empty!\n");
        return DHCP_OPT_FAILED;
    }

    auto iterInterfaces = m_setInterfaces.find(ifname);
    if (iterInterfaces != m_setInterfaces.end()) {
        m_setInterfaces.erase(iterInterfaces);
        WIFI_LOGI("DelSpecifiedInterface() m_setInterfaces del ifname:%{public}s success.\n", ifname.c_str());
    } else {
        WIFI_LOGI("DelSpecifiedInterface() m_setInterfaces not exists ifname:%{public}s.\n", ifname.c_str());
    }

    return DHCP_OPT_SUCCESS;
}

void DhcpServerServiceImpl::SigChildHandler(int signum)
{
    if (signum == SIGCHLD) {
        /* Received signal SIGCHLD, wait the dhcp server process pid status. */
        pid_t childPid = waitpid(GetServerPid(), nullptr, WUNTRACED | WNOHANG);
        if (childPid == GetServerPid()) {
            WIFI_LOGW("SigChildHandler() the dhcp server process received SIGCHLD.");
            mProExitSig = true;
        }
    }
}

pid_t DhcpServerServiceImpl::GetServerPid()
{
    return mPidDhcpServer;
}
}  // namespace Wifi
}  // namespace OHOS
