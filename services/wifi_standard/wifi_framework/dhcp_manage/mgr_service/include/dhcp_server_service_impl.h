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

#ifndef OHOS_DHCP_SERVER_SERVICE_IMPL_H
#define OHOS_DHCP_SERVER_SERVICE_IMPL_H

#include <sys/types.h>
#include <sys/wait.h>
#include <map>
#include <list>
#include <vector>
#include <set>
#include <thread>

#include "i_dhcp_server_service.h"
#include "dhcp_define.h"


namespace OHOS {
namespace Wifi {
class DhcpServerServiceImpl : public IDhcpServerService {
public:
    /**
     * @Description : Construct a new dhcp server service object.
     *
     */
    DhcpServerServiceImpl();

    /**
     * @Description : Destroy the dhcp server service object.
     *
     */
    ~DhcpServerServiceImpl() override;

    /**
     * @Description : Start dhcp server service of specified interface.
     *
     * @param ifname - interface name, eg:wlan0 [in]
     * @Return : success - DHCP_OPT_SUCCESS, failed - others.
     */
    int StartDhcpServer(const std::string& ifname) override;

    /**
     * @Description : Stop dhcp server service of specified interface.
     *
     * @param ifname - interface name, eg:wlan0 [in]
     * @Return : success - DHCP_OPT_SUCCESS, failed - others.
     */
    int StopDhcpServer(const std::string& ifname) override;

    /**
     * @Description : Get dhcp server service running status.
     *
     * @Return : 0 - not start, 1 - normal started.
     */
    int GetServerStatus(void) override;

    /**
     * @Description : Add or update dhcp ip address pool.
     *
     * @param tagName - ip address pool tag name [in]
     * @param range - ip address range [in]
     * @Return : success - DHCP_OPT_SUCCESS, failed - others.
     */
    int PutDhcpRange(const std::string& tagName, const DhcpRange& range) override;

    /**
     * @Description : Remove dhcp ip address pool.
     *
     * @param tagName - ip address pool tag name [in]
     * @param range - ip address range [in]
     * @Return : success - DHCP_OPT_SUCCESS, failed - others.
     */
    int RemoveDhcpRange(const std::string& tagName, const DhcpRange& range) override;

    /**
     * @Description : Remove all dhcp ip address pool.
     *
     * @param tagName - ip address pool tag name [in]
     * @Return : success - DHCP_OPT_SUCCESS, failed - others.
     */
    int RemoveAllDhcpRange(const std::string& tagName) override;

    /**
     * @Description : Set dhcp ip address pool of specified interface.
     *
     * @param ifname - interface name, eg:wlan0 [in]
     * @param range - ip address range [in]
     * @Return : success - DHCP_OPT_SUCCESS, failed - others.
     */
    int SetDhcpRange(const std::string& ifname, const DhcpRange& range) override;

    /**
     * @Description : Set dhcp ip address pool of specified interface.
     *
     * @param ifname - interface name, eg:wlan0 [in]
     * @param tagName - ip address pool tag name [in]
     * @Return : success - DHCP_OPT_SUCCESS, failed - others.
     */
    int SetDhcpRange(const std::string& ifname, const std::string& tagName) override;

    /**
     * @Description : Get dhcp server lease info.
     *
     * @param leases - lease info [out]
     * @Return : success - DHCP_OPT_SUCCESS, failed - others.
     */
    int GetLeases(std::vector<std::string>& leases) override;

    /**
     * @Description : Obtain the abnormal exit status of dhcp server process.
     *
     * @param ifname - interface name, eg:wlan0 [in]
     * @param pResultNotify - pointer to dhcp result notify [in]
     * @Return : success - DHCP_OPT_SUCCESS, failed - others.
     */
    int GetDhcpSerProExit(const std::string& ifname, IDhcpResultNotify *pResultNotify) override;

    /**
     * @Description : Reload dhcp server config.
     *
     * @Return : success - DHCP_OPT_SUCCESS, failed - others.
     */
    int ReConf(void) override;

    /**
     * @Description : Check and update dhcp server config of specified interface.
     *
     * @param ifname - interface name, eg:wlan0 [in]
     * @Return : success - DHCP_OPT_SUCCESS, failed - others.
     */
    int CheckAndUpdateConf(const std::string& ifname);

    /**
     * @Description : Delete dhcp server config of specified interface and reload all config.
     *
     * @param if_filename - interface file name, eg:wlan0.conf [in]
     * @Return : success - DHCP_OPT_SUCCESS, failed - others.
     */
    int DeleteInfConf(const std::string& if_filename);

    /**
     * @Description : Check invalid or already exist in dhcp range.
     *
     * @param range - ip address range [in]
     * @Return : true - yes, false - no.
     */
    bool CheckIpAddrRange(const DhcpRange& range);

    /**
     * @Description : Check ip address range is or not conflict.
     *
     * @param srcRange - already exist in ip address range [in]
     * @param addRange - need add ip address range [in]
     * @Return : true - yes, false - no.
     */
    bool CheckDhcpRangeConflict(const DhcpRange& srcRange, const DhcpRange& addRange);

    /**
     * @Description : Add the specified interface.
     *
     * @param ifname - interface name, eg:wlan0 [in]
     * @Return : success - DHCP_OPT_SUCCESS, failed - others.
     */
    int AddSpecifiedInterface(const std::string& ifname);

    /**
     * @Description : Delete the specified interface.
     *
     * @param ifname - interface name, eg:wlan0 [in]
     * @Return : success - DHCP_OPT_SUCCESS, failed - others.
     */
    int DelSpecifiedInterface(const std::string& ifname);

private:
    /**
     * @Description : Fork parent process function.
     *
     * @Return : success - DHCP_OPT_SUCCESS, failed - others.
     */
    int ForkParentProcess();

    /**
     * @Description : Fork child process function for start dhcp server process.
     *
     * @param ifname - interface name, eg:wlan0 [in]
     * @Return : success - DHCP_OPT_SUCCESS, failed - others.
     */
    int ForkExecProcess(const std::string& ifname = "reload cfg");

    /**
     * @Description : Stop dhcp server process.
     *
     * @param server_pid - process id [in]
     * @Return : success - DHCP_OPT_SUCCESS, failed - others.
     */
    int StopServer(const pid_t& server_pid);

    /**
     * @Description : Check ip address range list is or not same.
     *
     * @param tagRange - tag ip address range list [in]
     * @param infRange - interface ip address range list [in]
     * @Return : true - same, false - not same.
     */
    bool CheckTagDhcpRange(std::list<DhcpRange> &tagRange, std::list<DhcpRange> &infRange);

    /**
     * @Description : Exit dhcp process exit abnormal notify thread.
     *
     */
    void ExitDhcpMgrThreadFunc();

    /**
     * @Description : Dhcp server process exit abnormal notify.
     *
     */
    void RunDhcpSerProExitThreadFunc();

    /**
     * @Description : Register the SIGCHID signal.
     *
     */
    void RegisterSignal() const;

    /**
     * @Description : Unregister the SIGCHID signal.
     *
     */
    void UnregisterSignal() const;

    /**
     * @Description : Receives the SIGCHLD signal of the dhcp server process.
     *
     */
    static void SigChildHandler(int signum);

    /**
     * @Description : Get dhcp server process id.
     *
     * @Return : dhcp server process id.
     */
    static pid_t GetServerPid();

private:
    static bool mProExitSig;                /* dhcp server process exit signal */
    static bool mStopServer;                /* dhcp server process normal exit */
    static pid_t mPidDhcpServer;            /* dhcp server process id */
    std::set<std::string> m_setInterfaces;  /* the started specified interfaces */
    std::map<std::string, std::list<DhcpRange>> m_mapTagDhcpRange;  /* dhcp server can be used ip range */
    std::map<std::string, std::list<DhcpRange>> m_mapInfDhcpRange;  /* dhcp server using ip range */
    std::map<std::string, IDhcpResultNotify *> m_mapDhcpSerExitNotify;

    bool bDhcpSerProExitThread;
    std::thread *pDhcpSerProExitThread;
};
}  // namespace Wifi
}  // namespace OHOS
#endif