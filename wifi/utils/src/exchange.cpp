std::string appId = "";
    std::string packageName;
    GetBundleNameByUid(GetCallingUid(), packageName);
#ifndef OHOS_ARCH_LITE
    int32_t userId = static_cast<int32_t>(GetCallingUid() / UID_CALLINGUID_TRANSFORM_DIVISOR);
    appId = GetBundleAppIdByBundleName(userId, packageName);
#endif
    if (ProcessPermissionVerify(appId, packageName) == PERMISSION_DENIED) {
        if (WifiPermissionUtils::VerifyGetWifiPeersMacPermission() == PERMISSION_DENIED) {
            WIFI_LOGE("GetLinkedInfo:VerifyGetWifiPeersMacPermission() PERMISSION_DENIED!");
#ifdef SUPPORT_RANDOM_MAC_ADDR
        info.bssid = WifiConfigCenter::GetInstance().GetRandomMacAddr(WifiMacAddrInfoType::WIFI_SCANINFO_MACADDR_INFO,
            info.bssid);
        /* Clear mac addr */
        info.bssid = "";
#endif
        }


int WifiDeviceServiceImpl::ProcessPermissionVerify(const std::string &appId, const std::string &packageName)
{
    if (appId.length() == 0 || packageName.length() == 0) {
        WIFI_LOGI("ProcessPermissionVerify(), PERMISSION_DENIED");
        return PERMISSION_DENIED;
    }
    std::map<std::string, std::vector<std::string>> filterMap;
    if (WifiSettings::GetInstance().GetPackageFilterMap(filterMap) != 0) {
        WIFI_LOGE("WifiSettings::GetInstance().GetPackageFilterMap failed");
        return PERMISSION_DENIED;
    }
    std::vector<std::string> whilteListProcessInfo = filterMap["GetLinkProcessPermissionVerify"];
    auto iter = whilteListProcessInfo.begin();
    while (iter != whilteListProcessInfo.end()) {
        if (*iter == packageName + "|" + appId) {
            return PERMISSION_GRANTED;
        }
        iter++;
    }
    return PERMISSION_DENIED;
}