if (WifiPermissionUtils::VerifySetWifiConfigPermission() == PERMISSION_DENIED) {
    WIFI_LOGE("RegisterAutoJoinCondition:VerifySetWifiConfigPermission PERMISSION_DENIED!");
    return WIFI_OPT_PERMISSION_DENIED;
}

if (WifiPermissionUtils::VerifySetWifiConfigPermission() == PERMISSION_DENIED) {
    WIFI_LOGE("DeregisterAutoJoinCondition:VerifySetWifiConfigPermission PERMISSION_DENIED!");
    return WIFI_OPT_PERMISSION_DENIED;
}

if (WifiPermissionUtils::VerifySetWifiConfigPermission() == PERMISSION_DENIED) {
    WIFI_LOGE("RegisterFilterBuilder:VerifySetWifiConfigPermission PERMISSION_DENIED!");
    return WIFI_OPT_PERMISSION_DENIED;
}

if (WifiPermissionUtils::VerifySetWifiConfigPermission() == PERMISSION_DENIED) {
    WIFI_LOGE("DeregisterFilterBuilder:VerifySetWifiConfigPermission PERMISSION_DENIED!");
    return WIFI_OPT_PERMISSION_DENIED;
}