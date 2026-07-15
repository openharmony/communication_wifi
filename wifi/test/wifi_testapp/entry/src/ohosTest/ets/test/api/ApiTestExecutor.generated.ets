/**
 * Copyright (c) 2022 Shenzhen Kaihong Digital Industry Development Co., Ltd.
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

/** 本文件由 generate_ohostest_api_catalog.py 自动生成，请勿手改 */
import wifiManager from '@ohos.wifiManager';
import wifi from '@ohos.wifi';
import linkEnhance from '@ohos.distributedsched.linkEnhance';
import { BusinessError } from '@ohos.base';
import { ApiInvokeResult, ApiTestCase } from './ApiTestTypes';

function voidResult(): ApiInvokeResult {
  return { ok: true, valueType: 'void', value: undefined, errorCode: 0, errorMessage: '' };
}
function boolResult(v: boolean): ApiInvokeResult {
  return { ok: true, valueType: 'boolean', value: v, errorCode: 0, errorMessage: '' };
}
function numberResult(v: number): ApiInvokeResult {
  return { ok: true, valueType: 'number', value: v, errorCode: 0, errorMessage: '' };
}
function stringResult(v: string): ApiInvokeResult {
  return { ok: true, valueType: 'string', value: v, errorCode: 0, errorMessage: '' };
}
function arrayResult(v: Array<Object>): ApiInvokeResult {
  return { ok: true, valueType: 'array', value: v, errorCode: 0, errorMessage: '' };
}
function objectResult(v: Object): ApiInvokeResult {
  return { ok: true, valueType: 'object', value: v, errorCode: 0, errorMessage: '' };
}
function failResult(e: BusinessError): ApiInvokeResult {
  return {
    ok: false,
    valueType: 'none',
    value: undefined,
    errorCode: e.code,
    errorMessage: e.message
  };
}

function buildWifiDeviceConfig(params: Record<string, Object>): wifiManager.WifiDeviceConfig {
  return {
    ssid: (params['ssid'] as string) || 'ut_default',
    bssid: '',
    preSharedKey: (params['preSharedKey'] as string) || '',
    isHiddenSsid: (params['isHiddenSsid'] as boolean) || false,
    securityType: (params['securityType'] as number) || 0,
    creatorUid: 0,
    disableReason: 0,
    netId: -1,
    randomMacType: 0,
    randomMacAddr: '',
    ipType: (params['ipType'] as number) || 0,
    staticIp: { ipAddress: 0, gateway: 0, prefixLength: 0, dnsServers: [], domains: [] }
  };
}

function buildHotspotConfig(params: Record<string, Object>): wifiManager.HotspotConfig {
  return {
    ssid: (params['ssid'] as string) || 'OH_Hotspot',
    preSharedKey: (params['preSharedKey'] as string) || '12345678',
    securityType: 3,
    band: (params['band'] as number) || 0,
    channel: (params['channel'] as number) || 6,
    maxConn: 8,
  };
}

function buildP2pConfig(params: Record<string, Object>): wifiManager.WifiP2PConfig {
  return {
    netId: (params['netId'] as number) || 0,
    passphrase: (params['passphrase'] as string) || '12345678',
    goBand: (params['goBand'] as number) || 0,
    deviceAddress: '',
    groupName: 'OH_P2P_Group',
  };
}

async function invokeWifiManagerApi(
  api: string,
  params: Record<string, Object>
): Promise<ApiInvokeResult> {
  switch (api) {
    case "addCandidateConfig": {
      const cfg2 = buildWifiDeviceConfig(params);
      const id2 = await wifiManager.addCandidateConfig(cfg2);
      return numberResult(id2);
    }
    case "addDeviceConfig": {
      const cfgMode = params['invokeMode'] as string;
      const devCfg = buildWifiDeviceConfig(params);
      if (cfgMode === 'callback') {
        return new Promise((resolve) => {
          wifiManager.addDeviceConfig(devCfg, (err, resId) => {
            if (err) {
              resolve(failResult(err));
            } else {
              resolve(numberResult(resId));
            }
          });
        });
      }
      const newId = await wifiManager.addDeviceConfig(devCfg);
      return numberResult(newId);
    }
    case "allowAutoConnect": {
      wifiManager.allowAutoConnect(
        params['netId'] as number,
        params['isAllowed'] as boolean);
      return voidResult();
    }
    case "connectToCandidateConfig": {
      wifiManager.connectToCandidateConfig(params['netId'] as number);
      return voidResult();
    }
    case "connectToCandidateConfigWithUserAction": {
      const netId = (params['netId'] as number) || 0;
      await wifiManager.connectToCandidateConfigWithUserAction(
        netId);
      return voidResult();
    }
    case "connectToDevice": {
      wifiManager.connectToDevice(buildWifiDeviceConfig(params));
      return voidResult();
    }
    case "connectToNetwork": {
      wifiManager.connectToNetwork(params['netId'] as number);
      return voidResult();
    }
    case "createGroup": {
      wifiManager.createGroup(buildP2pConfig(params));
      return voidResult();
    }
    case "deletePersistentGroup": {
      wifiManager.deletePersistentGroup(params['netId'] as number);
      return voidResult();
    }
    case "disableHotspot": {
      wifiManager.disableHotspot(); return voidResult();
    }
    case "disableNetwork": {
      if (params['blockDuration'] !== undefined) {
        wifiManager.disableNetwork(
          params['netId'] as number,
          params['blockDuration'] as number);
      } else {
        wifiManager.disableNetwork(params['netId'] as number);
      }
      return voidResult();
    }
    case "disableWifi": {
      wifiManager.disableWifi(); return voidResult();
    }
    case "disconnect": {
      wifiManager.disconnect(); return voidResult();
    }
    case "enableHotspot": {
      wifiManager.enableHotspot(); return voidResult();
    }
    case "enableSemiWifi": {
      wifiManager.enableSemiWifi(); return voidResult();
    }
    case "enableWifi": {
      wifiManager.enableWifi(); return voidResult();
    }
    case "factoryReset": {
      wifiManager.factoryReset(); return voidResult();
    }
    case "get5GChannelList": {
      return {
        ok: false,
        valueType: 'none',
        value: undefined,
        errorCode: -1,
        errorMessage: 'skipped_device_hang_risk:get5GChannelList'
      };
    }
    case "getCandidateConfigs": {
      return arrayResult(wifiManager.getCandidateConfigs());
    }
    case "getCountryCode": {
      return stringResult(wifiManager.getCountryCode());
    }
    case "getCurrentGroup": {
      const grp = await wifiManager.getCurrentGroup();
      return objectResult(grp);
    }
    case "getDeviceConfigs": {
      return arrayResult(wifiManager.getDeviceConfigs());
    }
    case "getDeviceMacAddress": {
      return arrayResult(wifiManager.getDeviceMacAddress());
    }
    case "getDisconnectedReason": {
      return numberResult(wifiManager.getDisconnectedReason());
    }
    case "getHotspotBlockList": {
      return arrayResult(wifiManager.getHotspotBlockList());
    }
    case "getHotspotConfig": {
      return objectResult(wifiManager.getHotspotConfig());
    }
    case "getIpInfo": {
      return objectResult(wifiManager.getIpInfo());
    }
    case "getIpv6Info": {
      return objectResult(wifiManager.getIpv6Info());
    }
    case "getLinkedInfo": {
      const linkMode = params['invokeMode'] as string;
      if (linkMode === 'callback') {
        return new Promise((resolve) => {
          wifiManager.getLinkedInfo((err, linkInfo) => {
            if (err) {
              resolve(failResult(err));
            } else {
              resolve(objectResult(linkInfo));
            }
          });
        });
      }
      if (linkMode === 'sync') {
        return objectResult(wifiManager.getLinkedInfoSync());
      }
      const linkInfo2 = await wifiManager.getLinkedInfo();
      return objectResult(linkInfo2);
    }
    case "getLinkedInfoSync": {
      return objectResult(wifiManager.getLinkedInfoSync());
    }
    case "getMultiLinkedInfo": {
      return arrayResult(wifiManager.getMultiLinkedInfo());
    }
    case "getP2pGroups": {
      const groups = await wifiManager.getP2pGroups();
      return arrayResult(groups);
    }
    case "getP2pLinkedInfo": {
      const p2pInfo = await wifiManager.getP2pLinkedInfo();
      return objectResult(p2pInfo);
    }
    case "getP2pLocalDevice": {
      const localDev = await wifiManager.getP2pLocalDevice();
      return objectResult(localDev);
    }
    case "getP2pPeerDevices": {
      const peers = await wifiManager.getP2pPeerDevices();
      return arrayResult(peers);
    }
    case "getScanAlwaysAllowed": {
      return boolResult(wifiManager.getScanAlwaysAllowed());
    }
    case "getScanInfoList": {
      return arrayResult(wifiManager.getScanInfoList());
    }
    case "getScanResults": {
      const scanMode = params['invokeMode'] as string;
      if (scanMode === 'callback') {
        return new Promise((resolve) => {
          wifiManager.getScanResults((err, scanList) => {
            if (err) {
              resolve(failResult(err));
            } else {
              resolve(arrayResult(scanList));
            }
          });
        });
      }
      if (scanMode === 'sync') {
        return arrayResult(wifiManager.getScanResultsSync());
      }
      const scanList2 = await wifiManager.getScanResults();
      return arrayResult(scanList2);
    }
    case "getScanResultsSync": {
      return arrayResult(wifiManager.getScanResultsSync());
    }
    case "getSignalLevel": {
      return numberResult(wifiManager.getSignalLevel(
        params['rssi'] as number, params['band'] as number));
    }
    case "getStations": {
      return arrayResult(wifiManager.getStations());
    }
    case "getSupportedFeatures": {
      return numberResult(wifiManager.getSupportedFeatures());
    }
    case "getWifiDetailState": {
      return numberResult(wifiManager.getWifiDetailState());
    }
    case "isBandTypeSupported": {
      return boolResult(wifiManager.isBandTypeSupported(
        params['bandType'] as number));
    }
    case "isConnected": {
      return boolResult(wifiManager.isConnected());
    }
    case "isFeatureSupported": {
      return boolResult(wifiManager.isFeatureSupported(
        params['featureId'] as number));
    }
    case "isHotspotActive": {
      return boolResult(wifiManager.isHotspotActive());
    }
    case "isHotspotDualBandSupported": {
      return {
        ok: false,
        valueType: 'none',
        value: undefined,
        errorCode: -1,
        errorMessage: 'skipped_device_hang_risk:isHotspotDualBandSupported'
      };
    }
    case "isMeteredHotspot": {
      return boolResult(wifiManager.isMeteredHotspot());
    }
    case "isOpenSoftApAllowed": {
      return boolResult(wifiManager.isOpenSoftApAllowed());
    }
    case "isRandomMacDisabled": {
      return boolResult(wifiManager.isRandomMacDisabled());
    }
    case "isWifiActive": {
      return boolResult(wifiManager.isWifiActive());
    }
    case "p2pCancelConnect": {
      wifiManager.p2pCancelConnect(); return voidResult();
    }
    case "p2pConnect": {
      wifiManager.p2pConnect(buildP2pConfig(params));
      return voidResult();
    }
    case "reassociate": {
      wifiManager.reassociate(); return voidResult();
    }
    case "reconnect": {
      wifiManager.reconnect(); return voidResult();
    }
    case "removeAllNetwork": {
      wifiManager.removeAllNetwork(); return voidResult();
    }
    case "removeCandidateConfig": {
      await wifiManager.removeCandidateConfig((params['netId'] as number) || 0);
      return voidResult();
    }
    case "removeDevice": {
      wifiManager.removeDevice(params['id'] as number);
      return voidResult();
    }
    case "removeGroup": {
      wifiManager.removeGroup(); return voidResult();
    }
    case "scan": {
      wifiManager.scan(); return voidResult();
    }
    case "setDeviceName": {
      wifiManager.setDeviceName(params['devName'] as string);
      return voidResult();
    }
    case "setHotspotConfig": {
      wifiManager.setHotspotConfig(buildHotspotConfig(params));
      return voidResult();
    }
    case "setScanAlwaysAllowed": {
      wifiManager.setScanAlwaysAllowed(params['allowed'] as boolean);
      return voidResult();
    }
    case "startDiscoverDevices": {
      wifiManager.startDiscoverDevices();
      return voidResult();
    }
    case "startPortalCertification": {
      wifiManager.startPortalCertification();
      return voidResult();
    }
    case "startScan": {
      wifiManager.startScan(); return voidResult();
    }
    case "startWifiDetection": {
      wifiManager.startWifiDetection();
      return voidResult();
    }
    case "stopDiscoverDevices": {
      wifiManager.stopDiscoverDevices(); return voidResult();
    }
    case "updateNetwork": {
      return numberResult(
        wifiManager.updateNetwork(buildWifiDeviceConfig(params)));
    }
    default:
      return {
        ok: false,
        valueType: 'none',
        value: undefined,
        errorCode: -1,
        errorMessage: 'unknown api: ' + api
      };
  }
}

async function invokeWifiApi(
  api: string,
  params: Record<string, Object>
): Promise<ApiInvokeResult> {
  switch (api) {
    case 'enableWifi':
      wifi.enableWifi();
      return voidResult();
    case 'disableWifi':
      wifi.disableWifi();
      return voidResult();
    case 'isWifiActive':
      return boolResult(wifi.isWifiActive());
    case 'scan':
      wifi.scan();
      return voidResult();
    case 'isConnected':
      return boolResult(wifi.isConnected());
    case 'getSignalLevel':
      return numberResult(wifi.getSignalLevel(
        params['rssi'] as number,
        params['band'] as number));
    case 'getIpInfo':
      return objectResult(wifi.getIpInfo());
    case 'getCountryCode':
      return stringResult(wifi.getCountryCode());
    case 'getSupportedFeatures':
      return numberResult(wifi.getSupportedFeatures());
    case 'isFeatureSupported':
      return boolResult(wifi.isFeatureSupported(
        params['featureId'] as number));
    case 'enableHotspot':
      wifi.enableHotspot();
      return voidResult();
    case 'disableHotspot':
      wifi.disableHotspot();
      return voidResult();
    case 'isHotspotActive':
      return boolResult(wifi.isHotspotActive());
    case 'getHotspotConfig':
      return objectResult(wifi.getHotspotConfig());
    case 'getP2pPeerDevices':
      return arrayResult(await wifi.getP2pPeerDevices());
    case 'startDiscoverDevices':
      wifi.startDiscoverDevices();
      return voidResult();
    case 'stopDiscoverDevices':
      wifi.stopDiscoverDevices();
      return voidResult();
    default:
      return {
        ok: false,
        valueType: 'none',
        value: undefined,
        errorCode: -1,
        errorMessage: 'unknown wifi api'
      };
  }
}

async function invokeLinkEnhanceApi(
  api: string,
  params: Record<string, Object>
): Promise<ApiInvokeResult> {
  switch (api) {
    case 'createServer':
      return objectResult(
        linkEnhance.createServer(params['name'] as string));
    case 'createConnection':
      return objectResult(linkEnhance.createConnection(
        params['deviceId'] as string,
        params['name'] as string));
    default:
      return {
        ok: false,
        valueType: 'none',
        value: undefined,
        errorCode: -1,
        errorMessage: 'unknown linkEnhance api'
      };
  }
}

function noopCallback(): void {}

async function invokeEventApi(
  params: Record<string, Object>
): Promise<ApiInvokeResult> {
  const action = params['action'] as string;
  const event = params['event'] as string;
  const cb = noopCallback;
  const reg = action === 'register';
  switch (event) {
    case 'wifiStateChange':
      if (reg) {
        wifiManager.on('wifiStateChange', cb);
      } else {
        wifiManager.off('wifiStateChange', cb);
      }
      break;
    case 'wifiConnectionChange':
      if (reg) {
        wifiManager.on('wifiConnectionChange', cb);
      } else {
        wifiManager.off('wifiConnectionChange', cb);
      }
      break;
    case 'wifiScanStateChange':
      if (reg) {
        wifiManager.on('wifiScanStateChange', cb);
      } else {
        wifiManager.off('wifiScanStateChange', cb);
      }
      break;
    case 'wifiRssiChange':
      if (reg) {
        wifiManager.on('wifiRssiChange', cb);
      } else {
        wifiManager.off('wifiRssiChange', cb);
      }
      break;
    case 'streamChange':
      if (reg) {
        wifiManager.on('streamChange', cb);
      } else {
        wifiManager.off('streamChange', cb);
      }
      break;
    case 'deviceConfigChange':
      if (reg) {
        wifiManager.on('deviceConfigChange', cb);
      } else {
        wifiManager.off('deviceConfigChange', cb);
      }
      break;
    case 'hotspotStateChange':
      if (reg) {
        wifiManager.on('hotspotStateChange', cb);
      } else {
        wifiManager.off('hotspotStateChange', cb);
      }
      break;
    case 'hotspotStaJoin':
      if (reg) {
        wifiManager.on('hotspotStaJoin', cb);
      } else {
        wifiManager.off('hotspotStaJoin', cb);
      }
      break;
    case 'hotspotStaLeave':
      if (reg) {
        wifiManager.on('hotspotStaLeave', cb);
      } else {
        wifiManager.off('hotspotStaLeave', cb);
      }
      break;
    case 'p2pStateChange':
      if (reg) {
        wifiManager.on('p2pStateChange', cb);
      } else {
        wifiManager.off('p2pStateChange', cb);
      }
      break;
    case 'p2pConnectionChange':
      if (reg) {
        wifiManager.on('p2pConnectionChange', cb);
      } else {
        wifiManager.off('p2pConnectionChange', cb);
      }
      break;
    case 'p2pDeviceChange':
      if (reg) {
        wifiManager.on('p2pDeviceChange', cb);
      } else {
        wifiManager.off('p2pDeviceChange', cb);
      }
      break;
    case 'p2pPeerDeviceChange':
      if (reg) {
        wifiManager.on('p2pPeerDeviceChange', cb);
      } else {
        wifiManager.off('p2pPeerDeviceChange', cb);
      }
      break;
    case 'p2pPersistentGroupChange':
      if (reg) {
        wifiManager.on('p2pPersistentGroupChange', cb);
      } else {
        wifiManager.off('p2pPersistentGroupChange', cb);
      }
      break;
    case 'p2pDiscoveryChange':
      if (reg) {
        wifiManager.on('p2pDiscoveryChange', cb);
      } else {
        wifiManager.off('p2pDiscoveryChange', cb);
      }
      break;
    default:
      return {
        ok: false,
        valueType: 'none',
        value: undefined,
        errorCode: -1,
        errorMessage: 'unknown event'
      };
  }
  return voidResult();
}

export async function invokeApiTestCase(
  tc: ApiTestCase
): Promise<ApiInvokeResult> {
  try {
    if (tc.api.startsWith('on_')) {
      return await invokeEventApi(tc.params);
    }
    if (tc.module === 'wifiManager') {
      return await invokeWifiManagerApi(tc.api, tc.params);
    }
    if (tc.module === 'wifi') {
      return await invokeWifiApi(tc.api, tc.params);
    }
    if (tc.module === 'linkEnhance') {
      return await invokeLinkEnhanceApi(tc.api, tc.params);
    }
    return {
      ok: false,
      valueType: 'none',
      value: undefined,
      errorCode: -1,
      errorMessage: 'unknown module'
    };
  } catch (e) {
    return failResult(e as BusinessError);
  }
}
