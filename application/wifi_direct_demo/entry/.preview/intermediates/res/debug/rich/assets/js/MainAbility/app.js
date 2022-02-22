/******/ (() => { // webpackBootstrap
/******/ 	"use strict";
/******/ 	var __webpack_modules__ = ({

/***/ "../../../../../../../DEMO/p2pConn/entry/src/main/ets/MainAbility/app.ets?entry":
/*!**************************************************************************************!*\
  !*** ../../../../../../../DEMO/p2pConn/entry/src/main/ets/MainAbility/app.ets?entry ***!
  \**************************************************************************************/
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {


var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", ({ value: true }));
const LogUtil_ets_1 = __importDefault(__webpack_require__(/*! ./common/LogUtil.ets */ "../../../../../../../DEMO/p2pConn/entry/src/main/ets/MainAbility/common/LogUtil.ets"));
const WifiModel_ets_1 = __importDefault(__webpack_require__(/*! ./model/wifiModeImpl/WifiModel.ets */ "../../../../../../../DEMO/p2pConn/entry/src/main/ets/MainAbility/model/wifiModeImpl/WifiModel.ets"));
globalThis.exports.default = {
    onCreate() {
        LogUtil_ets_1.default.info('Application onCreate');
        WifiModel_ets_1.default.enableP2p();
    },
    onDestroy() {
        LogUtil_ets_1.default.info('Application onDestroy');
    },
};


/***/ }),

/***/ "../../../../../../../DEMO/p2pConn/entry/src/main/ets/MainAbility/common/LogUtil.ets":
/*!*******************************************************************************************!*\
  !*** ../../../../../../../DEMO/p2pConn/entry/src/main/ets/MainAbility/common/LogUtil.ets ***!
  \*******************************************************************************************/
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {


var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.LogUtil = void 0;
const BaseModel_ets_1 = __importDefault(__webpack_require__(/*! ../model/BaseModel.ets */ "../../../../../../../DEMO/p2pConn/entry/src/main/ets/MainAbility/model/BaseModel.ets"));
class LogUtil extends BaseModel_ets_1.default {
    TAG() {
        return '------------ P2P ------------ ';
    }
    debug(msg) {
        console.info(this.TAG() + msg);
    }
    log(msg) {
        console.log(this.TAG() + msg);
    }
    info(msg) {
        console.info(this.TAG() + msg);
    }
    warn(msg) {
        console.warn(this.TAG() + msg);
    }
    error(msg) {
        console.error(this.TAG() + msg);
    }
}
exports.LogUtil = LogUtil;
let mLogUtil = new LogUtil();
exports["default"] = mLogUtil;


/***/ }),

/***/ "../../../../../../../DEMO/p2pConn/entry/src/main/ets/MainAbility/model/BaseModel.ets":
/*!********************************************************************************************!*\
  !*** ../../../../../../../DEMO/p2pConn/entry/src/main/ets/MainAbility/model/BaseModel.ets ***!
  \********************************************************************************************/
/***/ ((__unused_webpack_module, exports) => {


Object.defineProperty(exports, "__esModule", ({ value: true }));
class BaseModel {
    constructor() {
    }
}
exports["default"] = BaseModel;


/***/ }),

/***/ "../../../../../../../DEMO/p2pConn/entry/src/main/ets/MainAbility/model/wifiModeImpl/WifiModel.ets":
/*!*********************************************************************************************************!*\
  !*** ../../../../../../../DEMO/p2pConn/entry/src/main/ets/MainAbility/model/wifiModeImpl/WifiModel.ets ***!
  \*********************************************************************************************************/
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {


var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.WifiModel = void 0;
const BaseModel_ets_1 = __importDefault(__webpack_require__(/*! ../BaseModel.ets */ "../../../../../../../DEMO/p2pConn/entry/src/main/ets/MainAbility/model/BaseModel.ets"));
const LogUtil_ets_1 = __importDefault(__webpack_require__(/*! ../../common/LogUtil.ets */ "../../../../../../../DEMO/p2pConn/entry/src/main/ets/MainAbility/common/LogUtil.ets"));
//var WifiNativeJs = isSystemplugin('wifi_native_js', 'ohos') ? globalThis.ohosplugin.wifi_native_js : isSystemplugin('wifi_native_js', 'system') ? globalThis.systemplugin.wifi_native_js : globalThis.requireNapi('wifi_native_js');
var WifiNativeJs = isSystemplugin('wifi', 'ohos') ? globalThis.ohosplugin.wifi : isSystemplugin('wifi', 'system') ? globalThis.systemplugin.wifi : globalThis.requireNapi('wifi');
class WifiModel extends BaseModel_ets_1.default {
    getListener() {
        return new WifiNativeJs.EventListener();
    }
    enableP2p() {
        LogUtil_ets_1.default.log("enableP2p");
        return WifiNativeJs.enableP2p();
    }
    disableP2p() {
        LogUtil_ets_1.default.log("disableP2p");
        return WifiNativeJs.disableP2p();
    }
    on(typeValue, callBack) {
        LogUtil_ets_1.default.log("on  " + typeValue);
        WifiNativeJs.on(typeValue, callBack);
    }
    discoverDevices() {
        LogUtil_ets_1.default.log("startDiscoverDevices");
        return WifiNativeJs.startDiscoverDevices();
    }
    stopDiscoverDevices() {
        LogUtil_ets_1.default.log("stopDiscoverDevices");
        return WifiNativeJs.stopDiscoverDevices();
    }
    discoverServices() {
        LogUtil_ets_1.default.log("DiscoverServices");
        return WifiNativeJs.discoverServices();
    }
    setDeviceName(name) {
        LogUtil_ets_1.default.log("setDeviceName");
        return WifiNativeJs.setP2pDeviceName(name);
    }
    stopDiscoverServices() {
        LogUtil_ets_1.default.log("stopDiscoverServices");
        return WifiNativeJs.stopDiscoverServices();
    }
    connectP2pDevices(config) {
        LogUtil_ets_1.default.log("connectP2pDevices");
        return WifiNativeJs.p2pConnect(config);
    }
    disconnectP2pDevices() {
        LogUtil_ets_1.default.log("disconnectP2pDevices");
        return WifiNativeJs.removeGroup();
    }
    cancelConnect() {
        LogUtil_ets_1.default.log("wifi direct - p2pCancelConnect()");
        return WifiNativeJs.p2pCancelConnect()();
    }
    getLinkInfo(cb) {
        LogUtil_ets_1.default.log("getLinkInfo");
        WifiNativeJs.getP2pLinkedInfo((result) => {
            LogUtil_ets_1.default.log("getLinkInfo  " + JSON.stringify(result));
            let resultStr = null;
            if (result != null) {
                let info = JSON.parse(JSON.stringify(result));
                resultStr = 'connectState��' + (info.connectState == 1 ? 'CONNECTED' : 'DISCONNECTED') + '\nisP2pGroupOwner��' + info.isP2pGroupOwner + '\ngroupOwnerAddress��' + info.groupOwnerAddress;
            }
            cb(resultStr);
        });
    }
    getCurrentGroupInfo(cb) {
        LogUtil_ets_1.default.log("getCurrentGroupInfo");
        WifiNativeJs.getCurrentGroup((result) => {
            let info = result;
            LogUtil_ets_1.default.log("current group result = " + result);
            if (result != null) {
                LogUtil_ets_1.default.log("current group info = " + JSON.stringify(result));
                info = JSON.parse(JSON.stringify(result));
            }
            cb(info);
        });
    }
    getP2pDevicesCallBack() {
        LogUtil_ets_1.default.log("wifi model getP2pDevicesCallBack");
        let mDeviceList = [];
        return new Promise((resolve) => {
            WifiNativeJs.getP2pDevices((result) => {
                if (result == null) {
                    LogUtil_ets_1.default.log("WifiNativeJs queryP2pDevices");
                    return;
                }
                let datas = JSON.parse(JSON.stringify(result));
                LogUtil_ets_1.default.log('result ===   ' + JSON.stringify(result));
                for (let j = 0; j < datas.length; j++) {
                    mDeviceList.push({
                        ssid: datas[j].deviceName,
                        macAddress: datas[j].macAddress,
                        status: datas[j].status
                    });
                }
                LogUtil_ets_1.default.log("mWifiList = " + JSON.stringify(mDeviceList));
                resolve(mDeviceList);
            });
        });
    }
    createGroup() {
        /*
            const int TEMPORARY_NET_ID = -1;
            const int PERSISTENT_NET_ID = -2;
            const int INVALID_NET_ID = -999;
             */
        WifiNativeJs.createGroup({
            'netId': -2
        });
    }
    deletePersistentGroup(id) {
        LogUtil_ets_1.default.log("deletePersistentGroup id = " + id);
        return WifiNativeJs.deletePersistentGroup(id);
    }
    removeGroup() {
        WifiNativeJs.removeGroup();
    }
    getMacAddress() {
        LogUtil_ets_1.default.log("getMacAddress");
        return WifiNativeJs.getDeviceMacAddress();
    }
    setWfdInfo() {
        return WifiNativeJs.setP2pWfdInfo(true);
    }
}
exports.WifiModel = WifiModel;
let wifiModel = new WifiModel();
exports["default"] = wifiModel;


/***/ })

/******/ 	});
/************************************************************************/
/******/ 	// The module cache
/******/ 	var __webpack_module_cache__ = {};
/******/ 	
/******/ 	// The require function
/******/ 	function __webpack_require__(moduleId) {
/******/ 		// Check if module is in cache
/******/ 		var cachedModule = __webpack_module_cache__[moduleId];
/******/ 		if (cachedModule !== undefined) {
/******/ 			return cachedModule.exports;
/******/ 		}
/******/ 		// Create a new module (and put it into the cache)
/******/ 		var module = __webpack_module_cache__[moduleId] = {
/******/ 			// no module.id needed
/******/ 			// no module.loaded needed
/******/ 			exports: {}
/******/ 		};
/******/ 	
/******/ 		// Execute the module function
/******/ 		__webpack_modules__[moduleId].call(module.exports, module, module.exports, __webpack_require__);
/******/ 	
/******/ 		// Return the exports of the module
/******/ 		return module.exports;
/******/ 	}
/******/ 	
/************************************************************************/
/******/ 	
/******/ 	// startup
/******/ 	// Load entry module and return exports
/******/ 	// This entry module is referenced by other modules so it can't be inlined
/******/ 	var __webpack_exports__ = __webpack_require__("../../../../../../../DEMO/p2pConn/entry/src/main/ets/MainAbility/app.ets?entry");
/******/ 	
/******/ })()
;