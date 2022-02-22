/******/ (() => { // webpackBootstrap
/******/ 	"use strict";
/******/ 	var __webpack_modules__ = ({

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

/***/ "../../../../../../../DEMO/p2pConn/entry/src/main/ets/MainAbility/common/StorageUtil.ets":
/*!***********************************************************************************************!*\
  !*** ../../../../../../../DEMO/p2pConn/entry/src/main/ets/MainAbility/common/StorageUtil.ets ***!
  \***********************************************************************************************/
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {


var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.StorageUtil = void 0;
const BaseModel_ets_1 = __importDefault(__webpack_require__(/*! ../model/BaseModel.ets */ "../../../../../../../DEMO/p2pConn/entry/src/main/ets/MainAbility/model/BaseModel.ets"));
const LogUtil_ets_1 = __importDefault(__webpack_require__(/*! ./LogUtil.ets */ "../../../../../../../DEMO/p2pConn/entry/src/main/ets/MainAbility/common/LogUtil.ets"));
var Storage = isSystemplugin('data.storage', 'ohos') ? globalThis.ohosplugin.data.storage : isSystemplugin('data.storage', 'system') ? globalThis.systemplugin.data.storage : globalThis.requireNapi('data.storage');
const PREFERENCES_PATH = '/data/accounts/account_0/appdata/com.example.demo.p2pconn/sharedPreference/WifiDirectPreference';
let mPreferences = null;
class StorageUtil extends BaseModel_ets_1.default {
    constructor() {
        super();
        mPreferences = Storage.getStorageSync(PREFERENCES_PATH);
    }
    isPreferencesExist(key) {
        if (mPreferences && mPreferences.hasSync(key)) {
            return true;
        }
        return false;
    }
    /**
     * 获取列表数据
     */
    getListData(key) {
        let data = mPreferences.getSync(key, '');
        LogUtil_ets_1.default.info('getListData  key == ' + key + ' data  ==  ' + data);
        if (data == '') {
            return [];
        }
        else {
            return JSON.parse(data);
        }
    }
    /**
    * 保存列表数据
    */
    putListData(key, value) {
        LogUtil_ets_1.default.info('putListData  key == ' + key + '  value  ==  ' + JSON.stringify(value));
        mPreferences.put(key, JSON.stringify(value), () => {
            mPreferences.flush();
        });
    }
    /**
     * 获取数据并指定默认
     */
    getDataToDef(key, def) {
        let data;
        if (mPreferences && mPreferences.hasSync(key)) {
            data = mPreferences.getSync(key, def);
        }
        else {
            data = def;
        }
        LogUtil_ets_1.default.info('getDataToDef  key == ' + key + '  data  ==  ' + data);
        return data;
    }
    /**
    * 同步保存原始数据
    */
    putObjData(key, value) {
        LogUtil_ets_1.default.info('putObjData  key == ' + key + '  value  ==  ' + value);
        mPreferences.putSync(key, value);
        mPreferences.flush();
    }
    getDataToJson(key, def) {
        let data;
        if (mPreferences && mPreferences.hasSync(key)) {
            data = mPreferences.getSync(key, def);
        }
        else {
            data = def;
        }
        LogUtil_ets_1.default.info('getDataToJson  key == ' + key + '  data  ==  ' + data);
        return JSON.parse(data);
    }
    /**
     * 删除指定键数据
     */
    delObjData(key) {
        LogUtil_ets_1.default.info('delObjData  key == ' + key);
        mPreferences.delete(key);
    }
}
exports.StorageUtil = StorageUtil;
let mStorageUtil = new StorageUtil();
exports["default"] = mStorageUtil;


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

/***/ "../../../../../../../DEMO/p2pConn/entry/src/main/ets/MainAbility/model/wifiModeImpl/WifiEntity.ets":
/*!**********************************************************************************************************!*\
  !*** ../../../../../../../DEMO/p2pConn/entry/src/main/ets/MainAbility/model/wifiModeImpl/WifiEntity.ets ***!
  \**********************************************************************************************************/
/***/ ((__unused_webpack_module, exports) => {


Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.WifiEntity = void 0;
class WifiEntity {
    constructor(index, deviceName, macAddress, status) {
        this.index = index;
        this.deviceName = deviceName;
        this.macAddress = macAddress;
        //    this.priMaryDeviceType = priMaryDeviceType
        //    this.secondaryDeviceType = secondaryDeviceType
        this.status = status;
    }
}
exports.WifiEntity = WifiEntity;


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


/***/ }),

/***/ "../../../../../../../DEMO/p2pConn/entry/src/main/ets/MainAbility/pages/component/dialog/customPromptDialog.ets":
/*!**********************************************************************************************************************!*\
  !*** ../../../../../../../DEMO/p2pConn/entry/src/main/ets/MainAbility/pages/component/dialog/customPromptDialog.ets ***!
  \**********************************************************************************************************************/
/***/ ((__unused_webpack_module, exports) => {


Object.defineProperty(exports, "__esModule", ({ value: true }));
/**
 * 自定义提示弹窗
 */
class CustomPromptDialog extends View {
    constructor(compilerAssignedUniqueChildId, parent, params) {
        super(compilerAssignedUniqueChildId, parent);
        this.title = '提示';
        this.cancelVal = '取消';
        this.confirmVal = '确定';
        this.__contentVal = new ObservedPropertySimple('', this, "contentVal");
        this.controller = undefined;
        this.eventAction = undefined;
        this.updateWithValueParams(params);
    }
    updateWithValueParams(params) {
        if (params.title !== undefined) {
            this.title = params.title;
        }
        if (params.cancelVal !== undefined) {
            this.cancelVal = params.cancelVal;
        }
        if (params.confirmVal !== undefined) {
            this.confirmVal = params.confirmVal;
        }
        if (params.contentVal !== undefined) {
            this.contentVal = params.contentVal;
        }
        if (params.controller !== undefined) {
            this.controller = params.controller;
        }
        if (params.eventAction !== undefined) {
            this.eventAction = params.eventAction;
        }
    }
    aboutToBeDeleted() {
        this.__contentVal.aboutToBeDeleted();
        SubscriberManager.Get().delete(this.id());
    }
    get contentVal() {
        return this.__contentVal.get();
    }
    set contentVal(newValue) {
        this.__contentVal.set(newValue);
    }
    setController(ctr) {
        this.controller = ctr;
    }
    render() {
        Column.create();
        Column.debugLine("pages/component/dialog/customPromptDialog.ets(14:5)");
        Column.width('100%');
        Column.backgroundColor(Color.White);
        Column.borderRadius(15);
        Text.create(this.title);
        Text.debugLine("pages/component/dialog/customPromptDialog.ets(15:7)");
        Text.width('95%');
        Text.fontSize(20);
        Text.fontColor(Color.Black);
        Text.fontWeight(FontWeight.Bold);
        Text.margin({
            top: 20,
            bottom: 15,
            left: 20
        });
        Text.pop();
        Scroll.create();
        Scroll.debugLine("pages/component/dialog/customPromptDialog.ets(25:7)");
        Scroll.width('95%');
        Scroll.height(120);
        Scroll.scrollable(ScrollDirection.Vertical);
        Flex.create();
        Flex.debugLine("pages/component/dialog/customPromptDialog.ets(26:9)");
        Flex.margin({
            left: 20,
            top: 10,
            right: 20,
            bottom: 10
        });
        Text.create(this.contentVal);
        Text.debugLine("pages/component/dialog/customPromptDialog.ets(27:11)");
        Text.fontSize(18);
        Text.fontColor(Color.Black);
        Text.lineHeight(33);
        Text.pop();
        Flex.pop();
        Scroll.pop();
        Row.create();
        Row.debugLine("pages/component/dialog/customPromptDialog.ets(43:7)");
        Button.createWithLabel(this.cancelVal, { type: ButtonType.Capsule, stateEffect: true });
        Button.debugLine("pages/component/dialog/customPromptDialog.ets(44:9)");
        Button.padding({
            top: 10,
            bottom: 10
        });
        Button.stateEffect(false);
        Button.fontSize(17);
        Button.fontColor(Color.Black);
        Button.backgroundColor(Color.White);
        Button.layoutWeight(1);
        Button.onClick(() => {
            this.controller.close();
        });
        Button.pop();
        Divider.create();
        Divider.debugLine("pages/component/dialog/customPromptDialog.ets(57:9)");
        Divider.width(1);
        Divider.height(30);
        Divider.color('#bcbcbc');
        Divider.vertical(true);
        Button.createWithLabel(this.confirmVal, { type: ButtonType.Capsule, stateEffect: true });
        Button.debugLine("pages/component/dialog/customPromptDialog.ets(62:9)");
        Button.padding({
            top: 10,
            bottom: 10
        });
        Button.stateEffect(false);
        Button.fontSize(17);
        Button.fontColor(Color.Black);
        Button.backgroundColor(Color.White);
        Button.layoutWeight(1);
        Button.onClick(() => {
            this.controller.close();
            this.eventAction();
        });
        Button.pop();
        Row.pop();
        Column.pop();
    }
}
exports["default"] = CustomPromptDialog;


/***/ }),

/***/ "../../../../../../../DEMO/p2pConn/entry/src/main/ets/MainAbility/pages/component/dialog/inputComponent.ets":
/*!******************************************************************************************************************!*\
  !*** ../../../../../../../DEMO/p2pConn/entry/src/main/ets/MainAbility/pages/component/dialog/inputComponent.ets ***!
  \******************************************************************************************************************/
/***/ ((__unused_webpack_module, exports) => {


Object.defineProperty(exports, "__esModule", ({ value: true }));
var prompt = isSystemplugin('prompt', 'system') ? globalThis.systemplugin.prompt : globalThis.requireNapi('prompt');
/**
 * 自定义输入弹窗
 */
class InputComponent extends View {
    constructor(compilerAssignedUniqueChildId, parent, params) {
        super(compilerAssignedUniqueChildId, parent);
        this.title = '提示';
        this.cancelVal = '取消';
        this.confirmVal = '确定';
        this.inputValLength = 15;
        this.__inputHint = new ObservedPropertySimple('', this, "inputHint");
        this.__inputValue = new ObservedPropertySimple('', this, "inputValue");
        this.__inputType = new ObservedPropertySimple(InputType.Password, this, "inputType");
        this.controller = undefined;
        this.eventConnect = undefined;
        this.updateWithValueParams(params);
    }
    updateWithValueParams(params) {
        if (params.title !== undefined) {
            this.title = params.title;
        }
        if (params.cancelVal !== undefined) {
            this.cancelVal = params.cancelVal;
        }
        if (params.confirmVal !== undefined) {
            this.confirmVal = params.confirmVal;
        }
        if (params.inputValLength !== undefined) {
            this.inputValLength = params.inputValLength;
        }
        if (params.inputHint !== undefined) {
            this.inputHint = params.inputHint;
        }
        if (params.inputValue !== undefined) {
            this.inputValue = params.inputValue;
        }
        if (params.inputType !== undefined) {
            this.inputType = params.inputType;
        }
        if (params.controller !== undefined) {
            this.controller = params.controller;
        }
        if (params.eventConnect !== undefined) {
            this.eventConnect = params.eventConnect;
        }
    }
    aboutToBeDeleted() {
        this.__inputHint.aboutToBeDeleted();
        this.__inputValue.aboutToBeDeleted();
        this.__inputType.aboutToBeDeleted();
        SubscriberManager.Get().delete(this.id());
    }
    get inputHint() {
        return this.__inputHint.get();
    }
    set inputHint(newValue) {
        this.__inputHint.set(newValue);
    }
    get inputValue() {
        return this.__inputValue.get();
    }
    set inputValue(newValue) {
        this.__inputValue.set(newValue);
    }
    get inputType() {
        return this.__inputType.get();
    }
    set inputType(newValue) {
        this.__inputType.set(newValue);
    }
    setController(ctr) {
        this.controller = ctr;
    }
    //  checkCharacter(str: string): boolean{
    //    let pattern = new RegExp("[`+-\\~!@#$^&*()=|{}':;',\\[\\].<>《》/?~！@#￥……&*（）——|{}【】‘；：”“'。，、？ ]");
    //    if (pattern.test(str)) {
    //      return true;
    //    }
    //    return false;
    //  }
    render() {
        Column.create();
        Column.debugLine("pages/component/dialog/inputComponent.ets(26:5)");
        Column.backgroundColor(Color.White);
        Column.borderRadius(10);
        Text.create(this.title);
        Text.debugLine("pages/component/dialog/inputComponent.ets(27:7)");
        Text.fontSize(20);
        Text.fontWeight(FontWeight.Bold);
        Text.fontColor(Color.Black);
        Text.margin({
            top: 15,
            bottom: 15,
            left: 20,
            right: 20
        });
        Text.pop();
        TextInput.create({ placeholder: this.inputHint, text: this.inputValue });
        TextInput.debugLine("pages/component/dialog/inputComponent.ets(38:7)");
        TextInput.placeholderColor(Color.Black);
        TextInput.placeholderFont({ size: 20 });
        TextInput.height(50);
        TextInput.borderRadius(6);
        TextInput.type(this.inputType);
        TextInput.margin({
            top: 10,
            left: 15,
            right: 15,
            bottom: 10
        });
        TextInput.padding({ left: 10, right: 10 });
        TextInput.onChange((value) => {
            this.inputValue = value;
        });
        TextInput.height(60);
        //      Divider()
        //        .color('#bcbcbc')
        //        .height(1)
        //        .margin({
        //          left: 15,
        //          right: 15
        //        })
        Row.create();
        Row.debugLine("pages/component/dialog/inputComponent.ets(63:7)");
        Button.createWithLabel(this.cancelVal, { type: ButtonType.Capsule, stateEffect: true });
        Button.debugLine("pages/component/dialog/inputComponent.ets(64:9)");
        Button.fontSize(17);
        Button.fontColor(Color.Black);
        Button.backgroundColor(Color.White);
        Button.layoutWeight(1);
        Button.stateEffect(false);
        Button.padding({
            top: 5,
            bottom: 5
        });
        Button.onClick(() => {
            this.controller.close();
        });
        Button.pop();
        Divider.create();
        Divider.debugLine("pages/component/dialog/inputComponent.ets(77:9)");
        Divider.width(1);
        Divider.height(30);
        Divider.vertical(true);
        Divider.color('#bcbcbc');
        Button.createWithLabel(this.confirmVal, { type: ButtonType.Capsule, stateEffect: true });
        Button.debugLine("pages/component/dialog/inputComponent.ets(82:9)");
        Button.fontSize(17);
        Button.fontColor(Color.Black);
        Button.backgroundColor(Color.White);
        Button.layoutWeight(1);
        Button.stateEffect(false);
        Button.padding({
            top: 5,
            bottom: 5
        });
        Button.onClick(() => {
            if (this.inputValue == '') {
                prompt.showToast({ message: '请输入' + this.title });
            }
            else if (this.inputValue.length > this.inputValLength) {
                prompt.showToast({ message: '输入内容超出限制' });
            }
            else {
                this.controller.close();
                this.eventConnect(this.inputValue);
            }
        });
        Button.pop();
        //      Divider()
        //        .color('#bcbcbc')
        //        .height(1)
        //        .margin({
        //          left: 15,
        //          right: 15
        //        })
        Row.pop();
        Column.pop();
    }
}
exports["default"] = InputComponent;


/***/ }),

/***/ "../../../../../../../DEMO/p2pConn/entry/src/main/ets/MainAbility/pages/index.ets?entry":
/*!**********************************************************************************************!*\
  !*** ../../../../../../../DEMO/p2pConn/entry/src/main/ets/MainAbility/pages/index.ets?entry ***!
  \**********************************************************************************************/
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {


var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", ({ value: true }));
const inputComponent_ets_1 = __importDefault(__webpack_require__(/*! ./component/dialog/inputComponent.ets */ "../../../../../../../DEMO/p2pConn/entry/src/main/ets/MainAbility/pages/component/dialog/inputComponent.ets"));
const customPromptDialog_ets_1 = __importDefault(__webpack_require__(/*! ./component/dialog/customPromptDialog.ets */ "../../../../../../../DEMO/p2pConn/entry/src/main/ets/MainAbility/pages/component/dialog/customPromptDialog.ets"));
const WifiModel_ets_1 = __importDefault(__webpack_require__(/*! ../model/wifiModeImpl/WifiModel.ets */ "../../../../../../../DEMO/p2pConn/entry/src/main/ets/MainAbility/model/wifiModeImpl/WifiModel.ets"));
const LogUtil_ets_1 = __importDefault(__webpack_require__(/*! ../common/LogUtil.ets */ "../../../../../../../DEMO/p2pConn/entry/src/main/ets/MainAbility/common/LogUtil.ets"));
const StorageUtil_ets_1 = __importDefault(__webpack_require__(/*! ../common/StorageUtil.ets */ "../../../../../../../DEMO/p2pConn/entry/src/main/ets/MainAbility/common/StorageUtil.ets"));
const WifiEntity_ets_1 = __webpack_require__(/*! ../model/wifiModeImpl/WifiEntity.ets */ "../../../../../../../DEMO/p2pConn/entry/src/main/ets/MainAbility/model/wifiModeImpl/WifiEntity.ets");
var prompt = isSystemplugin('prompt', 'system') ? globalThis.systemplugin.prompt : globalThis.requireNapi('prompt');
class Index extends View {
    constructor(compilerAssignedUniqueChildId, parent, params) {
        super(compilerAssignedUniqueChildId, parent);
        this.dialogEvent = undefined;
        this.promptEvent = undefined;
        this.isFinding = true //是否正在扫描
        ;
        this.connDeviceName = '' //提示框标题
        ;
        this.connContent = '' //提示框内容
        ;
        this.currentGroupInfo = {} //当前群组信息
        ;
        this.__p2pDeviceList = new ObservedPropertyObject([] //扫描到的P2P信息列表
        , this, "p2pDeviceList");
        this.__deviceName = new ObservedPropertySimple('OHOS' //本设备名称
        , this, "deviceName");
        this.__isDeviceStatus = new ObservedPropertySimple(true //设备状态
        , this, "isDeviceStatus");
        this.__isCreateDelGroup = new ObservedPropertySimple(false //创建/删除 群组 状态
        , this, "isCreateDelGroup");
        this.__btnText = new ObservedPropertySimple('停止' //
        , this, "btnText");
        this.inputController = new CustomDialogController({
            builder: () => {
                let jsDialog = new inputComponent_ets_1.default("2", this, {
                    title: '设备名称',
                    inputHint: '请输入设备名称',
                    inputValue: this.deviceName,
                    inputType: InputType.Normal,
                    eventConnect: (value) => {
                        this.dialogEvent(value);
                    }
                });
                jsDialog.setController(this.
                /*输入弹出窗*/
                inputController);
                View.create(jsDialog);
            },
            autoCancel: false
        }, this);
        this.promptDialogController = new CustomDialogController({
            builder: () => {
                let jsDialog = new customPromptDialog_ets_1.default("3", this, {
                    title: this.connDeviceName,
                    contentVal: this.connContent,
                    eventAction: () => {
                        this.promptEvent();
                    }
                });
                jsDialog.setController(this.
                //提示弹窗
                promptDialogController);
                View.create(jsDialog);
            },
            autoCancel: true
        }, this);
        this.updateWithValueParams(params);
    }
    updateWithValueParams(params) {
        if (params.dialogEvent !== undefined) {
            this.dialogEvent = params.dialogEvent;
        }
        if (params.promptEvent !== undefined) {
            this.promptEvent = params.promptEvent;
        }
        if (params.isFinding !== undefined) {
            this.isFinding = params.isFinding;
        }
        if (params.connDeviceName !== undefined) {
            this.connDeviceName = params.connDeviceName;
        }
        if (params.connContent !== undefined) {
            this.connContent = params.connContent;
        }
        if (params.currentGroupInfo !== undefined) {
            this.currentGroupInfo = params.currentGroupInfo;
        }
        if (params.p2pDeviceList !== undefined) {
            this.p2pDeviceList = params.p2pDeviceList;
        }
        if (params.deviceName !== undefined) {
            this.deviceName = params.deviceName;
        }
        if (params.isDeviceStatus !== undefined) {
            this.isDeviceStatus = params.isDeviceStatus;
        }
        if (params.isCreateDelGroup !== undefined) {
            this.isCreateDelGroup = params.isCreateDelGroup;
        }
        if (params.btnText !== undefined) {
            this.btnText = params.btnText;
        }
        if (params.inputController !== undefined) {
            this.inputController = params.inputController;
        }
        if (params.promptDialogController !== undefined) {
            this.promptDialogController = params.promptDialogController;
        }
    }
    aboutToBeDeleted() {
        this.__p2pDeviceList.aboutToBeDeleted();
        this.__deviceName.aboutToBeDeleted();
        this.__isDeviceStatus.aboutToBeDeleted();
        this.__isCreateDelGroup.aboutToBeDeleted();
        this.__btnText.aboutToBeDeleted();
        SubscriberManager.Get().delete(this.id());
    }
    get p2pDeviceList() {
        return this.__p2pDeviceList.get();
    }
    set p2pDeviceList(newValue) {
        this.__p2pDeviceList.set(newValue);
    }
    get deviceName() {
        return this.__deviceName.get();
    }
    set deviceName(newValue) {
        this.__deviceName.set(newValue);
    }
    get isDeviceStatus() {
        return this.__isDeviceStatus.get();
    }
    set isDeviceStatus(newValue) {
        this.__isDeviceStatus.set(newValue);
    }
    get isCreateDelGroup() {
        return this.__isCreateDelGroup.get();
    }
    set isCreateDelGroup(newValue) {
        this.__isCreateDelGroup.set(newValue);
    }
    get btnText() {
        return this.__btnText.get();
    }
    set btnText(newValue) {
        this.__btnText.set(newValue);
    }
    aboutToAppear() {
        LogUtil_ets_1.default.log('start -----------------   aboutToAppear');
        WifiModel_ets_1.default.setDeviceName('OHOS'); //设置设备名称
        StorageUtil_ets_1.default.putObjData('deviceName', 'OHOS'); //缓存设备名称到本地
        WifiModel_ets_1.default.getListener().on("p2pDevicesChange", this.onDevicesChange.bind(this));
        WifiModel_ets_1.default.getListener().on("p2pStateChange", this.onP2pStateChange.bind(this));
        WifiModel_ets_1.default.getListener().on("p2pConnStateChange", this.onP2pConnStateChange.bind(this));
        WifiModel_ets_1.default.getListener().on("p2pPeerDiscoveryStateChange", this.onP2pPeerDiscoveryStateChange.bind(this));
        WifiModel_ets_1.default.getListener().on("p2pCurrentDeviceChange", this.onP2pCurrentDeviceChange.bind(this));
        WifiModel_ets_1.default.getListener().on("p2pGroupStateChange", this.onP2pGroupStateChange.bind(this));
        WifiModel_ets_1.default.discoverDevices();
        LogUtil_ets_1.default.log('end -----------------   aboutToAppear');
    }
    render() {
        Column.create();
        Column.debugLine("pages/index.ets(64:5)");
        Column.backgroundColor('#F7FCFF');
        Column.width('100%');
        Column.height('100%');
        Column.alignItems(HorizontalAlign.Start);
        Text.create('WLAN直连');
        Text.debugLine("pages/index.ets(65:7)");
        Text.fontSize(24);
        Text.fontWeight(FontWeight.Bold);
        Text.margin({
            top: 15,
            left: 20,
            bottom: 15
        });
        Text.pop();
        Row.create();
        Row.debugLine("pages/index.ets(73:7)");
        Row.backgroundColor(Color.White);
        Row.borderRadius(6);
        Row.padding({
            left: 10,
            right: 10,
        });
        Row.margin({
            top: 10,
            left: 10,
            right: 10
        });
        Text.create('设备状态');
        Text.debugLine("pages/index.ets(74:9)");
        Text.fontSize(20);
        Text.pop();
        Text.create('');
        Text.debugLine("pages/index.ets(75:9)");
        Text.layoutWeight(1);
        Text.pop();
        Toggle.create({ type: ToggleType.Switch, isOn: this.isDeviceStatus });
        Toggle.debugLine("pages/index.ets(76:9)");
        Toggle.width(40);
        Toggle.height(30);
        Toggle.selectedColor(Color.Blue);
        Toggle.onChange(() => {
            this.isDeviceStatus = !this.isDeviceStatus;
            if (this.isDeviceStatus) {
                WifiModel_ets_1.default.enableP2p();
            }
            else {
                WifiModel_ets_1.default.disableP2p();
                this.p2pDeviceList = [];
            }
        });
        Toggle.pop();
        Row.pop();
        Row.create();
        Row.debugLine("pages/index.ets(101:7)");
        Row.backgroundColor(Color.White);
        Row.borderRadius(6);
        Row.padding({
            left: 10,
            right: 10,
        });
        Row.margin({
            top: 10,
            left: 10,
            right: 10
        });
        Text.create('创建/删除 群组');
        Text.debugLine("pages/index.ets(102:9)");
        Text.fontSize(20);
        Text.pop();
        Text.create('');
        Text.debugLine("pages/index.ets(103:9)");
        Text.layoutWeight(1);
        Text.pop();
        Toggle.create({ type: ToggleType.Switch, isOn: this.isCreateDelGroup });
        Toggle.debugLine("pages/index.ets(104:9)");
        Toggle.width(40);
        Toggle.height(30);
        Toggle.selectedColor(Color.Blue);
        Toggle.onChange(() => {
            this.isCreateDelGroup = !this.isCreateDelGroup;
            if (this.isCreateDelGroup) {
                WifiModel_ets_1.default.createGroup();
            }
            else {
                WifiModel_ets_1.default.removeGroup();
            }
        });
        Toggle.pop();
        Row.pop();
        Row.create();
        Row.debugLine("pages/index.ets(128:7)");
        Row.backgroundColor(Color.White);
        Row.borderRadius(6);
        Row.padding({
            left: 10,
            right: 10,
            top: 10,
            bottom: 10
        });
        Row.margin({
            top: 10,
            bottom: 10,
            left: 10,
            right: 10
        });
        Row.onClick(() => {
            this.getCurrentGroupInfo();
        });
        Text.create('Current Group Info');
        Text.debugLine("pages/index.ets(129:9)");
        Text.fontSize(20);
        Text.pop();
        Text.create('');
        Text.debugLine("pages/index.ets(130:9)");
        Text.layoutWeight(1);
        Text.pop();
        Image.create('res/image/ic_right.svg');
        Image.debugLine("pages/index.ets(131:9)");
        Image.width(28);
        Image.height(28);
        Image.objectFit(ImageFit.Contain);
        Row.pop();
        Row.create();
        Row.debugLine("pages/index.ets(151:7)");
        Row.backgroundColor(Color.White);
        Row.borderRadius(6);
        Row.padding({
            left: 10,
            right: 10,
            top: 10,
            bottom: 10
        });
        Row.margin({
            left: 10,
            right: 10
        });
        Row.onClick(() => {
            this.deletePersistGroup();
        });
        Text.create('Delete Persist Group');
        Text.debugLine("pages/index.ets(152:9)");
        Text.fontSize(20);
        Text.pop();
        Text.create('');
        Text.debugLine("pages/index.ets(153:9)");
        Text.layoutWeight(1);
        Text.pop();
        Image.create('res/image/ic_right.svg');
        Image.debugLine("pages/index.ets(154:9)");
        Image.width(28);
        Image.height(28);
        Image.objectFit(ImageFit.Contain);
        Row.pop();
        Text.create('我的设备');
        Text.debugLine("pages/index.ets(172:7)");
        Text.fontSize(18);
        Text.fontColor(Color.Gray);
        Text.margin({
            left: 20,
            top: 10,
            bottom: 10
        });
        Text.pop();
        Row.create();
        Row.debugLine("pages/index.ets(180:7)");
        Row.backgroundColor(Color.White);
        Row.borderRadius(6);
        Row.padding({
            left: 10,
            right: 10,
            top: 10,
            bottom: 10
        });
        Row.margin({
            left: 10,
            right: 10
        });
        Row.onClick(() => {
            this.dialogEvent = (value) => {
                if (WifiModel_ets_1.default.setDeviceName(value)) {
                    this.deviceName = value;
                    StorageUtil_ets_1.default.putObjData('deviceName', this.deviceName);
                }
            };
            this.inputController.open();
        });
        Text.create('设备名称');
        Text.debugLine("pages/index.ets(181:9)");
        Text.fontSize(20);
        Text.pop();
        Text.create(this.deviceName);
        Text.debugLine("pages/index.ets(182:9)");
        Text.fontColor('#999');
        Text.fontSize(18);
        Text.layoutWeight(1);
        Text.maxLines(1);
        Text.textAlign(TextAlign.End);
        Text.margin({
            left: 30,
            right: 5
        });
        Text.pop();
        Image.create('res/image/ic_right.svg');
        Image.debugLine("pages/index.ets(192:9)");
        Image.width(28);
        Image.height(28);
        Image.objectFit(ImageFit.Contain);
        Row.pop();
        Row.create();
        Row.debugLine("pages/index.ets(216:7)");
        Row.margin({
            top: 10,
            right: 20,
            left: 20,
            bottom: 10
        });
        Text.create('可用设备');
        Text.debugLine("pages/index.ets(217:9)");
        Text.backgroundColor('#F7FCFF');
        Text.fontSize(18);
        Text.fontColor(Color.Gray);
        Text.padding({
            top: 5,
            bottom: 5
        });
        Text.pop();
        Text.create('');
        Text.debugLine("pages/index.ets(225:9)");
        Text.layoutWeight(1);
        Text.pop();
        Image.create({ "id": 16777218, "type": 20000, params: [] });
        Image.debugLine("pages/index.ets(226:9)");
        Image.width(24);
        Image.height(24);
        Image.objectFit(ImageFit.Contain);
        Image.visibility(this.isFinding ? Visibility.Visible : Visibility.None);
        Row.pop();
        List.create({ space: 15 });
        List.debugLine("pages/index.ets(239:7)");
        List.layoutWeight(1);
        ForEach.create("5", this, ObservedObject.GetRawObject(this.p2pDeviceList), (item) => {
            ListItem.create();
            ListItem.debugLine("pages/index.ets(241:11)");
            ListItem.onClick(() => {
                this.connectP2pDevice(item);
            });
            let earlierCreatedChild_4 = this.findChildById("4");
            if (earlierCreatedChild_4 == undefined) {
                View.create(new CustomItem("4", this, {
                    deviceName: item.deviceName,
                    macAddress: item.macAddress,
                    status: item.status
                }));
            }
            else {
                earlierCreatedChild_4.updateWithValueParams({
                    deviceName: item.deviceName,
                    macAddress: item.macAddress,
                    status: item.status
                });
                View.create(earlierCreatedChild_4);
            }
            ListItem.pop();
        });
        ForEach.pop();
        List.pop();
        Button.createWithLabel(this.btnText);
        Button.debugLine("pages/index.ets(253:7)");
        Button.fontSize(20);
        Button.width(200);
        Button.alignSelf(ItemAlign.Center);
        Button.margin({
            top: 20,
            bottom: 20
        });
        Button.onClick(() => {
            if (this.isFinding) {
                this.btnText = '扫描';
                this.isFinding = false;
                WifiModel_ets_1.default.stopDiscoverDevices();
            }
            else {
                this.btnText = '停止';
                this.isFinding = true;
                WifiModel_ets_1.default.discoverDevices();
            }
        });
        Button.pop();
        Column.pop();
    }
    connectP2pDevice(item) {
        LogUtil_ets_1.default.log("wifi direct: connectP2pDevice  " + item.deviceName + "   " + item.status);
        if (item.status == 0) {
            this.connDeviceName = item.deviceName;
            WifiModel_ets_1.default.getLinkInfo((result) => {
                this.connContent = result;
            });
            this.promptEvent = () => {
            };
            if (this.connContent != null) {
                this.promptDialogController.open();
            }
        }
        else if (item.status == 1) {
            this.connDeviceName = '提示';
            this.connContent = '确定取消当前连接?';
            this.promptEvent = () => {
                prompt.showToast({ message: WifiModel_ets_1.default.cancelConnect() ? '取消成功' : '取消失败' });
            };
            this.promptDialogController.open();
        }
        else if (item.status == 4) {
            prompt.showToast({ message: '当前不可用' });
        }
        else if (item.status == 3) {
            let config = {
                'macAddress': item.macAddress,
                'groupOwnerIntent': 7
            };
            WifiModel_ets_1.default.connectP2pDevices(config);
        }
    }
    //获取p2p设备列表
    onDevicesChange() {
        LogUtil_ets_1.default.log("onDevicesChange");
        this.p2pDeviceList = [];
        WifiModel_ets_1.default.getP2pDevicesCallBack().then((list) => {
            LogUtil_ets_1.default.log('-----------------------------  ' + JSON.stringify(list));
            for (let i = 0; i < JSON.parse(JSON.stringify(list))
                .length; i++) {
                if (this.checkDouble(list[i].macAddress)) {
                    continue;
                }
                this.p2pDeviceList.push(new WifiEntity_ets_1.WifiEntity(i, list[i].ssid, list[i].macAddress, list[i].status));
            }
            LogUtil_ets_1.default.log('this.p2pDeviceList   ...   ' + JSON.stringify(this.p2pDeviceList));
        });
    }
    checkDouble(macAddress) {
        for (var index = 0; index < this.p2pDeviceList.length; index++) {
            const element = this.p2pDeviceList[index];
            if (element.macAddress == macAddress) {
                return true;
            }
        }
        return false;
    }
    onP2pStateChange(code) {
        LogUtil_ets_1.default.log("onP2pStateChange " + code);
        if (code === 3) {
            LogUtil_ets_1.default.log("code is 3, call discoverDevices");
            this.isDeviceStatus = true;
            WifiModel_ets_1.default.discoverDevices();
        }
        else {
            this.isDeviceStatus = false;
            WifiModel_ets_1.default.stopDiscoverDevices();
        }
    }
    onP2pConnStateChange(code) {
        LogUtil_ets_1.default.log("onP2pConnectedStateChange " + code);
    }
    onP2pPeerDiscoveryStateChange(code) {
        LogUtil_ets_1.default.log("onP2pPeerDiscoveryStateChange " + JSON.stringify(code));
    }
    onP2pCurrentDeviceChange(code) {
        LogUtil_ets_1.default.log("onP2pCurrentDeviceChange " + JSON.stringify(code));
    }
    onP2pGroupStateChange(code) {
        LogUtil_ets_1.default.log("onP2pGroupStateChange " + JSON.stringify(code));
    }
    getCurrentGroupInfo() {
        WifiModel_ets_1.default.getCurrentGroupInfo((info) => {
            LogUtil_ets_1.default.log("current group info" + info);
            this.currentGroupInfo = {
                "isP2pGroupOwner": info.isP2pGroupOwner,
                "passphrase": info.passphrase,
                "interface": info.interface,
                "groupName": info.groupName,
                "networkId": info.networkId,
                "frequency": info.frequency,
                "isP2pPersistent": info.isP2pPersistent,
                "goIpAddress": info.goIpAddress
            };
            this.connDeviceName = '群组信息';
            this.connContent = JSON.stringify(this.currentGroupInfo);
            this.promptEvent = () => {
            };
            this.promptDialogController.open();
        });
    }
    deletePersistGroup() {
        this.connDeviceName = '群组信息';
        this.connContent = '确定删除群组?';
        this.promptEvent = () => {
            LogUtil_ets_1.default.log("deletePersistGroup" + JSON.stringify(this.currentGroupInfo));
            if (this.currentGroupInfo && this.currentGroupInfo.isP2pPersistent) {
                LogUtil_ets_1.default.log("networkid is " + this.currentGroupInfo.networkId);
                prompt.showToast({
                    message: WifiModel_ets_1.default.deletePersistentGroup(this.currentGroupInfo.networkId) ? '成功' : '失败'
                });
            }
        };
        this.promptDialogController.open();
    }
    aboutToDisappear() {
        WifiModel_ets_1.default.stopDiscoverDevices();
    }
}
class CustomItem extends View {
    constructor(compilerAssignedUniqueChildId, parent, params) {
        super(compilerAssignedUniqueChildId, parent);
        this.statusStr = ["已连接", "已邀请", "失败", "可用", "不可用"];
        this.__deviceName = new SynchedPropertySimpleOneWay(params.deviceName, this, "deviceName");
        this.__macAddress = new SynchedPropertySimpleOneWay(params.macAddress, this, "macAddress");
        this.__status = new SynchedPropertySimpleOneWay(params.status, this, "status");
        this.updateWithValueParams(params);
    }
    updateWithValueParams(params) {
        if (params.statusStr !== undefined) {
            this.statusStr = params.statusStr;
        }
        this.deviceName = params.deviceName;
        this.macAddress = params.macAddress;
        this.status = params.status;
    }
    aboutToBeDeleted() {
        this.__deviceName.aboutToBeDeleted();
        this.__macAddress.aboutToBeDeleted();
        this.__status.aboutToBeDeleted();
        SubscriberManager.Get().delete(this.id());
    }
    get deviceName() {
        return this.__deviceName.get();
    }
    set deviceName(newValue) {
        this.__deviceName.set(newValue);
    }
    get macAddress() {
        return this.__macAddress.get();
    }
    set macAddress(newValue) {
        this.__macAddress.set(newValue);
    }
    get status() {
        return this.__status.get();
    }
    set status(newValue) {
        this.__status.set(newValue);
    }
    render() {
        Column.create();
        Column.debugLine("pages/index.ets(412:5)");
        Column.margin({
            right: 20,
            left: 20,
        });
        Row.create();
        Row.debugLine("pages/index.ets(413:7)");
        Row.width('100%');
        Row.height(100);
        Row.borderRadius(10);
        Row.alignItems(VerticalAlign.Center);
        Row.backgroundColor('#D2E9FF');
        Row.padding({
            left: 10,
            right: 10
        });
        Image.create('res/image/ic_phone.svg');
        Image.debugLine("pages/index.ets(414:9)");
        Image.width(48);
        Image.height(48);
        Image.objectFit(ImageFit.Contain);
        Image.margin({
            top: 10,
            bottom: 10,
            right: 10
        });
        Column.create();
        Column.debugLine("pages/index.ets(422:9)");
        Column.alignItems(HorizontalAlign.Start);
        Column.layoutWeight(1);
        Text.create(this.deviceName);
        Text.debugLine("pages/index.ets(423:11)");
        Text.fontSize(20);
        Text.maxLines(1);
        Text.fontWeight(FontWeight.Bold);
        Text.pop();
        Text.create(this.macAddress);
        Text.debugLine("pages/index.ets(424:11)");
        Text.fontSize(18);
        Text.maxLines(1);
        Text.pop();
        Text.create(this.statusStr[this.status]);
        Text.debugLine("pages/index.ets(425:11)");
        Text.fontSize(16);
        Text.pop();
        Column.pop();
        Image.create('res/image/ic_right.svg');
        Image.debugLine("pages/index.ets(432:9)");
        Image.width(28);
        Image.height(28);
        Image.objectFit(ImageFit.Contain);
        Row.pop();
        Column.pop();
    }
}
loadDocument(new Index("1", undefined, {}));


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
/******/ 	var __webpack_exports__ = __webpack_require__("../../../../../../../DEMO/p2pConn/entry/src/main/ets/MainAbility/pages/index.ets?entry");
/******/ 	
/******/ })()
;