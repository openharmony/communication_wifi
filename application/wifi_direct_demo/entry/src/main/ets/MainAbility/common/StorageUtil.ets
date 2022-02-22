import BaseModel from '../model/BaseModel.ets';
import LogUtil from './LogUtil.ets';
import Storage from '@ohos.data.storage';

const PREFERENCES_PATH = '/data/accounts/account_0/appdata/com.ohos.wifidirectdemo/sharedPreference/WifiDirectPreference';

let mPreferences = null;
export class StorageUtil extends BaseModel {
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
     * 获取数据并指定默认
     */
    getDataToDef(key, def) {
        let data;
        if (mPreferences && mPreferences.hasSync(key)) {
            data = mPreferences.getSync(key, def);
        } else {
            data = def;
        }
        LogUtil.info('getDataToDef  key == ' + key + '  data  ==  ' + data);
        return data;
    }
    /**
    * 同步保存原始数据
    */
    putObjData(key, value) {
        LogUtil.info('putObjData  key == ' + key + '  value  ==  ' + value);
        mPreferences.putSync(key, value);
        mPreferences.flush();
    }
    /**
     * 删除指定键数据
     */
    delObjData(key) {
        LogUtil.info('delObjData  key == ' + key);
        mPreferences.delete(key);
    }
}

let mStorageUtil = new StorageUtil();

export default mStorageUtil as StorageUtil;
