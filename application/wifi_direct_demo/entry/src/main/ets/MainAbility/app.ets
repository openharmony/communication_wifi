import logUtil from './common/LogUtil.ets'
import wifiModel from './model/wifiModeImpl/WifiModel.ets'
export default {
  onCreate() {
    logUtil.info('Application onCreate')
    wifiModel.enableP2p()
  },
  onDestroy() {
    logUtil.info('Application onDestroy')
  },
}