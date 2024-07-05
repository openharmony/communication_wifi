import { common, Want } from '@kit.AbilityKit';
import { rpc } from '@kit.IPCKit';
import { promptAction } from '@kit.ArkUI';
import { hilog } from '@kit.PerformanceAnalysisKit';
// 客户端需要将服务端对外提供的idl_service_ext_proxy.ts导入到本地工程中
import IdlServiceExtProxy from '../IdlServiceExt/idl_service_ext_proxy';

const TAG: string = '[Page_ServiceExtensionAbility]';
const DOMAIN_NUMBER: number = 0xFF00;

let connectionId: number;
let want: Want = {
  deviceId: '',
  bundleName: 'com.samples.stagemodelabilitydevelop',
  abilityName: 'ServiceExtAbility'
};

let options: common.ConnectOptions = {
  onConnect(elementName, remote: rpc.IRemoteObject): void {
    hilog.info(DOMAIN_NUMBER, TAG, 'onConnect callback');
    if (remote === null) {
      hilog.info(DOMAIN_NUMBER, TAG, `onConnect remote is null`);
      return;
    }
    let serviceExtProxy: IdlServiceExtProxy = new IdlServiceExtProxy(remote);
    // 通过接口调用的方式进行通信，屏蔽了RPC通信的细节，简洁明了
    serviceExtProxy.processData(1, (errorCode: number, retVal: number) => {
      hilog.info(DOMAIN_NUMBER, TAG, `processData, errorCode: ${errorCode}, retVal: ${retVal}`);
    });
    serviceExtProxy.insertDataToMap('theKey', 1, (errorCode: number) => {
      hilog.info(DOMAIN_NUMBER, TAG, `insertDataToMap, errorCode: ${errorCode}`);
    })
  },
  onDisconnect(elementName): void {
    hilog.info(DOMAIN_NUMBER, TAG, 'onDisconnect callback');
  },
  onFailed(code: number): void {
    hilog.info(DOMAIN_NUMBER, TAG, 'onFailed callback', JSON.stringify(code));
  }
};
@Entry
@Component
struct Page_ServiceExtensionAbility {
  build() {
    Column() {
      //...
      List({ initialIndex: 0 }) {
        ListItem() {
          Row() {
            //...
          }
          .onClick(() => {
            let context: common.UIAbilityContext = getContext(this) as common.UIAbilityContext; // UIAbilityContext
            // 建立连接后返回的Id需要保存下来，在解绑服务时需要作为参数传入
            connectionId = context.connectServiceExtensionAbility(want, options);
            // 成功连接后台服务
            promptAction.showToast({
              message: $r('app.string.SuccessfullyConnectBackendService')
            });
            // connectionId = context.connectAbility(want, options);
            hilog.info(DOMAIN_NUMBER, TAG, `connectionId is : ${connectionId}`);
          })
        }
        //...
      }
      //...
    }
    //...
  }
}