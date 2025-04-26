import { Want, common } from '@kit.AbilityKit'
import { connection } from '@kit.NetworkKit'
import { BusinessError } from '@kit.BasicServicesKit'
import { hilog } from '@kit.PerformanceAnalysisKit'
import { url } from '@kit.ArkTS'

const DOMAIN = 0x01560
const TAG = 'Utils';

let url_: string = '';
let netId_: number = -1;
let shouldShowBrowseItem_: boolean = true;

export function setShouldShowBrowseItem(want: Want): void {
  if (want.parameters) {
    shouldShowBrowseItem_ = want.parameters?.shouldShowBrowseItem as boolean;
    hilog.info(DOMAIN, TAG, '%{public}s', 'Succeeded set shouldShowBrowseItem:' + shouldShowBrowseItem_);
  } else {
    hilog.error(DOMAIN, TAG, '%{public}s', 'Failed set shouldShowBrowseItem');
  }
}

export function shouldShowBrowseItem(): boolean {
  return shouldShowBrowseItem_;
}

function validateURL(urlString: string): boolean {
  try {
    const urlObject = url.URL.parseURL(urlString);
    if (urlObject && urlObject.hostname) {
      return true;
    }
  } catch (error) {
    hilog.error(DOMAIN, TAG, '%{public}s', 'Invalid URL:' + error);
  }
  return false;
}

export function setUrl(want: Want): void {
  if (want.parameters && want.parameters.url && validateURL(want.parameters.url as string)) {
    url_ = want.parameters.url as string;
    hilog.info(DOMAIN, TAG, '%{public}s', 'Succeeded set url:' + url_);
  } else {
    hilog.error(DOMAIN, TAG, '%{public}s', 'Failed set url:' + url_);
  }
}

export function getUrl(): string {
  hilog.info(DOMAIN, TAG, '%{public}s', 'get url:' + url_);
  return url_;
}

function validateNetId(netId: number): boolean {
  if (netId >= 100) {
    return true;
  }
  hilog.error(DOMAIN, TAG, '%{public}s', 'Invalid net id:' + netId);
  return false;
}

export function setNetId(want: Want): void {
  if (want.parameters && want.parameters.netId && validateNetId(want.parameters.netId as number)) {
    netId_ = want.parameters.netId as number;
    hilog.info(DOMAIN, TAG, '%{public}s', 'Succeeded set net id:' + netId_);
  } else {
    hilog.error(DOMAIN, TAG, '%{public}s', 'Failed set net id:' + netId_);
  }
}

export async function bindToNetById(context: common.UIAbilityContext) {
  await connection.getAllNets((error: BusinessError, netHandleArray: connection.NetHandle[]) => {
    if (error) {
      hilog.error(DOMAIN, TAG, '%{public}s', `Failed to get all nets. Code:${error.code}, message:${error.message}`);
      return;
    }
    hilog.info(DOMAIN, TAG, '%{public}s', 'Succeeded get all nets.' + JSON.stringify(netHandleArray));
    const targetNetHandle = netHandleArray.find((netHandle) => netHandle.netId === netId_);
    if (targetNetHandle) {
      connection.setAppNet(targetNetHandle)
        .then(() => {
          hilog.info(DOMAIN, TAG, '%{public}s', 'Succeeded bind net. netId:' + netId_);
        })
        .catch((error: BusinessError) => {
          hilog.error(DOMAIN, TAG, '%{public}s', `Failed bind net. Code:${error.code}, message:${error.message},
            netId:` + netId_);
        })
    } else {
      hilog.error(DOMAIN, TAG, '%{public}s', 'Not find matched NetHandle.');
      exitApp(context);
    }
  })
}

export function exitApp(context: common.UIAbilityContext): void {
  try {
    context.terminateSelf()
      .then(() => {
        hilog.info(DOMAIN, TAG, '%{public}s', 'exit app success.')
      })
      .catch((err: BusinessError) => {
        hilog.error(DOMAIN, TAG, '%{public}s', `exit app fail.Code:${err.code}, message:${err.message}`)
      })
  } catch (error) {
    hilog.error(DOMAIN, TAG, '%{public}s', 'exit app abnormal.' + (error as BusinessError).message)
  }
}

export function handleNetworkChange(data: connection.NetHandle, context: common.UIAbilityContext): void {
  if (data.netId === netId_) {
    exitApp(context);
  }
}

export function extractDomain(urlString: string): string {
  try {
    const urlObject = url.URL.parseURL(urlString);
    return urlObject.hostname;
  } catch (error) {
    hilog.error(DOMAIN, TAG, '%{public}s', 'Invalid URL:' + error)
  }
  return 'Invalid URL';
}

export enum UserAgentSet {
  harmonyUA = '',
  mobileUA = 'Mozilla/5.0 (iPhone; CPU iPhone OS 16_4_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) ' +
    'Version/16.4 Mobile/15E148 Safari/604.1',
  desktopUA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) ' +
    'Chrome/114.0.0.0 Safari/537.36'
}