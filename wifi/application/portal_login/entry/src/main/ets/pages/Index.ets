/**
 * Copyright (c) 2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
 
import { webview } from '@kit.ArkWeb';
import { hilog } from '@kit.PerformanceAnalysisKit';
import { i18n, resourceManager  } from '@kit.LocalizationKit';
import { common, OpenLinkOptions } from '@kit.AbilityKit';
import { BusinessError } from '@kit.BasicServicesKit';
import { SymbolGlyphModifier, window } from '@kit.ArkUI';
import {
  getUrl, bindToNetById, extractDomain, handleNetworkChange, exitApp, shouldShowBrowseItem, UserAgentSet,
  validateURL, getIsInOOBE, getHmosUAComplexRegex, HarmonyUserAgentSet, StringNumberPair, getRetryList, getDefaultUrl
} from '../common/utils';
import {
  updateFinalUrl, updateOnHttpErrorReceive, updateOnErrorReceive, updateOnSslErrorEvent, updateAboutToDisappear,
  safeAnonymize
} from '../common/chr';
import { connection } from '@kit.NetworkKit';
import { emitter } from '@kit.BasicServicesKit';

const DOMAIN = 0x01560;
const TAG = 'Pages';
const RETRY_CODE = 999;
const MAX_RETRY = 3;

@Styles function pressedStyles() {
  .backgroundColor($r('sys.color.ohos_id_color_click_effect'))
  .borderRadius($r('sys.float.ohos_id_corner_radius_button'))
}

@Styles function normalStyles() {
  .backgroundColor($r('sys.color.ohos_id_color_button_normal'))
  .borderRadius($r('sys.float.ohos_id_corner_radius_button'))
}

@Extend(SymbolGlyph) function iconStyles() {
  .fontSize('24vp')
  .fontWeight(FontWeight.Regular)
  .fontColor([$r('sys.color.icon_primary')])
}

@Extend(Row) function buttonStyles() {
  .width('40vp')
  .height('40vp')
  .flexShrink(0)
  .layoutWeight(0)
  .justifyContent(FlexAlign.Center)
  .alignItems(VerticalAlign.Center)
  .responseRegion({ x: 0, y: 0, width: '48vp', height: '56vp' })
  .stateStyles({ pressed: pressedStyles, normal:normalStyles })
}

@Extend(Text) function textStyles() {
  .fontColor($r('sys.color.font_primary'))
  .fontSize($r('sys.float.Subtitle_M'))
  .fontWeight(FontWeight.Medium)
}

enum ThreatType {
  UNKNOWN = -1,
  THREAT_ILLEGAL = 0,
  THREAT_FRAUD = 1,
  THREAT_RISK = 2,
  THREAT_WARNING = 3,
}

class OnSafeBrowsingCheckResultCallback {
  threatType: ThreatType = ThreatType.UNKNOWN;
}

@Entry
@Component
struct Index {
  private webviewController: webview.WebviewController = new webview.WebviewController();
  private context = getContext(this) as common.UIAbilityContext;
  @State private webUrl: string = getUrl();
  private defaultUrl: string = getDefaultUrl();
  private harmonyUA: string = UserAgentSet.harmonyUA;
  private mobileUA: string = UserAgentSet.mobileUA;
  private desktopUA:string = UserAgentSet.desktopUA;
  @State private selectedUA: string = this.harmonyUA; // default use harmony UA
  @State private isMenuVisible: boolean = false;
  @State private isSelectUASheetVisible: boolean = false;
  @State private adaptPadding: number = 16;
  @State private loadProgress: number = 0;
  private sheetItemHeight = 50;
  private contextMenuWidth = 224;
  private netConnect: connection.NetConnection = connection.createNetConnection();
  private isInOOBE: boolean = getIsInOOBE();
  @StorageProp('topRectHeight') topRectHeight: number = 0;
  private isLoaded: boolean = false;
  private isNetBind: boolean = false;
  @State timerCount: number = 10;
  private timerId: number = -1;
  private isPhone: boolean = false;
  @State retryCount: number = 0;
  @State isActionBarVisible: boolean = true;

  @Builder
  ContextMenu() {
    Menu() {
      MenuItem({
        symbolStartIcon: new SymbolGlyphModifier($r('sys.symbol.tv_and_rectangle_portrait')).fontSize('24vp'),
        content: $r('app.string.actions_menu_user_agent')
      })
        .onClick(() => {
          this.isSelectUASheetVisible = true;
        })
      MenuItemGroup() {
       MenuItem({
         symbolStartIcon: new SymbolGlyphModifier($r('sys.symbol.worldclock')).fontSize('24vp'),
         content: $r('app.string.contextmenu_open_in_browser')
       })
         .visibility((shouldShowBrowseItem() && !this.isInOOBE) ? Visibility.Visible : Visibility.None)
         .onClick(() => {
           const link: string = this.webUrl;
           const openLinkOptions: OpenLinkOptions = {
             appLinkingOnly: false,
           }
           try {
             this.context.openLink(link, openLinkOptions)
               .then(() => {
                 hilog.info(DOMAIN, TAG, '%{public}s', 'open link browser success.')
               }).catch((error: BusinessError) => {
               hilog.error(DOMAIN, TAG, '%{public}s', `open link failed. Code:${error.code}, message:${error.message}`);
             })
           } catch (error) {
             hilog.error(DOMAIN, TAG, '%{public}s',
               `Failed to start link. Code:${error.code}, message:${error.message}`);
           }
         })
      }
    }
    .borderRadius($r('sys.float.ohos_id_corner_radius_menu'))
    .width(this.contextMenuWidth)
  }

  @Builder
  UASelectSheet() {
    Column() {
      // Title
      Row() {
        Column() {
          Text($r('app.string.actions_menu_user_agent'))
            .fontColor($r('sys.color.font_secondary'))
            .fontSize($r('sys.float.Subtitle_S'))
            .fontWeight(FontWeight.Medium)
            .margin({left: '12vp'})
        }
        .width('100%')
        .alignItems(HorizontalAlign.Start)
      }
      .alignItems(VerticalAlign.Bottom)

      // UA list
      Column() {
        Row() {
          Text($r('app.string.user_agent_harmony'))
            .textStyles()
          Blank()
          Radio({ value: this.harmonyUA, group: 'group1' })
            .radioStyle({
              uncheckedBorderColor: Color.White
            })
            .checked(this.selectedUA === this.harmonyUA)
            .onChange((isChecked) => {
              if (isChecked) {
                this.selectedUA = this.harmonyUA;
              }
            })
        }
        .height(this.sheetItemHeight)
        .width('100%')
        .onClick(() => {
          this.selectedUA = this.harmonyUA;
        })
        Divider()
        Row() {
          Text($r('app.string.compatibility_mode_of_the_mobile_version'))
            .textStyles()
          Blank()
          Radio({ value: this.mobileUA, group: 'group1' })
            .radioStyle({
              uncheckedBorderColor: Color.White
            })
            .checked(this.selectedUA === this.mobileUA)
            .onChange((isChecked) => {
              if (isChecked) {
                this.selectedUA = this.mobileUA;
              }
            })
        }
        .height(this.sheetItemHeight)
        .width('100%')
        .onClick(() => {
          this.selectedUA = this.mobileUA;
        })
        Divider()
        Row() {
          Text($r('app.string.compatibility_mode_of_the_PC_version'))
            .textStyles()
          Blank()
          Radio({ value: this.desktopUA, group: 'group1' })
            .radioStyle({
              uncheckedBorderColor: Color.White
            })
            .checked(this.selectedUA === this.desktopUA)
            .onChange((isChecked) => {
              if (isChecked) {
                this.selectedUA = this.desktopUA;
              }
            })
        }
        .height(this.sheetItemHeight)
        .width('100%')
        .onClick(() => {
          this.selectedUA = this.desktopUA;
        })
      }
      .backgroundColor($r('sys.color.ohos_id_color_background'))
      .borderRadius($r('sys.float.ohos_id_corner_radius_menu'))
      .padding({ left: '12vp', right: '12vp' })
      .width('100%')
      .margin({ top: '12vbp' })
    }
    .justifyContent(FlexAlign.Start)
    .alignItems(HorizontalAlign.Center)
    .padding({ left: '16vp', right: '16vp' })
  }

  build() {
    Flex({ direction: FlexDirection.Column }) {
      // Action bar
      Column() {
        Row() {
          Flex({ direction: FlexDirection.Row, justifyContent: FlexAlign.Center, alignItems: ItemAlign.Center }) {
            Row() {
              SymbolGlyph($r('sys.symbol.chevron_backward')).iconStyles()
            }
            .buttonStyles()
            .onClick(() => {
              if (this.webviewController.accessBackward()) {
                this.webviewController.backward();
              } else {
                exitApp(this.context);
              }
            })

            Text(extractDomain(this.webUrl))
              .fontColor($r('sys.color.ohos_id_color_text_primary'))
              .fontSize($r('sys.float.ohos_id_text_size_headline8'))
              .fontWeight(FontWeight.Bold)
              .width('100%')
              .opacity(0.9)
              .constraintSize({ minHeight: '24vp' })
              .maxLines(1)
              .textOverflow({ overflow: TextOverflow.Ellipsis })
              .wordBreak(WordBreak.BREAK_ALL)
              .textAlign(TextAlign.Center)

            Row() {
              SymbolGlyph($r('sys.symbol.dot_grid_2x2')).iconStyles()
            }
            .buttonStyles()
            .onClick(() => {
              this.isMenuVisible = true;
            })
            .bindMenu(this.isMenuVisible, this.ContextMenu(), {
              onDisappear: () => {
                this.isMenuVisible = false;
              },
              placement: Placement.BottomRight,
            })
          }
          .backgroundColor($r('sys.color.ohos_id_color_background'))
          .layoutWeight(1)
          .constraintSize({ minHeight: '40bp' })
          .padding({ left: this.adaptPadding, right: this.adaptPadding })
        }
        .width('100%')
        .backgroundColor($r('sys.color.ohos_id_color_background'))
        .margin({
          top: '8vp',
          bottom: '6vp',
          left: '16vp',
          right: '16vp'
        }).alignItems(VerticalAlign.Center)

        Progress({ value: 0, total: 100, type: ProgressType.Linear })
          .value(this.loadProgress)
          .color($r('sys.color.comp_background_emphasize'))
          .backgroundColor($r('sys.color.comp_background_secondary'))
          .visibility(this.loadProgress < 100 ? Visibility.Visible : Visibility.Hidden)
          .style({
            strokeWidth: '2vp',
            strokeRadius: 0
          })
          .width('100%')

        // 绑定 bindSheet用
        Column()
          .height(0)
          .bindSheet($$this.isSelectUASheetVisible, this.UASelectSheet(), {
            showClose: true,
            title: { title: $r('app.string.site_setting_single_website_title', extractDomain(this.webUrl)) },
            onDisappear: () => {
              try {
                this.webviewController.setCustomUserAgent(this.selectedUA);
                this.webviewController.refresh();
              } catch (error) {
                hilog.error(DOMAIN, TAG, '%{public}s',
                  `Failed setCustomUserAgent. Code:${error.code}, message:${error.message}`);
              }
            }
          })
      }
      .width('100%')
      .constraintSize({
        minHeight: '56vp'
      })
      .backgroundColor($r('sys.color.ohos_id_color_background'))
      .visibility(this.isActionBarVisible ? Visibility.Visible :
        Visibility.None)

      Web({ src: '', controller: this.webviewController })
        .javaScriptAccess(true)
        .fileAccess(false)
        .geolocationAccess(false)
        .domStorageAccess(true)
        .overviewModeAccess(false)
        .onOverrideUrlLoading((request) => {
          this.webUrl = request.getRequestUrl();
          if (validateURL(this.webUrl) && !this.webUrl.startsWith('http') && !this.webUrl.startsWith('https')) {
            (this.getUIContext().getHostContext() as common.UIAbilityContext).openLink(this.webUrl)
              .then(() => {
                hilog.info(DOMAIN, TAG, 'open link success.');               
              }).catch((err: BusinessError) => {
                hilog.error(DOMAIN, TAG, `open link failed. Code is ${err.code}, message is ${err.message}`);
              })
            return true;
          }
          return false;
        })
        .onConsole((event) => {
          return true;
        })
        .onControllerAttached(() => {
          try {
            this.harmonyUA = this.webviewController.getUserAgent();
            this.isPhone = /Phone/i.test(this.harmonyUA);
            this.selectedUA = this.harmonyUA;
            hilog.info(DOMAIN, TAG, '%{public}s', 'UA isPhone:'  + this.isPhone);
          } catch (error) {
            hilog.error(DOMAIN, TAG, '%{public}s', `Failed to get UA. Code:${error.code}, message:${error.message}`);
          }
        })
        .onPageBegin(() => {
          updateFinalUrl(this.webUrl);
          this.loadProgress = 0;
          if (this.isPhone && this.selectedUA === this.harmonyUA) {
            this.setUA();
            this.selectedUA = this.harmonyUA;
            try {
              this.webviewController.setCustomUserAgent(this.selectedUA);
            } catch (error) {
              hilog.error(DOMAIN, TAG, '%{public}s',
                `onPageBegin Failed setCustomUserAgent. Code:${error.code}, message:${error.message}`);
            }
          }
        })
        .onProgressChange((event) => {
          this.loadProgress = event.newProgress;
        })
        .onPageEnd((event) => {
          this.loadProgress = 100;
          if (event) {
            this.webUrl = event.url;
            hilog.info(DOMAIN, TAG, '%{public}s', 'Url:' + safeAnonymize(this.webUrl));
            if (event.url == 'about:blank') {
              hilog.info(DOMAIN, TAG, '%{public}s', 'about:blank exit.');
              exitApp(this.context);
            }
          }
        })
        .onSafeBrowsingCheckResult((callback) => { // 恶意网址检测
          let jsonData = JSON.stringify(callback);
          let json: OnSafeBrowsingCheckResultCallback = JSON.parse(jsonData);
          hilog.info(DOMAIN, TAG, '%{public}s', 'onSafeBrowsingCheckResult: [threatType]= ' + json.threatType);
        })
        .onHttpErrorReceive((event) => {
          if (event) {
            let errorCode = event.response.getResponseCode();
            let failedUrl = event.request.getRequestUrl();
            hilog.info(DOMAIN, TAG, 'getResponseCode:' + errorCode);
            this.handleHttpError(errorCode, failedUrl);
          }
        })
        .onErrorReceive((event) => {
          if (event) {
            updateOnErrorReceive(event.error.getErrorCode());
            hilog.info(DOMAIN, TAG, 'getErrorInfo:' + event.error.getErrorInfo());
            hilog.info(DOMAIN, TAG, 'getErrorCode:' + event.error.getErrorCode());
          }
        })
        .onSslErrorEventReceive((event) => {
          updateOnSslErrorEvent(event.error);
          hilog.info(DOMAIN, TAG, 'Ssl Error:' + event.error);
          AlertDialog.show({
            title: $r('app.string.continue_visit'),
            message: $r('app.string.ssl_normal_error_msg'),
            primaryButton: {
              value: $r('app.string.confirm_dialog_cancel'),
              action: () => {
                hilog.info(DOMAIN, TAG, 'primaryButton handleCancel');
                event.handler.handleCancel();
              }
            },
            secondaryButton: {
              value: $r('app.string.ssl_error_dialog_continue_btn'),
              fontColor: $r('sys.color.warning'),
              action: () => {
                hilog.info(DOMAIN, TAG, 'secondaryButton handleConfirm');
                event.handler.handleConfirm();
              }
            },
            cancel: () => {
              hilog.info(DOMAIN, TAG, 'cancel handleConfirm');
              event.handler.handleConfirm();
            }
          })
        })
        .onFullScreenEnter((event) => {
          hilog.info(DOMAIN, TAG, '%{public}s', 'onFullScreenEnter.');
          this.isActionBarVisible = false;
          this.handleFullScreenChange();
        })
        .onFullScreenExit(() => {
          hilog.info(DOMAIN, TAG, '%{public}s', 'onFullScreenExit.');
          this.isActionBarVisible = true;
          this.handleFullScreenChange();
        })
        .darkMode(WebDarkMode.Off)
        .backgroundColor(Color.White)
        .width('100%')
    }
    .padding({ top: px2vp(this.topRectHeight) })
  }

  private async handleFullScreenChange() {
    let orientation = window.Orientation.UNSPECIFIED;
    if (!this.isActionBarVisible){
      orientation = window.Orientation.AUTO_ROTATION;
    }
    try {
      const windowClass = await window.getLastWindow(this.context);
      await windowClass.setPreferredOrientation(orientation);
      hilog.info(DOMAIN, TAG, '%{public}s', 'Orientation' + orientation);
    } catch (error) {
      let err: BusinessError = error as BusinessError;
      hilog.error(DOMAIN, 'TAG', '%{public}s',
        `Orientation failed.Code:${err.code},message:${err.message}.` + orientation);
    }
  }

  private setUA():void {
    hilog.info(DOMAIN, TAG, '%{public}s', 'setUA enter.');
    this.harmonyUA = HarmonyUserAgentSet.harmonyUACompatible;
    let pattern:RegExp|undefined = getHmosUAComplexRegex();
    if (pattern) {
      if (pattern.test(extractDomain(this.webUrl))){
        this.harmonyUA = HarmonyUserAgentSet.harmonyUAHmos;
        hilog.info(DOMAIN, TAG, '%{public}s', 'setUA harmonyUAHmos.');
      }
    }
  }

  private handleHttpError(code:number, url:string) {
    const retryList:StringNumberPair[] = getRetryList();
    let retryFlag = false;
    for (let i = 0;i < retryList.length;i++) {
      if (retryList[i][0] === extractDomain(url) && retryList[i][1] === code) {
        retryFlag = true;
        break;
      }
    }
    if (retryFlag) {
      updateOnHttpErrorReceive(RETRY_CODE);
      if (this.retryCount < MAX_RETRY) {
        this.retryCount++;
        try {
          this.webviewController.loadUrl(this.defaultUrl);
          hilog.info(DOMAIN, 'TAG', '%{public}s', 'handleHttpError retryCount:' + this.retryCount);
        } catch (error) {
          let err: BusinessError = error as BusinessError;
          hilog.error(DOMAIN, 'TAG', '%{public}s', `retry Failed to load url.Code:${err.code},message:${err.message}`);
        }
      }
    } else {
      updateOnHttpErrorReceive(code);
    }
  }

  private startCountdown() {
    this.timerId = setInterval(() => {
      hilog.info(DOMAIN, TAG, '%{public}s', 'Timer count is:' + this.timerCount);
      if (this.timerCount > 0 && !this.isLoaded) {
        this.timerCount--
        if (this.isNetBind) {
          hilog.info(DOMAIN, TAG, '%{public}s', 'startCountdown LoadUrl');
          this.webUrl = getUrl();
          try {
            webview.ProxyController.removeProxyOverride(() => {
              hilog.info(DOMAIN, TAG, '%{public}s', 'removeProxyOverride proxy changed');
            });
          } catch (error) {
            let err: BusinessError = error as BusinessError;
            hilog.error(DOMAIN, TAG, '%{public}s', `removeProxyOverride Code:${err.code}, message:${err.message}`);
          }
          let proxyConfig:webview.ProxyConfig = new webview.ProxyConfig();
          try {
            webview.ProxyController.applyProxyOverride(proxyConfig, () => {
              hilog.info(DOMAIN, TAG, '%{public}s', 'applyProxyOverride proxy changed');
            });
          } catch (error) {
            let err: BusinessError = error as BusinessError;
            hilog.error(DOMAIN, TAG, '%{public}s', `applyProxyOverride Code:${err.code}, message:${err.message}`);
          }
          try {
            this.webviewController.loadUrl(this.webUrl);
            hilog.info(DOMAIN, TAG, '%{public}s', 'Load url:' + safeAnonymize(this.webUrl));
          } catch (error) {
            let err: BusinessError = error as BusinessError;
            hilog.error(DOMAIN, TAG, '%{public}s', `Failed to load url. Code:${err.code}, message:${err.message}`);
          }
          this.isLoaded = true;
        }
      } else {
        clearInterval(this.timerId)
        this.timerId = -1
        hilog.info(DOMAIN, TAG, '%{public}s', 'Stop timer.');
      }
    }, 100) // 100ms执行一次
  }

  onDidBuild() {
    hilog.info(DOMAIN, TAG, '%{public}s', 'Enter onDidBuild.');
    this.startCountdown();
  } 

  aboutToAppear(): void {
    bindToNetById(this.context)
    .then(()=>{
        hilog.info(DOMAIN, TAG, '%{public}s', 'aboutToAppear bindToNetById.');
        this.isNetBind = true;
      })
      .catch(()=>{
        hilog.error(DOMAIN, TAG, '%{public}s', 'aboutToAppear bindToNetById failed.');
      })
    try {
      i18n.System.setAppPreferredLanguage('default');
    } catch (error) {
      let err: BusinessError = error as BusinessError;
      hilog.error(DOMAIN, TAG, '%{public}s', `Failed to set Language. Code:${err.code}, message:${err.message}`);
    }
    emitter.on('WANT_UPDATE', () => {
      hilog.info(DOMAIN, TAG, '%{public}s', 'on new want.');
      try {
        this.webviewController.clearSslCache();
        hilog.info(DOMAIN, TAG, '%{public}s', 'clearSslCache');
      } catch (error) {
        let err: BusinessError = error as BusinessError;
        hilog.error(DOMAIN, TAG, '%{public}s', `Failed to clearSslCache. Code:${err.code}, message:${err.message}`);
      }
      this.isNetBind = false;
      this.timerCount = 10;
      this.isLoaded = false;
      this.startCountdown();
      bindToNetById(this.context)
        .then(()=>{
            hilog.info(DOMAIN, TAG, '%{public}s', 'on new want bindToNetById.');
            this.isNetBind = true;
        })
        .catch(()=>{
          hilog.error(DOMAIN, TAG, '%{public}s', 'on new want bindToNetById failed.');
        });
    });
  }

  aboutToDisappear(): void {
    updateAboutToDisappear();
    emitter.off('WANT_UPDATE');
  }
}