// @ts-ignore
import { Context } from '@ohos.abilityAccessCtrl';

// 构造单例对象
export class GlobalThis {
  private constructor() {}
  private static instance: GlobalThis;
  private _uiContexts = new Map<string, Context>();

  public static getInstance(): GlobalThis {
    if (!GlobalThis.instance) {
      GlobalThis.instance = new GlobalThis();
    }
    return GlobalThis.instance;
  }

  getContext(key: string): Context | undefined {
    return this._uiContexts.get(key);
  }

  setContext(key: string, value: Context): void {
    this._uiContexts.set(key, value);
  }

  // 其他需要传递的内容依此扩展
}