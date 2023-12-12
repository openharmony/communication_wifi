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

// @ts-nocheck

import image from '@ohos.multimedia.image'
import fileio from '@ohos.fileio'
import prompt from '@ohos.prompt'
import mediaLibrary from '@ohos.multimedia.mediaLibrary'
import DateTimeUtil from './DateTimeUtil'


/**
 * mediaUtils of wifi test
 */

const TAG = "[MediaUtils]"

class MediaUtils {
  async createAndGetFile(context: any) {
    let mediaTest = mediaLibrary.getMediaLibrary(context)
    let info = {
      prefix: 'IMG_', suffix: '.jpg', directory: mediaLibrary.DirectoryType.DIR_IMAGE
    }
    let dateTimeUtil = new DateTimeUtil()
    let name = `${dateTimeUtil.getDate()}_${dateTimeUtil.getTime()}`
    let displayName = `${info.prefix}${name}${info.suffix}`
    let publicPath = await mediaTest.getPublicDirectory(info.directory)
    console.log(TAG, `publicPath = ${publicPath}`)
    return await mediaTest.createAsset(mediaLibrary.MediaType.IMAGE, displayName, publicPath)
  }

  async savePicture(data: image.PixelMap, context: any) {
    console.log(TAG, `savePicture`)
    let packOpts: image.PackingOption = {
      format: "image/jpeg", quality: 100
    }
    let imagePackerApi = image.createImagePacker()
    let arrayBuffer = await imagePackerApi.packing(data, packOpts)
    let fileAsset = await this.createAndGetFile(context)
    let fd = await fileAsset.open('Rw')
    imagePackerApi.release()
    try {
      await fileio.write(fd, arrayBuffer)
    } catch (err) {
      console.log(`write failed, code is ${err.code}, message is ${err.message}`)
    }
    await fileAsset.close(fd)
    console.log(TAG, `write done`)
    prompt.showToast({
      message: '图片保存成功', duration: 1000
    })
  }
}

export default new MediaUtils()