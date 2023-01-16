import { Schema, model } from 'mongoose'

const schema = new Schema({
  name: {
    type: String,
    required: [true, '缺少名稱']
  },
  price: {
    type: Number,
    min: [0, '價格錯誤'],
    required: [true, '缺少價格']
  },
  description: {
    type: String,
    required: [true, '缺少說明']
  },
  image: {
    type: String,
    required: [true, '缺少圖片']
  },
  sell: {
    type: Boolean,
    required: [true, '缺少狀態']
  },
  category: {
    type: String,
    required: [true, '缺少分類'],
    // enum 限制欄位的值只能是陣列裡面的其中一個
    enum: {
      values: ['衣服', '皮件', '鞋子', '飾品', '3C', '其他'],
      message: '找不到 {VALUE} 分類'
    }
  }
}, { versionKey: false })

export default model('products', schema)
