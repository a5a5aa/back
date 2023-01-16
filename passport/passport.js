import passport from 'passport'
import bcrypt from 'bcrypt'
import passportLocal from 'passport-local'
import passportJWT from 'passport-jwt'
import users from '../models/users.js'

// 引用登入策略
const LocalStrategy = passportLocal.Strategy
const JWTStrategy = passportJWT.Strategy

// 使用 Local 策略寫 login 方式
passport.use('login', new LocalStrategy({
  // 預設帳密欄位是 username 和 password
  // 修改成 account 和 password
  usernameField: 'account',
  passwordField: 'password'
}, async (account, password, done) => {
  // done(錯誤, 傳到下一步的資料, 傳到下一步 info 的內容)
  try {
    const user = await users.findOne({ account })
    // 沒有找到就顯示帳號不存在
    if (!user) {
      return done(null, false, { message: '帳號不存在' })
    }
    // 如果密碼不一樣就顯示密碼錯誤
    if (!bcrypt.compareSync(password, user.password)) {
      return done(null, false, { message: '密碼錯誤' })
    }
    return done(null, user)
  } catch (error) {
    // 上面有錯誤就跳到這裡並進到下一步
    return done(error, false)
  }
}))

// 使用 JWT 策略寫 jwt 方式
passport.use('jwt', new JWTStrategy({
  jwtFromRequest: passportJWT.ExtractJwt.fromAuthHeaderAsBearerToken(),
  secretOrKey: process.env.JWT_SECRET,
  passReqToCallback: true,
  // 忽略過期檢查
  ignoreExpiration: true
}, async (req, payload, done) => {
  // 檢查有沒有過期
  // payload 解譯出來的過期時間單位是秒 JS 的 Date.now() 單位是毫秒，所以要 *1000
  const expired = payload.exp * 1000 < Date.now()
  if (expired && req.originalUrl !== '/users/extend' && req.originalUrl !== '/users/logout') {
    return done(null, false, { message: '登入逾時' })
  }
  const token = req.headers.authorization.split(' ')[1]
  try {
    const user = await users.findOne({ _id: payload._id, tokens: token })
    if (user) {
      return done(null, { user, token })
    }
    return done(null, false, { message: '使用者不存在或 JWT 無效' })
  } catch (error) {
    return done(error, false)
  }
}))
