const User = require('../model/User')
const bcrypt = require('bcrypt')
const jwt = require('jsonwebtoken')

const handleLogin = async (req, res) => {
  const cookies = req.cookies

  const { user, pwd } = req.body

  if (!user || !pwd) return res.status(400).json({ 'message': 'Username and password are required' })

  const foundUser = await User.findOne({ username: user }).exec()
  if (!foundUser) return res.sendStatus(401)
  const match = await bcrypt.compare(pwd, foundUser.password)
  if (match) {
    const roles = Object.values(foundUser.roles).filter(Boolean)

    const accessToken = jwt.sign(
      {
        "UserInfo": {
          "username": foundUser.username,
          "roles": roles
        }
      },
      process.env.ACCESS_TOKEN_SECRET,
      { expiresIn: '40s' }
    )
    const newRefreshToken = jwt.sign(
      { "username": foundUser.username },
      process.env.REFRESH_TOKEN_SECRET,
      { expiresIn: '1d' }
    )

    let newRefreshTokenArray = 
      !cookies.jwt 
        ? foundUser.refreshToken
        : foundUser.refreshToken.filter(rt => rt !== cookies.jwt)

    if (cookies?.jwt) {
      const refreshToken = cookies.jwt
      const foundToken = await User.findOne({ refreshToken }).exec()

      if (!foundToken) {
        newRefreshTokenArray = []
      }

      res.clearCookie('jwt', { httpOnly: true, sameSite: 'None', secure: true })
    }

    foundUser.refreshToken = [...newRefreshTokenArray, newRefreshToken]
    const result = await foundUser.save()

    res.cookie('jwt', newRefreshToken, { httpOnly: true, sameSite: 'None', secure: true, maxAge: 24 * 60 * 60 * 1000 })

    res.json({ accessToken })
  } else {
    res.sendStatus(401)
  }
}

module.exports = { handleLogin }