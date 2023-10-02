

const jwt = require('jsonwebtoken')

// import UserModel from '../models/User.model.js'; //schema for find user details this is only example

var checkUserAuth = async (req, res, next) => {
  let token
  const { authorization } = req.headers;
  console.log(authorization)
  if (authorization && authorization.startsWith('Bearer')) {
    try {
      // Get Token from header
      token = authorization.split(' ')[1]

      // Verify Token
      const { userID } = jwt.verify(token, process.env.JWT_SECRET_KEY)

      // Get User from Token
      req.user = await UserModel.findById(userID).select('-password')//database logic
      console.log(req.user)

      next()
    } catch (error) {
      console.log(error)
      res.status(401).send({ 
        status: false, 
         message: "Unauthorized User" 
        })
    }
  }
  if (!token) {
    res.status(401).send({ 
      status: false, 
      message: "Unauthorized User, No Token" 
    })
  }
}

module.exports = checkUserAuth;