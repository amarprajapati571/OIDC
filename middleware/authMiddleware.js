



// const BearerStrategy = require('passport-http-bearer').Strategy;
// const HybridStrategy = require('passport-jwt').Strategy;

const bcrypt = require('bcrypt');
const db = require('knex')(require('../knexfile'));
const jwt = require('jsonwebtoken');
const session = require('express-session');
const { v4: uuidv4 } = require('uuid');
const KnexSessionStore = require('connect-session-knex')(session);

const logger = require('./logger');

const cookieSettings = {
  httpOnly: true,
  secure: false,
  maxAge: 24 * 60 * 60 * 1000,
};

// const convert = (from, to) => (str) => Buffer.from(str, from).toString(to);
class AuthMiddleware {
  static sessionManager = session({
    cookie: cookieSettings,
    genid() {
      return uuidv4();
    },
    name: 'refreshToken',
    resave: false,
    rolling: true,
    saveUninitialized: true,
    secret: process.env.JWT_SIGNING_SECRET,
    store: new KnexSessionStore({ knex: db }),
  });

  static signingSecret = process.env.JWT_SECRET;

  static accessTokenExpirationTime = process.env.JWT_EXPIRATION_TIME;

  static async newSession(payload, req, res, checkDB = true) {
    let users = [payload];

    // We don't want to hit the DB again if we just created this user.
    if (checkDB) {
      users = await db.from('users').where('users.uid', payload.uid);
      if (users.length < 1) {
        res
          .status(403)
          .json({
            error: 'User not found',
            user: null,
          })
          .send();
        return false;
      }
    } else if (!payload.uid) {
      res
        .status(403)
        .json({
          error: 'Invalid user info',
          user: null,
        })
        .send(); // TODO - throw an error here and catch when
      return false; //        calling since this isn't really a
    } //                      "client" issue / 403

    try {
      const user = {
        uid: users[0].uid,
        email: users[0].email,
        first_name: users[0].first_name,
        last_name: users[0].last_name,
        preferences: users[0].preferences,
      };

      // Remove old sessions - our rolling sessions should have created a new one
      AuthMiddleware.destroyOldSessionsForUser(user.uid, req.sessionID);

      // Create the access token and attach it to the response.
      const accessToken = await jwt.sign(user, AuthMiddleware.signingSecret, {
        expiresIn: AuthMiddleware.accessTokenExpirationTime,
      });
      req.session.accessToken = accessToken;
      req.session.currentAccessToken = accessToken;
      req.session.save();
      res.cookie('accessToken', accessToken, cookieSettings);
      // Return the user on success
      return user;
    } catch (error) {
      res
        .status(500)
        .json({
          user: null,
        })
        .send();
      logger.log('warn', `Error: ${error}`);
      return false;
    }
  }

  static async destroyOldSessionsForUser(userUID, currentID) {
    db.from('sessions')
      .where('sessions.user_uid', userUID)
      .whereNot('sid', currentID)
      .del();
  }

  static jwtFromRequest(req) {
    let token = null;
    if (req.cookies && req.cookies.accessToken) {
      token = req.cookies.accessToken;
    }
    return token;
  }

  static authenticateHybrid(req, res, next) {
    if (!req.locals) {
      // CTODO - move this to a middleware
      req.locals = {};
    }

    const token = AuthMiddleware.jwtFromRequest(req);

    if (!token) {
      return res
        .status(403)
        .json({
          user: null,
        })
        .send();
    }

    // Verify the JWT (AccessToken) or the session (RefreshToken)
    jwt.verify(token, AuthMiddleware.signingSecret, (jwtError1, payload) => {
      if (jwtError1) {
        if (jwtError1 instanceof jwt.TokenExpiredError) {
          jwt.verify(
            token,
            AuthMiddleware.signingSecret,
            { ignoreExpiration: true },
            (jwtError2, secondPayload) => {
              if (jwtError2) {
                res
                  .status(403)
                  .json({
                    user: null,
                  })
                  .send();
              } else {
                AuthMiddleware.sessionManager(req, res, () => {
                  if (req.session && req.session.currentAccessToken === token) {
                    // Valid refresh token but expired access token - refresh
                    //   them both with a new session
                    AuthMiddleware.newSession(
                      secondPayload,
                      req,
                      res,
                      true,
                    ).then((user) => {
                      if (user) {
                        req.locals.user = user;
                      } // what if else?
                      next();
                    });
                  } else {
                    // It looks like a token was stolen - Ivalidate all sessions for user in jwt
                    AuthMiddleware.destroyOldSessionsForUser(
                      secondPayload.uid,
                      '',
                    );
                    res
                      .status(403)
                      .json({
                        user: null,
                      })
                      .send();
                  }
                });
              }
            },
          );
        } else {
          res
            .status(403)
            .json({
              user: null,
            })
            .send(); // Invalid session fell through.
        }
      } else {
        req.locals.user = payload;
        next();
      }
    });
  }

  static bearerFromRequest(req) {
    let token = null;
    if (req.headers && req.headers.authorization) {
      const parts = req.headers.authorization.split(' ');
      if (parts.length === 2) {
        const scheme = parts[0];
        const credentials = parts[1];

        if (/^Bearer$/i.test(scheme)) {
          token = credentials;
        }
      } else {
        return false;
      }
    }
    return token;
  }

  // When we want to allow bearer or session auth.
  static authenticateBearerWithoutPassthrough(req, res, next) {
    AuthMiddleware.authenticateBearer(req, res, next, false);
  }

  // When only bearer auth is allowed.
  static authenticateBearerWithPassthrough(req, res, next) {
    AuthMiddleware.authenticateBearer(req, res, next, true);
  }

  static authenticateBearer(req, res, next, passthrough = false) {
    if (!req.locals) {
      // CTODO - move this to a middleware
      req.locals = {};
    }

    const token = AuthMiddleware.bearerFromRequest(req);
    if (!token) {
      if (!passthrough) {
        return res.status(403).send();
      }
      return next();
    }

    // CTODO - Should these be JWTs with refresh?
    const strippedPrefix = token.substring(
      token.indexOf('_') + 1,
      token.length,
    );
    const indexPoint = strippedPrefix.indexOf('.');
    const uid = strippedPrefix.substring(0, indexPoint);
    const tokenValue = strippedPrefix.substring(
      indexPoint + 1,
      strippedPrefix.length,
    );

    db.from('access_tokens')
      .where('uid', uid)
      .then(async (tokens) => {
        if (tokens.length === 1) {
          const isMatch = await bcrypt.compare(
            tokenValue,
            tokens[0].access_token_hash,
          );
          if (isMatch) {
            const user = await db('users')
              .where('uid', tokens[0].owner_uid)
              .first(); // TODO: Should be an org and won't handle perms
            if (user) {
              req.locals.user = user;
              next();
            } else {
              return res.status(403).send();
            }
          }
        } else {
          return res.status(403).send();
        }
      })
      .catch((err) => {
        logger.log('info', `Error matching token: ${err}`);
        return res.status(500).send();
      });
  } // CTODO - incorrect token on yatt-pipe just hangs
  
  static checkUserAuth = async (req, res, next) => {
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

}

module.exports = {
  AuthMiddleware,
};

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
