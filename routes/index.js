var router = require('express').Router();
const { requiresAuth } = require('express-openid-connect');
const checkUserAuth = require('../middleware/authMiddleware');

router.get('/',  (req, res, next) => {
  let isAuthenticated= req.oidc.isAuthenticated()
  res.status(200).contentType('text/html').render('index', {
    title: 'Auth0 Webapp sample Nodejs',
    isAuthenticated: req.oidc.isAuthenticated()
  });
});

router.get('/profile', requiresAuth(), async (req, res, next) =>{

  const { sub, email, given_name, family_name, picture } = req.oidc.user;

  // Check if the user already exists in the database by their sub (unique identifier)
  // let existingUser = await UserModel.findOne({ sub });

  if (!existingUser) {
    // If the user doesn't exist, create a new user record in the database
    // const newUser = new UserModel({
    //   sub,
    //   email,
    //   given_name,
    //   family_name,
    //   picture,
    // });

    // await newUser.save(); // Save the new user to the database
  }

  let userProfile =  JSON.stringify(req.oidc.user, null, 2)
  res.status(200).contentType('text/html').render('profile', {
    userProfile: JSON.stringify(req.oidc.user, null, 2),
    title: 'Profile page'
  });
});

//inbuild middleware
router.get('/contact-us',requiresAuth(),(req,res,next)=>{
  res.status(200).contentType('text/html').render('contact', {
    userProfile: JSON.stringify(req.oidc.user, null, 2),
    title: 'contact page'
  });
})

//custom middleware 
router.get('/user-list', checkUserAuth, async (req, res, next) => { // Mark the route handler as async
  try {
    let { user_type } = req.user;

    //Database logic for retrieve  the data
    if (user_type === 'admin') {
      const users = await UserModel.find({ user_type: { $ne: 'admin' } }).lean(); // Use await here

      res.send(users);
    } else {
      res.send({
        status: false,
        message: "You are not admin"
      });
    }
  } catch (err) {
    console.error(err); // Log the error
    res.status(500).send({
      status: false,
      message: "Internal server error"
    });
  }
});

//Save user and getting JWT Token
router.get('/register',(req,res)=>{
  try{
    //Save and getting the userID 
    const token = jwt.sign({ userID: saved_user._id }, process.env.JWT_SECRET_KEY, { expiresIn: '5d' })
            res.status(201).send({ "status": "success", "message": "Registration Success", "token": token })
  }catch(err){
    console.log(err)
  }
})

module.exports = router;
