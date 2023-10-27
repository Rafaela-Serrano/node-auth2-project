const router = require("express").Router();

const { 
  checkUsernameExists, 
  validateRoleName 
} = require('./auth-middleware');

const jwt = require("jsonwebtoken");
const { JWT_SECRET } = require("../secrets/index"); // use this secret!

const bcrypt = require("bcryptjs");

const model = require("../users/users-model");

router.post("/register", validateRoleName, (req, res, next) => {
  /**
    [POST] /api/auth/register { "username": "anna", "password": "1234", "role_name": "angel" }

    response:
    status 201
    {
      "user"_id: 3,
      "username": "anna",
      "role_name": "angel"
    }
   */
  let {username,password}= req.body
  const {role_name} = req.body

  const hash = bcrypt.hashSync(password,8)
  password = hash 

  model.add({username,password,role_name})
  .then( added => {
    res.json(added)
  })
  .catch(next)
});


router.post('/login', checkUsernameExists, (req, res, next) => {
  /**
    [POST] /api/auth/login { "username": "sue", "password": "1234" }

    response:
    status 200
    {
      "message": "sue is back!",
      "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.ETC.ETC"
    }

    The token must expire in one day, and must provide the following information
    in its payload:

    {
      "subject"  : 1       // the user_id of the authenticated user
      "username" : "bob"   // the username of the authenticated user
      "role_name": "admin" // the role of the authenticated user
    }
   */
  let {username, password} = req.body

  model.findBy(username)
  .then( user => {
    if(user && bcrypt.compareSync(password,user.password)){
      const token = generateToken(user)

      res.status(200).json({
        message:`${user.username} is back!`,
        token
      })
    }else{
      next({
        status:401,
        message:"Invalid credentials"
      })}
  }
  ).catch(next)
});

function generateToken(user) {
  const payload = {
    subject: user.id,
    username: user.username,
    role: user.role,
  }
  const options = {
    expiresIn: '1d',
  }
  return jwt.sign(payload, JWT_SECRET, options)
}

module.exports = router;
