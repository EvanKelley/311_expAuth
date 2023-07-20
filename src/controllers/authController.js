
let db = require("../model/db");

let argon = require("argon2");

let jwt = require("jsonwebtoken");


// accept the email and password
// store the email and hash
let registerUser = async function(req, res){
  // get the email and password for the request
  let email = req.body.email;
  let password = req.body.password;
  
  // make sure the email is truthy
  if(!email){
    res.status(400).json("Email is required");
    return;
  }

  // convert password to its hash
  let hash
  try{
    hash = await argon.hash(password);
  }catch(err){
    // if for some reason the conversion fails, 
    // log the error, and resonpse with 500 code,
    console.log("Failed to hash the password", err);
    res.sendStatus(500);
    return;
  }

  // I have the hash and email
  let sql = "insert into todo_users (email, hash) values (?, ?)";
  let params = [email, hash];

  db.query(sql, params, function(err, results){
    if(err){
      console.log("Failed to register a user", err);
      res.sendStatus(500);
    } else {
      res.sendStatus(204);
    }
  });
 };


let loginUser = function(req, res){

  // 1. get the email and password from the request
  // 2. (skip) generate the hash from the password (skip because the library will compare password to hash)
  // 3. fetch the stored hash for the email from the database
  // 4. if the user exists in the database check the stored hash against the presented password
  //    to decide if the login failed or not
  // 5. if the user does not exist, fail the login

  let email = req.body.email;
  let password = req.body.password;

  let sql = "select id, hash from todo_users where email = ?";
  let params = [email];

  db.query(sql, params, async function(err, results){
    let storedHash;
    let storedId;
    if(err){
        console.log("Failed to fetch hash for user", err);
    } else if (results.length > 1) {
        console.log("Returned more than 1 user for the email", email);
    } else if (results.length == 1) {
        storedHash = results[0].hash;
        storedId = results[0].id;
    } else if (results.length == 0) {
        console.log("Did not find a user for email", email);
    }

    try{
      let pass = await argon.verify(storedHash, password);
      if(pass){
        // Generate a token and send it back
        let token = {
          id: storedId,
          email: email
        }; 
        
        // Token is good for 1 day 
        let signedToken = jwt.sign(token, process.env.JWT_SECRET,{expiresIn: 86400});
        res.json(signedToken);

      } else {
        res.sendStatus(401);
      }
    } catch(err){
        console.log("Failed when verifying the hash", err);
        res.sendStatus(401);
    }
  });
};


module.exports = {
  registerUser,
  loginUser
};