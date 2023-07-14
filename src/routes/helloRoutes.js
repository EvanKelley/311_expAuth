let express = require("express");

let router = express.Router();

let authsMiddleware = require("../middleware/auths");

// This is unprotected (does not require the client to be authenticated)
router.get("/hello", function(req,res){
    res.json("Hello there!");
})

// This is a protected (requires the client to be authenticated)
router.get("/handshake" , authsMiddleware.checkJWT, function(req,res){

  // get the JWT from the client, and make sure it checks out

    let userId = req.userinfo.id;

    res.json(`I see you comrade #${userId}!`);
})

module.exports = router;