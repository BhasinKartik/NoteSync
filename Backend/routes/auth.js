const express=require('express');
const User = require('../models/User');
const router=express.Router();
const { body, validationResult } = require('express-validator');
const bcrypt=require('bcryptjs');
const jwt=require('jsonwebtoken');
const JWT_SECRET="Kartikisagood$oy";
const fetchuser=require('../middleware/fetchuser');
router.post('/createuser', [
    body('name','Please enter a valid name').isLength({ min: 3 }),
    body('email','Please enter a valid email').isEmail(),
    body('password','Password length should be more than 4').isLength({ min: 5 }),
], async(req, res) => {
    const errors = validationResult(req);
    let success=false;
    if (!errors.isEmpty()) {
        return res.status(400).json({ success, errors: errors.array() });
    }
    try{
    let user=await User.findOne({email:req.body.email})
    if(user){
        return res.status(400).json({success, error:"This email already exists!"})
    }
    const salt= await bcrypt.genSalt(10);
    const secPass=await bcrypt.hash(req.body.password,salt);
    // res.send(req.body);
     user=await User.create({
        name: req.body.name,
        email: req.body.email,
        password: secPass,
    })
    const data={
        user:{
            id:user.id
        }
    }
    const authtoken=jwt.sign(data,JWT_SECRET);
    success=true;
res.json({success,authtoken});
}catch(err){
    console.log(err.message)
res.status(500).send("some error occured");
}
})
router.post('/login', [
    body('email','Enter a valid email').isEmail(),
    body('password','Password length should be more than 4').isLength({ min: 5 }),
], async(req, res) => {
    const errors = validationResult(req);
    let success=false;
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }
    const {email,password}=req.body;
    try{
        let user=await User.findOne({email});
        if(!user){
return res.status(400).send("Please try to login with correct credentials");
        }
    const passwordCompare= await bcrypt.compare(password,user.password);
    if(!passwordCompare){
        success=false;
return res.status(400).send("Please try to login with correct credentials");
    }
    const data={
        user:{
            id:user.id
        }
    }
    const authtoken= jwt.sign(data,JWT_SECRET);
    success=true;
res.json({success,authtoken});
}catch(error){
    console.log(error.message);
    res.status(500).send("Internal server error");
}
})
router.post('/getuser',fetchuser, async(req,res)=>{
    try{
     const userId=req.user.id;
        const user=await User.findById(userId).select("-password");
        res.send(user)
    }catch(error){
        console.log(error.message);
    res.status(500).send("Internal server error");
    }
})
module.exports=router