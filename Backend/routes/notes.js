const express=require('express');
const router=express.Router();
const fetchuser=require('../middleware/fetchuser');
const Notes=require('../models/Notes');
const { body, validationResult } = require('express-validator');
//Route 1: Get All the notes using: GET "/api/auth/getuser", Login required
router.get('/fetchallnotes',fetchuser,async(req,res)=>{
    try{
const notes=await Notes.find({user:req.user.id});
res.json(notes);
    }catch(error){
        console.log(error.message);
        res.status(500).send("Internal server error");
    }
})
//Route 2: Add a new note using: POST "/api/notes/addnote", Login required
router.post('/addnote',fetchuser, [
    body('title','Please enter a valid title').isLength({ min: 3 }),
    body('description','description length should be more than 4').isLength({ min: 5 }),
], async(req,res)=>{
    try{
    const {title,description,tag}=req.body;
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }
    const note=new Notes({
        title,description,tag,user:req.user.id
    })
    const savedNote=await note.save();
    res.json(savedNote);
}catch(error){
    console.log(error.message);
    res.status(500).send("Internal server error");
}
})

//Route 3: Update an existing note using: PUT "/api/notes/updatenote", Login required
router.put('/updatenote/:id',fetchuser, async(req,res)=>{
    try{
    const {title,description,tag}=req.body;
    const newNote={};
    if(title){newNote.title=title};
    if(description){newNote.description=description};
    if(tag){newNote.tag=tag};
    let note=await Notes.findById(req.params.id);
    if(!note){return res.status(404).send("Not Found")};
    if(note.user.toString()!=req.user.id){
        return res.status(401).send("Not Allowed");
    }
    note=await Notes.findByIdAndUpdate(req.params.id,{$set:newNote},{new:true})
    res.json({newNote});
}catch(error){
    console.log(error.message);
    res.status(500).send("Internal server error");
}
})

//Route 3: Update an existing note using: PUT "/api/notes/updatenote", Login required
router.delete('/deletenote/:id',fetchuser, async(req,res)=>{
    try{
    const {title,description,tag}=req.body;
    const newNote={};
    if(title){newNote.title=title};
    if(description){newNote.description=description};
    if(tag){newNote.tag=tag};
    let note=await Notes.findById(req.params.id);
    if(!note){return res.status(404).send("Not Found")};
    if(note.user.toString()!=req.user.id){
        return res.status(401).send("Not Allowed");
    }
    note=await Notes.findByIdAndDelete(req.params.id)
    res.json({"Success": "Note has been deleted",note:note})
}catch(error){
    console.log(error.message);
    res.status(500).send("Internal server error");
}
})
module.exports=router;