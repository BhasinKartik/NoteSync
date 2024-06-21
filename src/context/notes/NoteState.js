import NoteContext from './NoteContext';
import {useState} from 'react'
const NoteState=(props)=>{
    const host= "https://backend-ns-1-01.onrender.com";
    const notesInitial=[];

const [notes,setNotes]=useState(notesInitial);

const getNotes=async ()=>{

    const response=await fetch(`${host}/api/notes/fetchallnotes`,{
        method:'GET',
        headers:{
            'Content-Type':'application/json',
            'auth-token':localStorage.getItem('token')
        },
    });
    const json= await response.json();
// console.log(json);
const reversedJson=json;
reversedJson.reverse();
setNotes(reversedJson);
}

const addNote=async (title,description,tag)=>{
    const response=await fetch(`${host}/api/notes/addnote`,{
        method:'POST',
        headers:{
            'Content-Type':'application/json',
            'auth-token':localStorage.getItem('token')
        },
        body:JSON.stringify({title,description,tag})
    })
    const json= await response.json();

    console.log("Adding a new Note");
    const note= json;
//   console.log(json);
    notes.concat(note);
    getNotes();
}
const deleteNote= async (id)=>{
    const response=await fetch(`${host}/api/notes/deletenote/${id}`,{
        method:'DELETE',
        headers:{
            'Content-Type':'application/json',
            'auth-token':localStorage.getItem('token')
        },
    })

// console.log("Deleting note with id:",id);
const newNotes=notes.filter((note)=>{
    return note._id!==id;
})
setNotes(newNotes);
}

const editNote=async (id, title, description, tag)=>{
const response=await fetch(`${host}/api/notes/updatenote/${id}`,{
    method:'PUT',
    headers:{
        'Content-Type':'application/json',
        'auth-token': localStorage.getItem('token')
    },
    body:JSON.stringify({title,description,tag})
})

const newNotes=JSON.parse(JSON.stringify(notes));

for(let index=0;index<newNotes.length;index++){
    const element=newNotes[index];
    if(element._id===id){
        newNotes[index].title=title;
        newNotes[index].description=description;
        newNotes[index].tag=tag;
        break;
    }
}
setNotes(newNotes);
}
    return(    
<NoteContext.Provider value={{notes,addNote,deleteNote,editNote,getNotes}}>
    {props.children}
</NoteContext.Provider>
    )
}
export default NoteState;