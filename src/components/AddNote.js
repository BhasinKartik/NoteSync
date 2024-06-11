import React,{useContext,useState} from 'react'
import NoteContext from '../context/notes/NoteContext'
const AddNote = (props) => {
    const context=useContext(NoteContext);
  const {addNote}=context;
  const [note,setNote]=useState({title:"",description:"",tag:""});
  const onChange=(e)=>{
    setNote({...note,[e.target.name]:e.target.value})
  }
  const handleClick=(e)=>{
    e.preventDefault();
        addNote(note.title,note.description,note.tag);
        setNote({title:"",description:"",tag:""})
        props.showAlert("Note added successfully!","success");
  }
  return (
    <div className="notesInput">
        <h1>Add a Note</h1>
       <div className="container">
      <form>
  <div className="form-group my-2">
    <label htmlFor="title">Title</label>
    <input type="text" className="form-control" id="title"name="title"onChange={onChange} value={note.title}/>
  </div>
  <div className="form-group my-2">
    <label htmlFor="description">Description</label>
    <input type="text" className="form-control" id="description" name="description" onChange={onChange} value={note.description}/>
  </div>
  <div className="form-group my-2">
    <label htmlFor="tag">Tag</label>
    <input type="text" className="form-control" id="tag" name="tag" onChange={onChange} value={note.tag}/>
  </div>
  <button disabled={note.title.length<3 || note.description.length<5} type="submit" className="btn btn-primary" onClick={handleClick}>Add</button>
</form>
      </div>
    </div>
  )
}

export default AddNote
