import React,{useContext,useState,useEffect,useRef} from 'react'
import NoteContext from '../context/notes/NoteContext';
import Noteitem from './Noteitem'
import AddNote from './AddNote'
import { useNavigate } from 'react-router-dom';


const Notes = (props) => {
  const {showAlert}=props;
    const context=useContext(NoteContext);
  const {notes,getNotes,editNote}=context;
  let notes_r=notes;
  notes_r.reverse();

  let navigate = useNavigate();
  useEffect(()=>{
    if(localStorage.getItem('token')){
      getNotes();
    }
    else {
      navigate('/login');
    }
    //eslint-disable-next-line
  },[])


  const ref=useRef(null);
  const refClose=useRef(null);

  const updateNote=(currentNote)=>{
    ref.current.click();
    console.log("clicked edit");
    setNote({id:currentNote._id, etitle:currentNote.title, edescription: currentNote.description, etag:currentNote.tag});
  }

  const [note,setNote]=useState({id:"", etitle:"",edescription:"",etag:""});

  const onChange=(e)=>{
    setNote({...note,[e.target.name]:e.target.value})
  }
  const handleClick=(e)=>{
    e.preventDefault();
    editNote(note.id, note.etitle, note.edescription, note.etag);
    refClose.current.click();
    showAlert("Note updated successfully!","success");
    console.log("updating the note:",note)
  }
  return (
  <>
    <AddNote showAlert={showAlert}/>

    <div className="row md-3 my-3">
<button ref={ref} type="button" className="btn btn-primary d-none" data-bs-toggle="modal" data-bs-target="#exampleModal">
</button>
<div className="modal fade" id="exampleModal" tabIndex="-1" aria-labelledby="exampleModalLabel" aria-hidden="true">
  <div className="modal-dialog">
    <div className="modal-content">
      <div className="modal-header">
        <h5 className="modal-title" id="exampleModalLabel">Modal title</h5>
        <button type="button" className="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
      </div>
      <div className="modal-body">
      <form>
  <div className="form-group my-2">
    <label htmlFor="title">Title</label>
    <input type="text" className="form-control" id="etitle"name="etitle" value={note.etitle}onChange={onChange}/>
  </div>
  <div className="form-group my-2">
    <label htmlFor="description">Description</label>
    <input type="text" className="form-control" id="edescription" name="edescription" value={note.edescription} onChange={onChange}/>
  </div>
  <div className="form-group my-2">
    <label htmlFor="tag">Tag</label>
    <input type="text" className="form-control" id="etag" name="etag" value={note.etag} onChange={onChange}/>
  </div>
</form>
      </div>
      <div className="modal-footer">
        <button ref={refClose} type="button" className="btn btn-secondary" data-bs-dismiss="modal">Close</button>
        <button disabled={note.etitle.length<3 || note.edescription.length<4} onClick={handleClick}type="button" className="btn btn-primary">Update Note</button>
      </div>
    </div>
  </div>
</div>
<div className="container my-1"></div>
      <h1>Your Notes</h1>
      {notes.length===0 && 'No Notes to display'}
      {notes.map((note)=>{
        return <Noteitem key={note._id} updateNote={updateNote} note={note} showAlert={showAlert}/>;
      })}
    </div>
    </>
  )
  
}

export default Notes
