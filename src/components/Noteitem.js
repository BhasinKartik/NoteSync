import {React,useContext} from 'react'
import NoteContext from '../context/notes/NoteContext';
const Noteitem = (props) => {
    const {note,updateNote,showAlert}=props;
    const context=useContext(NoteContext);
  const {deleteNote}=context;
  return (
    <div className="col-md-3">
      <div className="card my-3">
  <div className="card-body">
    <h5 className="card-title">{note.title}</h5>
    <p className="card-text">{note.description}</p>
  </div>
  <div className="row-md-3">
  <button type="submit" className="btn btn-dark mx-2 my-2" onClick={()=>{deleteNote(note._id);showAlert("Note deleted successfully!","success");}}>Delete</button>
  <button type="submit" className="btn btn-dark mx-2 my-2" onClick={()=>{updateNote(note)}}>Edit</button>
  </div>
</div>
    </div>
  )
}

export default Noteitem
