// import logo from './logo.svg';
import { useState } from 'react';
import './App.css';
import {
  BrowserRouter as Router,
  Routes,
  Route,
} from "react-router-dom";
import Navbar from './components/Navbar';
import About from './components/About';
import Home from './components/Home';
import Login from './components/Login'
import Signup from './components/Signup'
import NoteState from './context/notes/NoteState';
import Alert from './components/Alert';
function App() {
  const [alert,setAlert]=useState({})
const showAlert=(message,type)=>{
setAlert(
  {
    msg:message,
type:type
  }
)
setTimeout(()=>{
setAlert({msg:"",type:""})
},1000)
}
  return (
    <>
      <Router>
        <Navbar />
        <Alert alert={alert}/>
    <div className="container my-5">
      <NoteState>
        <Routes>
        <Route exact path="/" element={<Home showAlert={showAlert}/>} />
          <Route exact path="/about" element={<About showAlert={showAlert}/>}/>
          <Route exact path="/login" element={<Login showAlert={showAlert}/>} />
          <Route exact path="/signup" element={<Signup showAlert={showAlert}/>}/>
        </Routes>
        </NoteState>
      </div>
      </Router>
    </>
  );
}

export default App;
