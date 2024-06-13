import React,{useState} from 'react'
import { useNavigate } from 'react-router-dom';
const Signup = (props) => {
    const [credentials,setCredentials]=useState({name:"", email:"",password:"",cpassword:""});
    let navigate = useNavigate();
    const host= "https://backend-ns-1-01.onrender.com";
    const onChange=(e)=>{
        setCredentials({...credentials,[e.target.name]:e.target.value});
            }
    const handleSignup=async(e)=>{
    e.preventDefault();
    const {name,email,password,cpassword}=credentials;
    const response=await fetch(`${host}/api/auth/createuser`,{
    method:'POST',
    headers:{
        'Content-Type':'application/json',
    },
    body:JSON.stringify({name:credentials.name, email:credentials.email,password:credentials.password})
    
})
const json=await response.json();
if(cpassword===password){
  if(json.success){
    localStorage.setItem('token',json.authtoken);
    localStorage.setItem('name',json.name);
    
    // history.push("/");
    navigate('/');
    props.showAlert("Account Created successfully","success");
    console.log(json);
}
else props.showAlert("This email already exists!","danger");
}
else props.showAlert("Confirm your password again!","danger");
    
}
  return (
    <div>
       <div className="container my-3"> 
        <h1>Create your own NoteSync Account</h1>
        </div>
       <div>
      <form onSubmit={handleSignup}>
  <div className="mb-3">
    <label htmlFor="email" className="htmlForm-label">Name</label>
    <input type="text" className="form-control" id="name" name="name" onChange={onChange} value={credentials.name} aria-describedby="emailHelp" required/>
  </div>
  <div className="mb-3">
    <label htmlFor="email" className="htmlForm-label">Email</label>
    <input type="email" className="form-control" id="email" name="email" value={credentials.email} onChange={onChange}aria-describedby="emailHelp" required/>
  </div>
  <div className="mb-3">
    <label htmlFor="Password" className="form-label">Password</label>
    <input type="password" className="form-control" id="password" name="password" value={credentials.password} onChange={onChange} required/>
  </div>
  <div className="mb-3">
    <label htmlFor="cpassword" className="form-label">Confirm Password</label>
    <input type="password" className="form-control" id="cpassword" name="cpassword" value={credentials.cpassword} onChange={onChange}/>
  </div>
  <button type="submit" className="btn btn-primary">Submit</button>
</form>
    </div>
    </div>
  )
}

export default Signup
