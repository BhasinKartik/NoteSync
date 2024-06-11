import React, { useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
const Login = (props) => {
    const [credentials,setCredentials]=useState({email:"",password:""});
    let navigate = useNavigate();
    const host= "https://backend-ns-1-01.onrender.com";
    const onChange=(e)=>{
        setCredentials({...credentials,[e.target.name]:e.target.value});
            }
    const handleSubmit=async(e)=>{
    e.preventDefault();
    const response=await fetch(`${host}/api/auth/login`,{
    method:'POST',
    headers:{
        'Content-Type':'application/json',
    },
    body:JSON.stringify({email:credentials.email,password:credentials.password})
})
const json=await response.json();
    if(json.success){
        localStorage.setItem('token',json.authtoken);
        // history.push("/");
        navigate('/');
    props.showAlert("Logged in successfully","success");
        console.log(json.success,json.authtoken);
    }
    else props.showAlert("Invalid Credentials","danger");
}
  return (
    <div>
       <div className="my-4">
         <h1>Login</h1>
         </div>
      <form onSubmit={handleSubmit}>
  <div className="mb-3">
    <label htmlFor="email" className="htmlForm-label">Email address</label>
    <input type="email" className="form-control" value={credentials.email}id="email" name="email" onChange={onChange}aria-describedby="emailHelp"/>
  </div>
  <div className="mb-3">
    <label htmlFor="Password" className="form-label">Password</label>
    <input type="password" className="form-control" value={credentials.password} id="password" name="password" onChange={onChange}/>
  </div>
  <button type="submit" className="btn btn-primary">Submit</button>
</form>
<h4 className="my-3">Don't have an account?</h4>
<Link className="btn btn-success mx-2" to="/signup" role="button">Sign up</Link>
    </div>
  )
}

export default Login
