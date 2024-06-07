import React from 'react'
function Alert(props) {
  var AlertType=props.alert.type;
  if(AlertType==="danger")AlertType="Error";
  return (
    <div style={{height:'40px'}}>
      { props.alert && <div className={`alert alert-${props.alert.type} alert-dismissible fade show`} role="alert">
  <strong>{AlertType}</strong> {props.alert.msg}
  {/* <button type="button" className="btn-close" data-bs-dismiss="alert" aria-label="Close"></button> */}
</div>
}
</div>
  )
}
export default Alert;
