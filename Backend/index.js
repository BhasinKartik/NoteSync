const connectToMongo=require('./db');
const express = require('express');
const cors=require('cors');
connectToMongo();

const app = express()
app.use(express.json())
app.use(cors());

const port=5000;
// respond with "hello world" when a GET request is made to the homepage

// app.get('/', (req, res) => {
//   res.send('hello world')
// })

//available routes;
app.use('/api/auth',require('./routes/auth'));
app.use('/api/notes',require('./routes/notes'));


app.listen(port,()=>{
    console.log(`Example app listening at http://localhost:${port}`);
})