const mongoose=require('mongoose')
const connectToMongo = async () => {
    try {
    //   mongoose.set("strictQuery", false)/;
      mongoose.connect(process.env.mongoURI);
      console.log("Connected to Mongo Cluster Successfully!");
    } catch (error) {
      console.log(error);
    }
  };
module.exports=connectToMongo;