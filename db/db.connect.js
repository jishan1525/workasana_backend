const mongoose = require("mongoose");


require("dotenv").config();
const mongoUrl = process.env.MONGODB;
const intializeDatabase= async() => {
try{
    await mongoose.connect(mongoUrl).then((()=>{
        console.log("Connected to Database")
    }))
}
catch(error){
    console.log(error)
}
}

module.exports = {intializeDatabase};

