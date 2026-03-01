const mongoose = require("mongoose");

let isConnected = false;

async function intializeDatabase() {
  const mongoUrl = process.env.MONGODB;

  if (!mongoUrl) {
    throw new Error("MONGODB env variable is missing on the server");
  }

  
  if (isConnected) return;

  try {
    await mongoose.connect(mongoUrl, {
      serverSelectionTimeoutMS: 10000,
    });

    isConnected = true;
    console.log("Connected to Database");
  } catch (err) {
    console.error("MongoDB connection failed:", err.message);
    throw err; 
  }
}

module.exports = { intializeDatabase };