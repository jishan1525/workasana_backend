const mongoose = require("mongoose");

let cached = global.mongoose;

if (!cached) {
  cached = global.mongoose = { conn: null, promise: null };
}

async function intializeDatabase() {
  const mongoUrl = process.env.MONGODB;

  if (!mongoUrl) {
    throw new Error("MONGODB env variable is missing on the server");
  }

  // Already connected
  if (cached.conn) return cached.conn;

  // Create a single shared connection promise
  if (!cached.promise) {
    cached.promise = mongoose
      .connect(mongoUrl, {
        serverSelectionTimeoutMS: 20000, // give cold starts more time
      })
      .then((mongooseInstance) => mongooseInstance);
  }

  cached.conn = await cached.promise;
  console.log("Connected to Database");
  return cached.conn;
}

module.exports = { intializeDatabase };