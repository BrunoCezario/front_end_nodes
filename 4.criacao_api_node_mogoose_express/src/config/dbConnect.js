import mongoose, { mongo } from "mongoose";

async function conectaNaDatabase() {
  mongoose.connec(process.env.DB_CONNECTION_STRING);
  return mongoose.connection;
};

export default conectaNaDatabase;
