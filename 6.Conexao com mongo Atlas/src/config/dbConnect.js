import mongoose, { mongo } from "mongoose";

//recebe a nossa string de conexão via variavel de ambiente 
async function conectaNaDatabase() {
  //mongoose.connect(process.env.DB_CONNECTION_STRING);
   mongoose.connect("mongodb+srv://admin:admin123@cluster0.dw7ez.mongodb.net/livraria?retryWrites=true&w=majority&appName=Cluster0  ");
    return mongoose.connection;
  };
  
  export default conectaNaDatabase;

//esta classe foi criada para ficar com a string de conexao