import mongoose, {mongo} from "mongoose";

async function conectaNaDataBase(){
//mongoose.connect(process.env.DB_CONNECTION_STRING);
mongoose.connect("mongodb+srv://admin:admin123@cluster0.dw7ez.mongodb.net/livraria?retryWrites=true&w=majority&appName=Cluster0  ");
return mongoose.connection;
}


export default conectaNaDataBase;