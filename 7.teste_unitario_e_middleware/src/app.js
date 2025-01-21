import express from "express";
import conectaNaDataBase from "./config/dbConnect.js";
import livro from "./models/Livro.js";

const conexao = await conectaNaDataBase();

conexao.on("error", (erro) => {
    console.log("erro da conexão", erro);
})

conexao.once("open", () => {
    console.log("Conexão com o banco de dados feita com sucesso.");
})


const logger = async (req, res, next) => {
    console.log(req.path);
    next();
};

const autorizacao = async (req, res, next) => {
    if (!req.headers.authorization) {
        return res.send(401, "Não autorizado");
    }
    req.userId = 1;
    next();
}


const app = express();
app.use(express.json());
app.use(logger);
app.use(autorizacao);

app.get("/teste", async (req, res) => {
    res.send("teste do sistema");
});

app.get("/usuarios", async (req, res) => {
    console.log(req.usrerId);
    res.send("Testando Acesso De Usuário");
});

/////////////////////////////////////////

app.get("/", (req, res,) => {
    res.status(200).send("Programação 5 em node.js");
})

app.get("/livros", async (req, res) => {
    const lista = await livro.find({});
    res.status(200).json(lista)
});

app.post("/add-livro", async (req, res) => {
    try {
        const novoLivro = await livro.create(req.body);
        res.status(200).json({ message: "Criado com sucesso", livro: novoLivro });

    } catch (error) {
        res.status(500).json({ message: `${erro.message} - falha ao cadastrar livro` });
    }
    //res.status(201).send("livro cradastrado com sucesso.");
});

app.use((req, res, next) => {

    console.log('Hora:', Date.now())
    next();
})



export default app;


