import express from "express";
import conectaNaDatabase from "./config/dbConnect.js";
import livro from "./models/Livro.js";

//o conectaNaDatabase é assincrono por isso precisamos de um await 
const conexao = await conectaNaDatabase();

//evento para tratar o erro e capturar o erro na conexão.
conexao.on("error", (erro) => {
    console.error("erro de conexão", erro);
  });
  
//indicar que a conexão foi iniciada com sucesso.
conexao.once("open", () => {
    console.log("Conexao com o banco feita com sucesso");
  })


const app = express();
app.use(express.json());
//app.set("view engine","ejs")

//pagina inicial
app.get("/", (req, res) => {
  res.status(200).send("Curso de Node.js");
});

//buscar todos os livros
app.get("/livros", async (req, res) => {
    const listaLivros = await livro.find({})
  res.status(200).json(listaLivros);
});

//bsucar livro pelo id 
app.get("/livros/:id", (req, res) => {
  const index = buscaLivro(req.params.id);
  res.status(200).json(livros[index]);
})

//cadastrar livro 
app.post("/livros", async (req, res) => {
    try {
        const novoLivro = await livro.create(req.body);
        res.status(201).json({ message: "criado com sucesso", livro: novoLivro });
      } catch (erro) {
        res.status(500).json({ message: `${erro.message} - falha ao cadastrar livro` });
      }
 // res.status(201).send("livro cadastrado com sucesso");
 // res.status(200).json(livros);
});



//recebe parametros na chamada - put para edição 
//editar titulo do livro
app.put("/livros/:id", (req, res) => {
  const index = buscaLivro(req.params.id);
  livros[index].titulo = req.body.titulo;
  res.status(200).json(livros);
});

//apagar o livro
app.delete("/livros/:id", (req, res) => {
  const index = buscaLivro(req.params.id);
  livros.splice(index, 1);
  res.status(200).send("livro removido com sucesso");
});


export default app;
