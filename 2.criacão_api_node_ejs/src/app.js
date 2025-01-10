import express from "express";

const app = express();
app.use(express.json());
app.set("view engine","ejs")
app.use(express.urlencoded({ extended: true }));

const materias = [
  {
    id: 1,
    nome: "NODEJS"
   },
  {
    id: 2,
    nome: "C#"
  },
  {
    id: 3,
    nome: "INTRODUÇÃO A COMPUTAÇÃO"
  },
  {
    id: 4,
    nome: "REVISÃO DE JAVA SCRIPT"
  }
]


//exibir valor em um input 
// app.get("/home", (req, res) => {
//   const valor = livros.join('\n'); 
//   res.render("home",{valor});
// });

//exibir a lista de objetos no página home
app.get("/home", (req, res) => {
  const texto = materias.map(item => `Id: ${item.id}\n
  Título: ${item.nome}`).join('\n');  
  res.render("home",{texto});
});

//Chama a página principal
app.get("/", (req, res) => {
  res.render('formulario'); 
});

app.post('/submit', (req, res) => {
  const { nome, endereco, documento } = req.body; 
  // Pega os valores dos campos inseridos
  res.render('resposta', { nome, endereco, documento }); 
  // Passa os valores para a página de resultado
});


export default app;
