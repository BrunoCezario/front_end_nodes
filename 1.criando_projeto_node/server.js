import http from "http";

const rotas = {
    "/": "Curso de programacao 5 da Jala UNiversity",
    "/alunos": "Entrei na rota de alunos",
    "/professores": "Entrei na rota de professores"
}

const PORTA = 3000;

const server = http.createServer((req, res) => {
    res.writeHead(200, { "Content-type": "text/plain" });
    res.end(rotas[req.url]);
})

server.listen(PORTA, () => {
    console.log("servidor executando");
});