//exemplo test
//it ou test tanto faz 

const request = require('supertest');
//const app = require('../app.js');
function sum(a, b) {
    return a + b;
}


describe("Testes para o controller xpto teste inicial", () => {
    it("Testando função tttt", () => {
        const Primeiro = 1;
        const segundo = 2;

        let resultado = sum(Primeiro, segundo);
        expect(resultado).toEqual(Primeiro + segundo);
    });


    it("Erro funcao ttt", () => {
        const Primeiro = 1;
        const segundo = 2;

        let resultado = sum(Primeiro, segundo);
        expect(resultado).toEqual(Primeiro + segundo + 7);
    });

    it('Teste da API', async () => {
        const resposta = await request('https://swapi.dev/api/')
            .get('species')
            .expect(200);
        //console.log(resposta.body);
    });

})

