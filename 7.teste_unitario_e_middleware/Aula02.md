# Funcionalidades da Aula 02

1. Middleware de Erros e Tratamento de Erros
2. Autenticação e Autorização
3. Logs - Winston e Morgan
4. Armazenamento de imagens - rota animais

## Middleware de Erros e Tratamento de Erros

Vamos criar um middleware de tratamento de erros genéricos e específicos.

Para enviar um código e mensagem personalizados para o middleware de erros, você pode criar um erro personalizado (como uma classe CustomError) que inclua informações como código, status e mensagem. Dessa forma, você pode capturar esses erros no middleware e responder com as informações personalizadas. Além disso, você pode usar express-async-errors para tratar erros assíncronos de maneira mais simples.

Na pasta utils, crie uma classe chamada CustomError:

```js
// utils/CustomError.js

class CustomError extends Error {
  constructor(message, statusCode, code) {
    super(message);
    this.statusCode = statusCode || 500;
    this.code = code || "INTERNAL_SERVER_ERROR";
  }
}

export default CustomError;
```

Essa classe será usada para criar erros personalizados com código, mensagem e status.

Crie uma pasta chamada middlewares. Agora, você pode criar um middleware de erro para verificar se o erro é uma instância de CustomError e, em caso afirmativo, usar o código, status e mensagem personalizados:

```js
// middlewares/errorHandler.js

import CustomError from "../utils/CustomError.js";

const errorHandler = (err, req, res, next) => {
  // Verifica se o erro é do tipo CustomError
  if (err instanceof CustomError) {
    return res.status(err.statusCode).json({
      code: err.code,
      message: err.message,
    });
  }

  // Caso contrário, é um erro genérico (sem código e mensagem personalizada)
  return res.status(500).json({
    code: "INTERNAL_SERVER_ERROR",
    message: "Erro interno no servidor",
  });
};

export default errorHandler;
```

Instale o pacote **express-async-errors** para lidar com erros assíncronos automaticamente. Isso permite que você use try-catch sem precisar passar o erro manualmente para o middleware.

```bash
npm install express-async-errors
```

No seu app.js ou onde você configurar o Express, basta importar o pacote:

```js
import "express-async-errors";
import express from "express";
import dotenv from "dotenv";
import { connectDatabase } from "./config/database.js";
import abrigoRoutes from "./routes/abrigoRoutes.js";
import animalRoutes from "./routes/animalRoutes.js";
import adotanteRoutes from "./routes/adotanteRoutes.js";
import adocaoRoutes from "./routes/adocaoRoutes.js";
import errorHandler from "./middlewares/errorHandler.js";

dotenv.config();

const app = express();

// Conexão com o banco de dados
connectDatabase();

// Middlewares
app.use(express.json());

// Rotas
app.use("/api/abrigos", abrigoRoutes);
app.use("/api/animais", animalRoutes);
app.use("/api/adotantes", adotanteRoutes);
app.use("/api/adocoes", adocaoRoutes);

// Middleware de erro
app.use(errorHandler);

export default app;
```

Nas controllers e services, faça o tratamento de erros com Try/Catch e o middleware de erros personalizado, segue um exemplo em Abrigo:

```js
//controllers/AbrigoController.js
import { abrigoService } from "../services/AbrigoService.js";
import { successResponse, errorResponse } from "../utils/ApiResponse.js";
import { validateAbrigo } from "../utils/AbrigoValidator.js";

class AbrigoController {
  async listarTodos(req, res, next) {
    try {
      const abrigos = await abrigoService.listarTodos(); // Chamando o serviço
      return successResponse(res, abrigos);
    } catch (error) {
      next(error);
    }
  }

  async obterPorId(req, res, next) {
    try {
      const abrigo = await abrigoService.obterPorId(req.params.id); // Chamando o serviço
      return successResponse(res, abrigo);
    } catch (error) {
      next(error);
    }
  }

  async criar(req, res, next) {
    try {
      validateAbrigo(req.body); // Valida os dados antes de criar
      const abrigo = await abrigoService.criar(req.body); // Chamando o serviço
      return successResponse(res, abrigo, 201);
    } catch (error) {
      next(error);
    }
  }

  async atualizar(req, res, next) {
    try {
      validateAbrigo(req.body); // Valida os dados antes de atualizar
      const abrigo = await abrigoService.atualizar(req.params.id, req.body); // Chamando o serviço
      return successResponse(res, abrigo);
    } catch (error) {
      next(error);
    }
  }

  async excluir(req, res, next) {
    try {
      await abrigoService.excluir(req.params.id); // Chamando o serviço
      return successResponse(res, { message: "Abrigo removido com sucesso" });
    } catch (error) {
      next(error);
    }
  }
}

export const abrigoController = new AbrigoController();
```

```js
//services/AbrigoService.js
import { Abrigo } from "../models/Abrigo.js";
import CustomError from "../utils/CustomError.js";

class AbrigoService {
  async listarTodos() {
    try {
      const abrigos = await Abrigo.find();
      if (!abrigos || abrigos.length === 0) {
        throw new CustomError(
          "Nenhum abrigo encontrado",
          404,
          "LISTAR_ABRIGOS_NAO_ENCONTRADOS"
        );
      }
      return abrigos;
    } catch (error) {
      throw new CustomError(error.message, error.statusCode, error.code);
    }
  }

  async obterPorId(id) {
    try {
      const abrigo = await Abrigo.findById(id);
      console.log("abrigo:", abrigo); // Verifique o valor de abrigo
      if (abrigo == null) {
        throw new CustomError(
          `Erro ao obter abrigo com id ${id}`,
          404,
          "ABRIGO_NAO_ENCONTRADO"
        );
      }
      return abrigo;
    } catch (error) {
      throw new CustomError(error.message, error.statusCode, error.code);
    }
  }

  async criar(dados) {
    try {
      const abrigo = await Abrigo.create(dados);
      return abrigo;
    } catch (error) {
      throw new CustomError(error.message, error.statusCode, error.code);
    }
  }

  async atualizar(id, dados) {
    try {
      const abrigo = await Abrigo.findByIdAndUpdate(id, dados, { new: true });
      if (!abrigo) {
        throw new CustomError(
          "Abrigo não encontrado para atualização",
          404,
          "ABRIGO_NAO_ENCONTRADO"
        );
      }
      return abrigo;
    } catch (error) {
      throw new CustomError(error.message, error.statusCode, error.code);
    }
  }

  async excluir(id) {
    try {
      const abrigo = await Abrigo.findByIdAndDelete(id);
      if (!abrigo) {
        throw new CustomError(
          "Abrigo não encontrado para exclusão",
          404,
          "ABRIGO_NAO_ENCONTRADO"
        );
      }
      return abrigo;
    } catch (error) {
      throw new CustomError(error.message, error.statusCode, error.code);
    }
  }
}

export const abrigoService = new AbrigoService();
```

Por fim, vamos ajustar o arquivo ApiResponse.js para ter um retorno formatado do erro:

```js
export const successResponse = (res, data, status = 200) => {
  return res.status(status).json({ success: true, data });
};

export const errorResponse = (res, message, error = null, status = 500) => {
  return res.status(status).json({
    success: false,
    message,
    statusCode: error.statusCode,
    code: error.code,
  });
};
```

## Autenticação e Autorização

### Estrutura do Banco de Dados

### 1. **Tabela: `usuarios`**

Esta tabela vai armazenar as informações de autenticação e a relação com o tipo de usuário (admin, abrigo, adotante).

| Coluna             | Tipo         | Descrição                                          |
| ------------------ | ------------ | -------------------------------------------------- |
| `id`               | UUID         | Identificador único do usuário.                    |
| `nome`             | VARCHAR(100) | Nome completo do usuário.                          |
| `email`            | VARCHAR(100) | Email único para autenticação.                     |
| `senha`            | VARCHAR(255) | Senha criptografada (usando hashing, como bcrypt). |
| `tipo_usuario`     | VARCHAR(20)  | Tipo de usuário: 'admin', 'abrigo', 'adotante'.    |
| `data_criacao`     | TIMESTAMP    | Data de criação do usuário.                        |
| `data_atualizacao` | TIMESTAMP    | Data de atualização do usuário.                    |
| `abrigo`           | UUID         | Identificador único do abrigo.                     |
| `adotante`         | UUID         | Identificador único do adotante.                   |

---

## Fluxo de Autenticação e Autorização

### 1. **Autenticação**:

- **Login**: O usuário fornece seu **email** e **senha**. A senha será comparada com a senha armazenada na tabela `usuarios` após ser criptografada (por exemplo, com **bcrypt**).
- **Token JWT**: Após o login bem-sucedido, geramos um **JSON Web Token (JWT)** que será usado para autenticar as requisições subsequentes. O JWT conterá as informações do usuário e o tipo de permissão (admin, abrigo, adotante).

### 2. **Autorização**:

- Dependendo do **tipo_usuario** armazenado na tabela `usuarios`, podemos restringir as permissões para cada tipo de usuário:
  - **Admin**: Tem permissões totais (pode cadastrar abrigos e gerenciar tudo).
  - **Abrigo**: Pode cadastrar animais, visualizar e gerenciar apenas os animais que pertencem ao seu abrigo.
  - **Adotante**: Só pode adotar animais, não pode criar ou alterar dados no sistema.

---

## Exemplo de Implementação de Autenticação e Autorização

Rode o comando npm i jsonwebtoken bcrypt

### 1. **Cadastro de Usuário e Autenticação (controllers/AuthController.js)**:

```javascript
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import { Usuario } from "../models/Usuario.js";
import { Abrigo } from "../models/Abrigo.js"; // Importa o modelo Abrigo
import { Adotante } from "../models/Adotante.js"; // Importa o modelo Adotante

class AuthController {
  // Função para registrar um novo usuário
  async cadastrar(req, res) {
    try {
      const { nome, email, senha, tipo_usuario, abrigoId, adotanteId } =
        req.body;

      // Verifica se o usuário já existe
      const usuarioExistente = await Usuario.findOne({ email });
      if (usuarioExistente) {
        return res.status(400).json({ message: "Email já cadastrado" });
      }

      // Criptografa a senha
      const senhaHash = await bcrypt.hash(senha, 10);

      // Criação do usuário
      const usuario = new Usuario({
        nome,
        email,
        senha: senhaHash,
        tipo_usuario,
      });

      // Caso seja um tipo "abrigo", associar o usuário ao abrigo
      if (tipo_usuario === "abrigo" && abrigoId) {
        const abrigo = await Abrigo.findById(abrigoId); // Procura o abrigo pelo ID
        if (!abrigo) {
          return res.status(400).json({ message: "Abrigo não encontrado" });
        }
        usuario.abrigo = abrigoId; // Associa o usuário ao abrigo
      }

      // Caso seja um tipo "adotante", associar o usuário ao adotante
      if (tipo_usuario === "adotante" && adotanteId) {
        const adotante = await Adotante.findById(adotanteId); // Procura o adotante pelo ID
        if (!adotante) {
          return res.status(400).json({ message: "Adotante não encontrado" });
        }
        usuario.adotante = adotanteId; // Associa o usuário ao adotante
      }

      // Salva o usuário
      await usuario.save();

      return res
        .status(201)
        .json({ message: "Usuário cadastrado com sucesso!" });
    } catch (error) {
      return res.status(500).json({ message: error.message });
    }
  }

  // Função para fazer login e gerar o token JWT
  async login(req, res) {
    try {
      const { email, senha } = req.body;

      // Verifica se o usuário existe
      const usuario = await Usuario.findOne({ email });
      if (!usuario) {
        return res.status(401).json({ message: "Email ou senha inválidos" });
      }

      // Verifica a senha
      const senhaValida = await bcrypt.compare(senha, usuario.senha);
      if (!senhaValida) {
        return res.status(401).json({ message: "Email ou senha inválidos" });
      }

      // Gera o token JWT
      const token = jwt.sign(
        { id: usuario.id, tipo_usuario: usuario.tipo_usuario },
        process.env.JWT_SECRET_KEY,
        { expiresIn: "1h" }
      );

      return res.json({ token });
    } catch (error) {
      return res.status(500).json({ message: error.message });
    }
  }
}

export const authController = new AuthController();
```

### 2. **Middlewares de Autenticação e Autorização (middlewares/authMiddleware.js)**:

```js
import jwt from "jsonwebtoken";
import CustomError from "../utils/CustomError.js";

// Middleware para autenticar e verificar a autorização
export const verificarAutenticacao = async (req, res, next) => {
  const { authorization } = req.headers;

  if (!authorization) {
    throw new CustomError("Token não fornecido", 401, "TOKEN_NAO_FORNECIDO");
  }

  try {
    const token = authorization.split(" ")[1]; // Pega o token após "Bearer"
    const decoded = jwt.verify(token, process.env.JWT_SECRET_KEY);

    req.usuario = decoded; // Passa os dados do usuário para a requisição
    next();
  } catch (error) {
    throw new CustomError("Token inválido ou expirado", 401, "TOKEN_INVALIDO");
  }
};

// Middleware para verificar se o usuário é administrador
export const verificarAdmin = async (req, res, next) => {
  if (req.usuario.tipo_usuario !== "admin") {
    throw new CustomError("Acesso não autorizado", 403, "ACESSO_NEGADO");
  }
};

// Middleware para verificar se o usuário é do tipo 'abrigo'
export const verificarAbrigo = async (req, res, next) => {
  if (req.usuario.tipo_usuario === "admin") {
    return next(); // Se for admin, permite o acesso a qualquer rota
  }

  if (req.usuario.tipo_usuario !== "abrigo") {
    throw new CustomError("Acesso não autorizado", 403, "ACESSO_NEGADO");
  }
  next(); // Se for abrigo, permite o acesso à rota
};

// Middleware para verificar se o usuário é do tipo 'adotante'
export const verificarAdotante = async (req, res, next) => {
  if (req.usuario.tipo_usuario === "admin") {
    return next(); // Se for admin, permite o acesso a qualquer rota
  }

  if (req.usuario.tipo_usuario !== "adotante") {
    throw new CustomError("Acesso não autorizado", 403, "ACESSO_NEGADO");
  }
  next(); // Se for adotante, permite o acesso à rota
};
```

### 3. **Coleção Usuario (models/Usuario.js)**:

```js
import mongoose from "mongoose";

const UsuarioSchema = new mongoose.Schema(
  {
    nome: {
      type: String,
      required: true,
      trim: true,
    },
    email: {
      type: String,
      required: true,
      trim: true,
      unique: true,
    },
    senha: {
      type: String,
      required: true,
    },
    tipo_usuario: {
      type: String,
      required: true,
      enum: ["admin", "abrigo", "adotante"], // Define os tipos de usuário permitidos
    },
    // Relacionamento com o Abrigo (para tipo "abrigo")
    abrigo: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "Abrigo", // Relaciona com o modelo Abrigo
    },
    // Relacionamento com o Adotante (para tipo "adotante")
    adotante: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "Adotante", // Relaciona com o modelo Adotante
    },
  },
  {
    timestamps: true,
    collection: "usuarios", // Define explicitamente o nome da coleção no banco de dados
  }
);

export const Usuario = mongoose.model("Usuario", UsuarioSchema);
```

### 4. **Rotas de Autenticação (routes/authRoutes.js)**:

```js
import express from "express";
import { authController } from "../controllers/AuthController.js";

const router = express.Router();

// Rota para registrar um novo usuário
router.post("/cadastro", authController.cadastrar.bind(authController));

// Rota para login de usuário e gerar token JWT
router.post("/login", authController.login.bind(authController));

export default router;
```

### 5. **Autorização nas Rotas (app.js)**:

```js
import "express-async-errors";
import express from "express";
import dotenv from "dotenv";
import { connectDatabase } from "./config/database.js";
import abrigoRoutes from "./routes/abrigoRoutes.js";
import animalRoutes from "./routes/animalRoutes.js";
import adotanteRoutes from "./routes/adotanteRoutes.js";
import adocaoRoutes from "./routes/adocaoRoutes.js";
import authRoutes from "./routes/authRoutes.js";
import errorHandler from "./middlewares/errorHandler.js";
import {
  verificarAbrigo,
  verificarAdmin,
  verificarAdotante,
  verificarAutenticacao,
} from "./middlewares/authMiddleware.js";

dotenv.config();

const app = express();

// Conexão com o banco de dados
connectDatabase();

// Middlewares
app.use(express.json());

// Roteamento com autorização baseada no tipo de usuário
app.use("/api/abrigos", verificarAutenticacao, verificarAbrigo, abrigoRoutes); // Admin tem acesso total às rotas de Abrigo
app.use("/api/animais", verificarAutenticacao, verificarAbrigo, animalRoutes); // Admin tem acesso total às rotas de Animais
app.use(
  "/api/adotantes",
  verificarAutenticacao,
  verificarAdotante,
  adotanteRoutes
); // Adotante só pode acessar rotas de Adotante
app.use("/api/adocoes", verificarAutenticacao, verificarAdmin, adocaoRoutes); // Adotante só pode acessar rotas de Adoção
app.use("/api/auth", authRoutes); // Autenticação pode ser acessada por todos

// Middleware de erro
app.use(errorHandler);

export default app;
```

## Logs

Winston é uma das bibliotecas de log mais populares em Node.js. Ele oferece muitos recursos como suporte a múltiplos transportes (arquivos, console, etc.), diferentes níveis de log e formato customizável.

Morgan é uma biblioteca de log usada principalmente para registrar logs HTTP em aplicativos Express. Ele é simples de configurar e se integra bem com Express para capturar logs de requisições.

**Por que usar ambos?**

Morgan é uma biblioteca especializada em capturar logs de requisições HTTP. Ela fornece uma maneira simples de registrar dados como o método HTTP, o status da resposta, o tempo de resposta, o IP do cliente, entre outras informações úteis para análise de tráfego e monitoramento de APIs.

Winston, por outro lado, é uma solução de logging mais robusta e flexível que pode ser configurada para registrar diferentes tipos de eventos (erros, informações gerais, etc.) em vários destinos, como console, arquivos ou até mesmo bancos de dados. Ele também oferece uma grande flexibilidade quanto ao formato dos logs e à configuração de múltiplos "transportes" (destinos para os logs).

**Vantagens de usar Winston e Morgan juntos**

Logar requisições HTTP com Morgan: Morgan vai automaticamente capturar informações das requisições HTTP, o que é útil para monitoramento do tráfego de sua aplicação e ajuda a detectar erros relacionados a requests.

Logar erros e eventos customizados com Winston: Winston pode ser configurado para logar erros, eventos importantes e dados gerais da aplicação, permitindo uma análise mais detalhada dos problemas e monitoramento do sistema.

Centralização dos logs: Usando Winston como o logger central, você pode configurar o formato, o destino e os níveis dos logs (por exemplo, info, warn, error), enquanto Morgan apenas captura as requisições. A vantagem é que você pode manter todos os logs (requisições HTTP e eventos da aplicação) centralizados e com um formato consistente.

Logs em diferentes destinos: Você pode configurar Winston para gravar logs tanto no console (com console transport) quanto em arquivos (com file transport), enquanto Morgan pode continuar logando no console com um formato mais simples (mas ainda eficiente). Assim, você pode salvar logs de requisições HTTP em arquivos separados ou integrá-los aos logs da aplicação.

Melhor monitoramento: Winston e Morgan juntos podem fornecer uma visão completa da sua aplicação, desde o tráfego de requisições HTTP até os erros e eventos internos. Isso é extremamente útil para diagnósticos e para detectar padrões de problemas.

### Adicionando no Projeto

Instale as duas bibliotecas com `npm install winston morgan`

Vamos configurar o Morgan para capturar logs de requisições HTTP e direcioná-los para o Winston, que irá gerenciar a saída dos logs (por exemplo, no console e em arquivos).

Crie um arquivo na pasta utils chamado de winston.js e adicione o código:

```js
import winston from "winston";

// Configuração do Winston para capturar apenas erros
const logger = winston.createLogger({
  level: "error", // Captura apenas erros (você pode mudar para 'info' ou outro nível, mas queremos focar em erros)
  format: winston.format.combine(
    winston.format.colorize(), // Adiciona cores no console para facilitar leitura
    winston.format.timestamp(), // Adiciona timestamp aos logs
    winston.format.printf(({ timestamp, level, message }) => {
      return `${timestamp} ${level}: ${message}`;
    })
  ),
  transports: [
    new winston.transports.Console(), // Exibe no console
    new winston.transports.File({ filename: "logs/errors.log" }), // Salva os logs de erro em um arquivo
  ],
});

export default logger;
```

Agora ajuste o seu middleware de erros para armazenar isso nos seus logs também:

```js
import logger from "../utils/winston.js"; // Importa o logger Winston

// Middleware para capturar erros
const errorHandler = (err, req, res, next) => {
  // Verifica se o erro é uma instância de CustomError
  if (err.statusCode && err.code) {
    // Se for um CustomError, loga a mensagem de erro
    logger.error(
      `Código: ${err.code}, Mensagem: ${err.message}, Status: ${err.statusCode}`
    );
  } else {
    // Caso não seja um CustomError, loga o erro genérico
    logger.error(`Erro: ${err.message}`);
  }

  // Envia a resposta com o erro para o cliente
  res.status(err.statusCode || 500).json({
    message: err.message || "Erro interno do servidor",
    code: err.code || "INTERNAL_SERVER_ERROR",
  });
};

export default errorHandler;
```

Os logs estão sendo salvos atualmente em uma pasta logs, com um arquivo errors.log.

Para também salvar os logs de erro em uma coleção no MongoDB usando o Mongoose, podemos criar um modelo de log no MongoDB e configurar o Winston para utilizar um transporte personalizado que salva os logs diretamente nessa coleção.

Execute o comando `npm i winston-transport`

Vamos criar um modelo de log usando Mongoose para armazenar os logs no banco de dados. Crie um arquivo em Models, chamado de Logs.js

```js
import mongoose from "mongoose";

const logSchema = new mongoose.Schema(
  {
    message: { type: String, required: true },
    level: { type: String, required: true },
    timestamp: { type: Date, default: Date.now },
    meta: { type: mongoose.Schema.Types.Mixed }, // Para armazenar dados adicionais, se necessário
  },
  {
    collection: "logs", // Nome da coleção no MongoDB onde os logs serão armazenados
  }
);

const Log = mongoose.model("Log", logSchema);

export default Log;
```

Agora, vamos criar um transporte personalizado do Winston para salvar os logs diretamente no MongoDB. Para isso, usaremos o winston-transport e a conexão com o MongoDB.

Crie um arquivo chamado mongoTransport.js (Transporte para MongoDB) em utils.

```js
import TransportStreamOptions from "winston-transport";
import Log from "../models/Logs.js"; // Importa o modelo de Log

class MongoDBTransport extends TransportStreamOptions {
  log(info, callback) {
    // Previne o bloqueio de execução de logs
    setImmediate(() => this.emit("logged", info));

    // Salva o log na coleção do MongoDB
    const log = new Log({
      message: info.message,
      level: info.level,
      timestamp: new Date(),
      meta: info,
    });

    log
      .save()
      .then(() => {
        callback();
      })
      .catch((error) => {
        console.error("Erro ao salvar log no MongoDB:", error);
        callback();
      });
  }
}

export default MongoDBTransport;
```

Agora, vamos configurar o Winston para usar esse transporte personalizado junto com os outros transportes (console e arquivo). Modifique o arquivo winston.js.

```js
import winston from "winston";
import MongoDBTransport from "./mongoTransport.js"; // Transporte para MongoDB

// Função personalizada para formatar o timestamp e os logs
const customFormat = winston.format.printf(({ timestamp, level, message }) => {
  const formattedTimestamp = new Date(timestamp).toLocaleString("pt-BR", {
    timeZone: "UTC",
    day: "2-digit",
    month: "short",
    year: "numeric",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  });

  return `${formattedTimestamp} ${level}: ${message}`;
});

// Criação do logger
const logger = winston.createLogger({
  level: "info", // Inclui logs de nível 'info' e superiores
  format: winston.format.combine(
    winston.format.timestamp(), // Adiciona timestamp como texto
    customFormat // Aplica o formato customizado
  ),
  transports: [
    // Transporte para o console
    new winston.transports.Console({
      format: winston.format.combine(
        winston.format.colorize(), // Adiciona cores ao console
        winston.format.timestamp(),
        customFormat
      ),
    }),
    // Transporte para o arquivo
    new winston.transports.File({
      filename: "logs/combined.log", // Log geral
      format: winston.format.combine(winston.format.timestamp(), customFormat),
    }),
    new winston.transports.File({
      filename: "logs/errors.log", // Apenas logs de erro
      level: "error",
      format: winston.format.combine(winston.format.timestamp(), customFormat),
    }),
    // Transporte para o MongoDB
    new MongoDBTransport({
      format: winston.format.combine(winston.format.timestamp(), customFormat),
    }),
  ],
});

// Stream personalizado para Morgan
logger.stream = {
  write: (message) => {
    logger.info(message.trim()); // Registra logs HTTP como nível 'info'
  },
};

export default logger;
```

E vamos adicionar o Morgan no app.js

```js
import "express-async-errors";
import express from "express";
import dotenv from "dotenv";
import morgan from "morgan";
import logger from "./utils/winston.js"; // Logger configurado
import { connectDatabase } from "./config/database.js";
import abrigoRoutes from "./routes/abrigoRoutes.js";
import animalRoutes from "./routes/animalRoutes.js";
import adotanteRoutes from "./routes/adotanteRoutes.js";
import adocaoRoutes from "./routes/adocaoRoutes.js";
import authRoutes from "./routes/authRoutes.js";
import errorHandler from "./middlewares/errorHandler.js";
import {
  verificarAbrigo,
  verificarAdmin,
  verificarAdotante,
  verificarAutenticacao,
} from "./middlewares/authMiddleware.js";

dotenv.config();

const app = express();

// Middleware para logs HTTP com Morgan
app.use(
  morgan("combined", {
    stream: logger.stream, // Usa o stream configurado no Winston
  })
);

// Conexão com o banco de dados
connectDatabase();

// Middlewares
app.use(express.json());

// Roteamento com autorização baseada no tipo de usuário
app.use("/api/abrigos", verificarAutenticacao, verificarAbrigo, abrigoRoutes);
app.use(
  "/api/animais",
  /*verificarAutenticacao, verificarAbrigo,*/ animalRoutes
);
app.use(
  "/api/adotantes",
  verificarAutenticacao,
  verificarAdotante,
  adotanteRoutes
);
app.use("/api/adocoes", verificarAutenticacao, verificarAdmin, adocaoRoutes);
app.use("/api/auth", authRoutes);

// Middleware de erro
app.use(errorHandler);

export default app;
```

## Armazenamento de Imagens no MongoDB

No MongoDB podemos usar o tipo Buffer no Mongoose, que permite salvar os dados binários das imagens. No entanto, isso não é recomendado para grandes volumes de dados devido a limitações de desempenho no MongoDB.

A estratégia mais comum é salvar a URL das fotos dos animais, que geralmente ficam hospedadas em um servidor de arquivos ou em um serviço de armazenamento em nuvem. Nesse caso, você pode ter um campo fotos no modelo que armazena um array de URLs, permitindo que o animal tenha várias fotos.

Altere o Modelo Animal para Armazenar Imagens como um Array de Strings.

```js
import mongoose from "mongoose";

const AnimalSchema = new mongoose.Schema(
  {
    nome: {
      type: String,
      required: true,
      trim: true,
      maxlength: 100,
    },
    especie: {
      type: String,
      required: true,
      trim: true,
      enum: ["cachorro", "gato"],
    },
    raca: {
      type: String,
      trim: true,
      maxlength: 100,
    },
    idade: {
      type: Number,
      required: true,
      min: 0,
    },
    sexo: {
      type: String,
      required: true,
      enum: ["macho", "fêmea"],
    },
    descricao: {
      type: String,
      trim: true,
      maxlength: 500,
    },
    abrigo_id: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "Abrigo",
      required: true,
    },
    fotos: {
      type: [String], // Array de strings para armazenar os caminhos ou URLs das fotos
      default: [],
    },
  },
  {
    timestamps: true,
    collection: "animais",
  }
);

export const Animal = mongoose.model("Animal", AnimalSchema);
```

Como mencionado, é mais eficiente armazenar as imagens em algum serviço de armazenamento (como Amazon S3) e armazenar apenas as URLs no MongoDB.

Agora que temos o campo para armazenar as fotos, o próximo passo é lidar com o upload das imagens. Aqui está uma solução usando o Multer (um middleware de upload de arquivos para Express).

Primeiro, instale o Multer `npm install multer`

Agora, no seu controller de animais, você pode configurar o Multer para fazer o upload das fotos e buscar as imagens:

```js
import multer from "multer"; // Importa o multer para lidar com o upload de arquivos
import { animalService } from "../services/AnimalService.js";
import { successResponse, errorResponse } from "../utils/ApiResponse.js";
import { validateAnimal } from "../utils/AnimalValidator.js";
import path from "path";

// Configuração do Multer para o upload de fotos
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, "uploads/"); // Diretório onde as imagens serão armazenadas
  },
  filename: (req, file, cb) => {
    cb(null, Date.now() + path.extname(file.originalname)); // Nome único para a imagem
  },
});

// Define o número máximo de arquivos e os tipos permitidos
const upload = multer({
  storage: storage,
  limits: { fileSize: 5 * 1024 * 1024 }, // Tamanho máximo do arquivo (5MB)
  fileFilter: (req, file, cb) => {
    const filetypes = /jpeg|jpg|png|gif/;
    const extname = filetypes.test(
      path.extname(file.originalname).toLowerCase()
    );
    const mimetype = filetypes.test(file.mimetype);
    if (mimetype && extname) {
      return cb(null, true);
    } else {
      cb(new Error("Arquivo inválido. Apenas imagens são permitidas."));
    }
  },
}).array("fotos", 10); // 'fotos' é o campo do formulário, e 10 é o número máximo de arquivos

class AnimalController {
  async listarTodos(req, res) {
    try {
      const animais = await animalService.listarTodos();

      // Cria a URL completa das fotos
      const animaisComFotos = animais.map((animal) => {
        animal.fotos = animal.fotos.map(
          (foto) => `${process.env.BASE_URL}/uploads/${foto}`
        ); // Adiciona a URL correta
        return animal;
      });

      return successResponse(res, animaisComFotos);
    } catch (error) {
      return errorResponse(res, "Erro ao listar animais", error.message);
    }
  }

  async obterPorId(req, res) {
    try {
      const animal = await animalService.obterPorId(req.params.id);
      if (!animal)
        return errorResponse(res, "Animal não encontrado", null, 404);
      return successResponse(res, animal);
    } catch (error) {
      return errorResponse(res, "Erro ao obter animal", error.message);
    }
  }

  async criar(req, res) {
    try {
      upload(req, res, async (err) => {
        if (err) {
          return errorResponse(res, "Erro no upload das fotos", err.message);
        }

        // Valida os dados antes de criar
        validateAnimal(req.body);

        // Adiciona os caminhos das imagens no campo 'fotos'
        const fotos = req.files ? req.files.map((file) => file.filename) : []; // Salva apenas o nome do arquivo

        const animalData = { ...req.body, fotos };

        const animal = await animalService.criar(animalData); // Cria o animal com as fotos
        return successResponse(res, animal, 201);
      });
    } catch (error) {
      return errorResponse(res, "Erro ao criar animal", error.message);
    }
  }

  async atualizar(req, res) {
    try {
      validateAnimal(req.body); // Valida os dados antes de atualizar
      const animal = await animalService.atualizar(req.params.id, req.body);
      if (!animal)
        return errorResponse(res, "Animal não encontrado", null, 404);
      return successResponse(res, animal);
    } catch (error) {
      return errorResponse(res, "Erro ao atualizar animal", error.message);
    }
  }

  async excluir(req, res) {
    try {
      const animal = await animalService.excluir(req.params.id);
      if (!animal)
        return errorResponse(res, "Animal não encontrado", null, 404);
      return successResponse(res, { message: "Animal removido com sucesso" });
    } catch (error) {
      return errorResponse(res, "Erro ao excluir animal", error.message);
    }
  }
}

export const animalController = new AnimalController();
```

Por fim, crie uma pasta uploads na raiz principal para armazenar as fotos.

Ajuste o arquivo app.js para buscar as imagens:

```js
import "express-async-errors";
import express from "express";
import dotenv from "dotenv";
import { connectDatabase } from "./config/database.js";
import abrigoRoutes from "./routes/abrigoRoutes.js";
import animalRoutes from "./routes/animalRoutes.js";
import adotanteRoutes from "./routes/adotanteRoutes.js";
import adocaoRoutes from "./routes/adocaoRoutes.js";
import authRoutes from "./routes/authRoutes.js";
import errorHandler from "./middlewares/errorHandler.js";
import {
  verificarAbrigo,
  verificarAdmin,
  verificarAdotante,
  verificarAutenticacao,
} from "./middlewares/authMiddleware.js";
import path from "path";
import { fileURLToPath } from "url"; // Importa fileURLToPath para trabalhar com ES Modules

dotenv.config();

const app = express();

// Conexão com o banco de dados
connectDatabase();

// Obtém o diretório atual (equivalente ao __dirname no CommonJS)
const __dirname = path.dirname(fileURLToPath(import.meta.url));

// Servir imagens estáticas da pasta 'uploads'
app.use("/uploads", express.static(path.join(__dirname, "../uploads")));

// Middlewares
app.use(express.json());

// Roteamento com autorização baseada no tipo de usuário
app.use("/api/abrigos", verificarAutenticacao, verificarAbrigo, abrigoRoutes);
app.use(
  "/api/animais",
  /*verificarAutenticacao, verificarAbrigo,*/ animalRoutes
);
app.use(
  "/api/adotantes",
  verificarAutenticacao,
  verificarAdotante,
  adotanteRoutes
);
app.use("/api/adocoes", verificarAutenticacao, verificarAdmin, adocaoRoutes);
app.use("/api/auth", authRoutes);

// Middleware de erro
app.use(errorHandler);

export default app;
```

Por fim, no Postman altere a requisição POST para FormData, adicione os campos e seus valores, assim como o campo fotos, com as imagens.

Para buscar a imagem, pegue o caminho do retorno do GET e abra no navegador.
