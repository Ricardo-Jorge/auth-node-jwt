/* imports */
require("dotenv").config();
const express = require("express");
const mongoose = require("mongoose"); // chamando o pacote para trabalhar com MongoDB
const bcrypt = require("bcrypt"); // Pacote para criptografar passwords
const jwt = require("jsonwebtoken"); //

const app = express(); //Chamar o express em uma const chamada app para iniciar as rotas

//Config JSON response
app.use(express.json());

//Models
const User = require("./models/User");

// Public Route
app.get("/", (req, res) => {
  res.status(200).json({ msg: "Bem vindo a nossa API!" });
});

// Private Route
app.get("/user/:id", checkToken, async (req, res) => {
  const id = req.params.id;

  // check if user exists
  const user = await User.findById(id, "-password");

  if (!user) {
    return res.status(404).json({ msg: "Usuário não encontrado!" });
  }

  res.status(200).json({ user });
});

function checkToken(req, res, next) {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];

  if (!token) {
    return res.status(401).json({ msg: "Acesso negado!" });
  }

  try {
    const secret = process.env.SECRET;

    jwt.verify(token, secret);

    next();
  } catch (err) {
    res.status(400).json({ msg: "Token inválido" });
  }
}

// Register User - Usar o metodo async pq essa ação do sistema vai depender de um tempo de espera por uma resposta do usuario
app.post("/auth/register", async (req, res) => {
  const { name, email, password, confirmPassword } = req.body;

  // validation
  if (!name) {
    return res.status(422).json({ msg: "O nome é obrigatório!" });
  }
  if (!email) {
    return res.status(422).json({ msg: "O e-mail é obrigatório!" });
  }
  if (!password) {
    return res.status(422).json({ msg: "A senha é obrigatória!" });
  }

  if (password !== confirmPassword) {
    return res.status(422).json({ msg: "As senhas não conferem!" });
  }

  // check if user exists
  const userExist = await User.findOne({ email: email });

  if (userExist) {
    return res
      .status(422)
      .json({ msg: "E-mail já existe, utilize outro e-mail!" });
  }

  // Create password
  const salt = await bcrypt.genSalt(12);
  const passwordHash = await bcrypt.hash(password, salt);

  // Create user
  const user = new User({
    name,
    email,
    password: passwordHash,
  });

  try {
    await user.save();
    res.status(201).json({ msg: "Usuário criado com sucesso!" });
  } catch (error) {
    res.status(500).json({
      msg: "Aconteceu um erro no servidor, tente novamente mais tarde!",
    });
  }
});

// Login User
app.post("/auth/login", async (req, res) => {
  const { email, password } = req.body;

  // Validate User
  if (!email) {
    return res.status(422).json({ msg: "O e-mail é obrigatório!" });
  }
  if (!password) {
    return res.status(422).json({ msg: "A senha é obrigatória!" });
  }

  // check if user exists
  const user = await User.findOne({ email: email });

  if (!user) {
    return res.status(404).json({ msg: "Usuário não encontrado!" });
  }

  // check if password match
  const checkPassword = await bcrypt.compare(password, user.password);

  if (!checkPassword) {
    return res.status(422).json({ msg: "Senha inválida!" });
  }

  try {
    const secret = process.env.SECRET;

    const token = jwt.sign(
      {
        id: user._id,
      },
      secret
    );

    res.status(200).json({ msg: "Autenticação realizada com sucesso", token });
  } catch (err) {
    res.status(500).json({
      msg: "Aconteceu um erro no servidor, tente novamente mais tarde!",
    });
  }
});

// Chamar as Credentials definidas no arquivo .env
const dbUser = process.env.DB_USER;
const dbPassword = process.env.DB_PASS;

mongoose
  .connect(
    `mongodb+srv://${dbUser}:${dbPassword}@cluster1.hrfyn.mongodb.net/?retryWrites=true&w=majority&appName=Cluster1`
  ) // Conexão com banco de dados do MongoDb
  .then(() => {
    app.listen(3000); //disponivbilizando o acesso a essa api atrves da porta 3000
    console.log("Conectou ao banco!");
  })
  .catch((err) => console.log(err));
