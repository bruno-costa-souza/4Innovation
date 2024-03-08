const express = require('express')
const session = require('express-session')
const cors = require('cors')
const mysql = require('mysql');
const app = express()
const port = 3006
const crypto = require('crypto');
const { body, validationResult } = require('express-validator');

app.use(session({
    secret: crypto.randomBytes(16).toString('hex'),
    resave: true,
    saveUninitialized: true,
    cookie: { maxAge: 3600000 }
}));

app.use(express.json({limit: '5000mb'}))
app.use(cors())
app.listen(port, () => {
    console.log('Iniciado')
})

const db = mysql.createConnection({
    host: 'localhost',
    user: 'root',
    password: '',
    database: 'login'
})

app.use('/', express.static('../frontend'));
const ejs = require('ejs')
app.engine('html', ejs.renderFile);
app.engine('js', ejs.renderFile);
app.set('views', '../frontend/');
app.use(express.urlencoded({ extended: true }));

app.post('/registro', function (req, res) {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
  }
  let data = req.body;
  if (!data.user || data.user.trim() === '') { 
    return res.status(400).json({ message: "Falha! Nome de usuário em branco" });
  }
  if (!data.password || data.password.trim() === '') { 
      return res.status(400).json({ message: "Falha! Senha em branco" });
  }
  if (data) {
      db.query('SELECT COUNT(*) AS count FROM logins WHERE user = ?', [data.user], (selectError, selectResults) => {
          if (selectError) {
              return res.status(500).json({ error: "Erro interno do servidor" });
          }
          if (selectResults[0].count > 0) {
              return res.status(409).json({ message: "Usuário já existe" });
          } else {
              db.query('INSERT INTO logins (user, password) VALUES (?, ?)', [data.user, data.password], (insertError, insertResults) => {
                  if (insertError) {
                      return res.status(500).json({ error: "Erro interno do servidor" });
                  }
                    if (insertResults.affectedRows > 0) {
                        return res.status(200).json({ message: "Registro bem-sucedido" });
                    } else {
                        return res.status(401).json({ message: "Credenciais inválidas" });
                  }
              });
          }
      });
  }
});

function requireLogin(req, res, next) {
    if (req.session && req.session.user) {
        return next();
    } else {
        return res.status(401).json({ message: "Você não está autenticado" });
    }
}

app.get("/dashboard", requireLogin, (req, res) => {
    res.render("dashboard.html");
});

app.post('/login', function (req, res) {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }
    let data = req.body;
    if (data) {
      db.query('SELECT * FROM logins WHERE user = ? AND password = ?', [data.user, data.password], (error, results) => {
        if (error) {
          return res.status(500).json({ error: "Erro interno do servidor" });
        }
        if (results.length > 0) {
            req.session.user = data.user;
          return res.status(200).json({ message: "Login bem-sucedido" });
        } else {
          return res.status(401).json({ message: "Credenciais inválidas" });
        }
      });
    }
});

app.post('/cadastrados',function(req,res){
    db.query('SELECT user FROM logins ',[],(error,results) => {
        if (error) {
            console.error('Erro ao buscar assinaturas:', error);
            res.status(500).send('Erro ao buscar assinaturas');
        } else {
            res.status(200).send(results); 
        }
    })
})

app.post('/deletar', function (req, res) {
  let data = req.body;
  if (data) {
      db.query('DELETE FROM logins WHERE user = ?', [data.user], (error, results) => {
          if (error) {
              console.error('Erro ao deletar usuário:', error);
              return res.status(500).json({ error: "Erro interno do servidor ao deletar usuário" });
          } else {
              if (results.affectedRows > 0) {
                  return res.status(200).json({ message: `Usuário ${data.user} foi deletado ` });
              } else {
                  return res.status(404).json({ message: `Usuário ${data.user} não encontrado` });
              }
          }
      });
  } else {
      return res.status(400).json({ message: "Dados inválidos" });
  }
});

app.post('/update', function (req, res) {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }
    let data = req.body;
    if (!data.password || data.password.trim() === '') { 
      return res.status(400).json({ message: "Falha! Senha em branco" });
    }
    if (data) {
      db.query('UPDATE logins SET password = ? WHERE user = ?', [data.password, data.user], (error, results) => {
        if (error) {
          return res.status(500).json({ error: "Erro interno do servidor" });
        }
        if (results.affectedRows > 0) {
          return res.status(200).json({ message: "Senha atualizada com sucesso" });
        } else {
          return res.status(404).json({ message: "Usuário não encontrado" });
        }
      });
    }
});

db.connect((err) => {
    if (err) {
      console.error('Erro ao conectar ao banco de dados:', err);
    } else {
      console.log('Conectado ao banco de dados.');
    }
});
