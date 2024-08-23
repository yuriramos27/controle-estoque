const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bodyParser = require('body-parser');
const path = require('path');
const session = require('express-session');
const bcrypt = require('bcryptjs');

const app = express();
const db = new sqlite3.Database('database.db');

app.use(bodyParser.urlencoded({ extended: true }));
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

app.use(session({
    secret: 'secret-key',
    resave: false,
    saveUninitialized: true,
}));

// Criação da tabela de usuários e computadores
db.serialize(() => {
    db.run("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT, password TEXT)");
    db.run("CREATE TABLE IF NOT EXISTS computadores (id INTEGER PRIMARY KEY AUTOINCREMENT, marca TEXT, modelo TEXT, especificacoes TEXT, status TEXT,data_aluguel TEXT,data_retorno TEXT)");

});

// Middleware de autenticação
function checkAuth(req, res, next) {
    if (req.session.user) {
        next();
    } else {
        res.redirect('/login');
    }
}

// Rota para a página inicial protegida por autenticação
app.get('/', checkAuth, (req, res) => {
    db.all("SELECT * FROM computadores", (err, rows) => {
        if (err) throw err;
        res.render('index', { computadores: rows });
    });
});

// Rota para o formulário de login
app.get('/login', (req, res) => {
    res.render('login');
});

// Rota para processar o login
app.post('/login', (req, res) => {
    const { username, password } = req.body;
    db.get("SELECT * FROM users WHERE username = ?", [username], (err, user) => {
        if (err) throw err;
        if (user && bcrypt.compareSync(password, user.password)) {
            req.session.user = user;
            res.redirect('/');
        } else {
            res.redirect('/login');
        }
    });
});

// Rota para o logout
app.get('/logout', (req, res) => {
    req.session.destroy();
    res.redirect('/login');
});

// Rota para adicionar um computador (protegida por autenticação)
app.post('/add', checkAuth, (req, res) => {
    const { marca, modelo, especificacoes, status, data_aluguel, data_retorno } = req.body;
    db.run("INSERT INTO computadores (marca, modelo, especificacoes, status, data_aluguel, data_retorno ) VALUES (?, ?, ?, ?, ?, ?)",
        [marca, modelo, especificacoes, status, data_aluguel, data_retorno], (err) => {
            if (err) throw err;
            res.redirect('/');
        });
});

// Rota para excluir um computador (protegida por autenticação)
app.post('/delete/:id', checkAuth, (req, res) => {
    const id = req.params.id;
    db.run("DELETE FROM computadores WHERE id = ?", id, (err) => {
        if (err) throw err;
        res.redirect('/');
    });
});

// Rota para exibir o formulário de edição (protegida por autenticação)
app.get('/edit/:id', checkAuth, (req, res) => {
    const id = req.params.id;
    db.get("SELECT * FROM computadores WHERE id = ?", id, (err, row) => {
        if (err) throw err;
        res.render('edit', { computador: row });
    });
});

// Rota para salvar as alterações (protegida por autenticação)
app.post('/edit/:id', checkAuth, (req, res) => {
    const id = req.params.id;
    const { marca, modelo, especificacoes, status } = req.body;
    db.run("UPDATE computadores SET marca = ?, modelo = ?, especificacoes = ?, status = ?, data_aluguel = ?, data_retorno = ? WHERE id = ?",
        [marca, modelo, especificacoes, status, id], (err) => {
            if (err) throw err;
            res.redirect('/');
        });
});

// Rota para registrar um novo usuário (opcional, pode ser desabilitada em produção)
app.get('/register', (req, res) => {
    res.render('register');
});

app.post('/register', (req, res) => {
    const { username, password } = req.body;
    const hashedPassword = bcrypt.hashSync(password, 10);
    db.run("INSERT INTO users (username, password) VALUES (?, ?)", [username, hashedPassword], (err) => {
        if (err) throw err;
        res.redirect('/login');
    });
});

app.listen(3000, () => {
    console.log('Servidor rodando na porta 3000');
});
