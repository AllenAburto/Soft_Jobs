require("dotenv").config();
const express = require("express");
const cors = require("cors");
const morgan = require("morgan");

const { registrarUsuario, obtenerUsuario, verificarCredenciales, generarToken } = require("./controllers");
const { verificarToken } = require("./middlewares");

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json());
app.use(cors());
app.use(morgan("dev"));

app.post("/usuarios", async (req, res) => {
    try {
        const { email, password, rol, lenguaje } = req.body;
        if (!email || !password) {
            return res.status(400).send("Email y contraseña son obligatorios");
        }
        await registrarUsuario(email, password, rol, lenguaje);
        res.status(201).send("Usuario registrado exitosamente");
    } catch (error) {
        console.error(error);
        res.status(500).send(error.message);
    }
});

app.post("/login", async (req, res) => {
    try {
        const { email, password } = req.body;
        const usuario = await verificarCredenciales(email, password);
        const token = generarToken(usuario.email, usuario.rol);
        res.json({ token });
    } catch (error) {
        console.error(error);
        res.status(401).send(error.message);
    }
});

app.get("/usuarios", verificarToken, async (req, res) => {
    try {
        const usuario = await obtenerUsuario(req.user.email);
        res.json(usuario);
    } catch (error) {
        console.error(error);
        res.status(500).send(error.message);
    }
});

app.listen(PORT, () => {
    console.log(`Servidor corriendo en http://localhost:${PORT}`);
});
