const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const pool = require("./db");
require("dotenv").config(); // Cargar variables de entorno

// 🔹 Registrar usuario con contraseña encriptada
const registrarUsuario = async (email, password, rol, lenguaje) => {
    try {
        if (!email || !password || !rol || !lenguaje) {
            throw new Error("Todos los campos son obligatorios");
        }

        const passwordEncriptada = bcrypt.hashSync(password, 10);
        const query = "INSERT INTO usuarios (email, password, rol, lenguaje) VALUES ($1, $2, $3, $4)";
        const values = [email, passwordEncriptada, rol, lenguaje];

        await pool.query(query, values);
    } catch (error) {
        console.error("Error al registrar usuario:", error.message);
        throw new Error("No se pudo registrar el usuario");
    }
};

// 🔹 Verificar credenciales y comparar contraseñas
const verificarCredenciales = async (email, password) => {
    try {
        if (!email || !password) {
            throw new Error("Email y contraseña son obligatorios");
        }

        const query = "SELECT * FROM usuarios WHERE email = $1";
        const { rows } = await pool.query(query, [email]);

        if (rows.length === 0) {
            throw new Error("Email o contraseña incorrecta");
        }

        const usuario = rows[0];
        const passwordEsCorrecta = bcrypt.compareSync(password, usuario.password);

        if (!passwordEsCorrecta) {
            throw new Error("Email o contraseña incorrecta");
        }

        return usuario;
    } catch (error) {
        console.error("Error al verificar credenciales:", error.message);
        throw new Error("Error al verificar credenciales");
    }
};

// 🔹 Generar token JWT (Ahora incluye el rol)
const generarToken = (email, rol) => {
    try {
        return jwt.sign({ email, rol }, process.env.JWT_SECRET, { expiresIn: "1h" }); // Expira en 1 hora
    } catch (error) {
        console.error("Error al generar token:", error.message);
        throw new Error("No se pudo generar el token");
    }
};

// 🔹 Obtener datos del usuario autenticado
const obtenerUsuario = async (email) => {
    try {
        const query = "SELECT email, rol, lenguaje FROM usuarios WHERE email = $1";
        const { rows } = await pool.query(query, [email]);

        if (rows.length === 0) {
            throw new Error("Usuario no encontrado");
        }

        return rows[0];
    } catch (error) {
        console.error("Error al obtener usuario:", error.message);
        throw new Error("No se pudo obtener el usuario");
    }
};

module.exports = {
    registrarUsuario,
    verificarCredenciales,
    generarToken,
    obtenerUsuario
};