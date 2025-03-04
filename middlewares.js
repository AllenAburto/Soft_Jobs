const jwt = require("jsonwebtoken");

const verificarToken = (req, res, next) => {
    try {
        const authHeader = req.header("Authorization");
        if (!authHeader || !authHeader.startsWith("Bearer ")) {
            return res.status(401).send("Acceso denegado, token no proporcionado");
        }

        const token = authHeader.split("Bearer ")[1];
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        req.user = decoded;
        next();
    } catch (error) {
        console.error("Error al verificar token:", error.message);
        res.status(401).send("Token inválido o expirado");
    }
};

module.exports = { verificarToken };