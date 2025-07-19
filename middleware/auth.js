const jwt = require('jsonwebtoken');
const pool = require('../db'); // Importar la conexión a la base de datos

const SECRET_KEY = process.env.JWT_SECRET || 'mi_clave_ultra_segura';

const authenticateToken = async (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  // Verificar si se proporcionó un token
  if (!token) {
    return res.status(401).json({ mensaje: 'Token requerido' });
  }

  try {
    // Verificar el token
    const user = jwt.verify(token, SECRET_KEY);

    // Verificar si el usuario existe y está activo
    const result = await pool.query('SELECT estado FROM usuarios WHERE id_usuario = $1', [user.id_usuario]);
    if (result.rows.length === 0 || !result.rows[0].estado) {
      return res.status(403).json({ mensaje: 'Usuario no encontrado o inactivo' });
    }

    // Opcional: Verificar si el módulo en el token coincide con el solicitado
    if (req.body.id_modulo && user.id_modulo && user.id_modulo !== req.body.id_modulo) {
      return res.status(403).json({ mensaje: 'Acceso denegado: módulo no permitido' });
    }

    // Almacenar el usuario en req para las rutas posteriores
    req.usuario = user;
    next();
  } catch (err) {
    console.error('Error en autenticación:', err.message);
    return res.status(403).json({ mensaje: 'Token inválido o expirado' });
  }
};

module.exports = authenticateToken;