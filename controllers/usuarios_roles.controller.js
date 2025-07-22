const pool = require('../db');
const { registrarAuditoria } = require('../controllers/auditoria.controller');
const jwt = require('jsonwebtoken');

const SECRET_KEY = process.env.JWT_SECRET || 'mi_clave_ultra_segura';

// Helper para obtener el token del header
function extraerToken(req) {
  const authHeader = req.headers.authorization;
  console.log('Header authorization:', authHeader); // Depuración
  if (!authHeader || !authHeader.startsWith('Bearer ')) return null;
  return authHeader.split(' ')[1];
}

// Helper para decodificar el token manualmente
function decodificarToken(token) {
  try {
    return token ? jwt.verify(token, SECRET_KEY) : null;
  } catch (error) {
    console.error('Error al decodificar token:', error.message);
    return null;
  }
}

// Middleware para autenticar token
const autenticarToken = (req, res, next) => {
  const token = extraerToken(req);
  if (!token) return res.status(401).json({ mensaje: 'Token no proporcionado' });

  try {
    const decoded = jwt.verify(token, SECRET_KEY);
    req.usuario = decoded; // Asigna el usuario decodificado
    next();
  } catch (error) {
    res.status(401).json({ mensaje: 'Token inválido o expirado', error: error.message });
  }
};

// ========================
// Obtener todos los roles de un usuario
// ========================
const getRolesByUsuario = async (req, res) => {
  const { id_usuario } = req.params;
  try {
    const result = await pool.query(
      `SELECT r.* FROM usuarios_roles ur
       JOIN roles r ON ur.id_rol = r.id_rol
       WHERE ur.id_usuario = $1`,
      [id_usuario]
    );
    const token = extraerToken(req);
    const usuarioAutenticado = req.usuario || decodificarToken(token);

    await registrarAuditoria({
      accion: 'SELECT',
      modulo: 'seguridad',
      tabla: 'usuarios_roles',
      id_usuario: usuarioAutenticado?.id_usuario || null,
      details: {
        consulta: `SELECT r.* FROM usuarios_roles ur JOIN roles r ON ur.id_rol = r.id_rol WHERE ur.id_usuario = $1`,
        parametros: [id_usuario],
        token: token || 'Sin token',
        usuario_autenticado: usuarioAutenticado?.usuario || 'Sin usuario autenticado'
      },
      nombre_rol: usuarioAutenticado?.nombre_rol || 'Sistema'
    });

    res.json({ data: result.rows, id_usuario_autenticado: usuarioAutenticado?.id_usuario || null });
  } catch (err) {
    console.error('Error en getRolesByUsuario:', err);
    res.status(500).json({ mensaje: 'Error del servidor', error: err.message });
  }
};

// ========================
// Asignar un rol a un usuario
// ========================
const addRolToUsuario = async (req, res) => {
  const { id_usuario, id_rol } = req.body;
  try {
    const result = await pool.query(
      'INSERT INTO usuarios_roles (id_usuario, id_rol) VALUES ($1, $2) RETURNING *',
      [id_usuario, id_rol]
    );
    const token = extraerToken(req);
    const usuarioAutenticado = req.usuario || decodificarToken(token);

    await registrarAuditoria({
      accion: 'INSERT',
      modulo: 'seguridad',
      tabla: 'usuarios_roles',
      id_usuario: usuarioAutenticado?.id_usuario || null,
      details: {
        ...result.rows[0],
        token: token || 'Sin token',
        usuario_autenticado: usuarioAutenticado?.usuario || 'Sin usuario autenticado'
      },
      nombre_rol: usuarioAutenticado?.nombre_rol || 'Sistema'
    });

    res.status(201).json({ data: result.rows[0], id_usuario_autenticado: usuarioAutenticado?.id_usuario || null });
  } catch (err) {
    console.error('Error en addRolToUsuario:', err);
    res.status(500).json({ mensaje: 'Error del servidor', error: err.message });
  }
};

// ========================
// Quitar un rol a un usuario
// ========================
const removeRolFromUsuario = async (req, res) => {
  const { id_usuario, id_rol } = req.body;
  try {
    const result = await pool.query(
      'DELETE FROM usuarios_roles WHERE id_usuario = $1 AND id_rol = $2 RETURNING *',
      [id_usuario, id_rol]
    );
    if (result.rows.length === 0) {
      return res.status(404).json({ mensaje: 'Relación no encontrada' });
    }
    const token = extraerToken(req);
    const usuarioAutenticado = req.usuario || decodificarToken(token);

    await registrarAuditoria({
      accion: 'DELETE',
      modulo: 'seguridad',
      tabla: 'usuarios_roles',
      id_usuario: usuarioAutenticado?.id_usuario || null,
      details: {
        ...result.rows[0],
        token: token || 'Sin token',
        usuario_autenticado: usuarioAutenticado?.usuario || 'Sin usuario autenticado'
      },
      nombre_rol: usuarioAutenticado?.nombre_rol || 'Sistema'
    });

    res.json({ mensaje: 'Rol quitado del usuario', id_usuario_autenticado: usuarioAutenticado?.id_usuario || null });
  } catch (err) {
    console.error('Error en removeRolFromUsuario:', err);
    res.status(500).json({ mensaje: 'Error del servidor', error: err.message });
  }
};

module.exports = {
  getRolesByUsuario,
  addRolToUsuario,
  removeRolFromUsuario,
  autenticarToken
};