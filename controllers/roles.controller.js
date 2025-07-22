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
// Obtener todos los roles
// ========================
const getAllRoles = async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM roles');
    const token = extraerToken(req);
    const usuarioAutenticado = req.usuario || decodificarToken(token);

    await registrarAuditoria({
      accion: 'SELECT',
      modulo: 'seguridad',
      tabla: 'roles',
      id_usuario: usuarioAutenticado?.id_usuario || null,
      details: {
        consulta: 'SELECT * FROM roles',
        token: token || 'Sin token',
        usuario_autenticado: usuarioAutenticado?.usuario || 'Sin usuario autenticado'
      },
      nombre_rol: usuarioAutenticado?.nombre_rol || 'Sistema'
    });

    res.json({ data: result.rows, id_usuario_autenticado: usuarioAutenticado?.id_usuario || null });
  } catch (err) {
    console.error('Error en getAllRoles:', err);
    res.status(500).json({ mensaje: 'Error del servidor', error: err.message });
  }
};

// ========================
// Obtener rol por ID
// ========================
const getRolById = async (req, res) => {
  const { id } = req.params;
  try {
    const result = await pool.query('SELECT * FROM roles WHERE id_rol = $1', [id]);
    if (result.rows.length === 0) {
      return res.status(404).json({ mensaje: 'Rol no encontrado' });
    }
    const token = extraerToken(req);
    const usuarioAutenticado = req.usuario || decodificarToken(token);

    await registrarAuditoria({
      accion: 'SELECT',
      modulo: 'seguridad',
      tabla: 'roles',
      id_usuario: usuarioAutenticado?.id_usuario || null,
      details: {
        consulta: 'SELECT * FROM roles WHERE id_rol = $1',
        parametros: [id],
        token: token || 'Sin token',
        usuario_autenticado: usuarioAutenticado?.usuario || 'Sin usuario autenticado'
      },
      nombre_rol: usuarioAutenticado?.nombre_rol || 'Sistema'
    });

    res.json({ data: result.rows[0], id_usuario_autenticado: usuarioAutenticado?.id_usuario || null });
  } catch (err) {
    console.error('Error en getRolById:', err);
    res.status(500).json({ mensaje: 'Error del servidor', error: err.message });
  }
};

// ========================
// Crear rol
// ========================
const createRol = async (req, res) => {
  const { nombre_rol, descripcion, estado } = req.body;
  try {
    const result = await pool.query(
      'INSERT INTO roles (nombre_rol, descripcion, estado) VALUES ($1, $2, $3) RETURNING *',
      [nombre_rol, descripcion, estado ?? true]
    );
    const token = extraerToken(req);
    const usuarioAutenticado = req.usuario || decodificarToken(token);

    await registrarAuditoria({
      accion: 'INSERT',
      modulo: 'seguridad',
      tabla: 'roles',
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
    console.error('Error en createRol:', err);
    res.status(500).json({ mensaje: 'Error del servidor', error: err.message });
  }
};

// ========================
// Actualizar rol
// ========================
const updateRol = async (req, res) => {
  const { id } = req.params;
  const { nombre_rol, descripcion, estado } = req.body;
  try {
    const result = await pool.query(
      'UPDATE roles SET nombre_rol = $1, descripcion = $2, estado = $3 WHERE id_rol = $4 RETURNING *',
      [nombre_rol, descripcion, estado, id]
    );
    if (result.rows.length === 0) {
      return res.status(404).json({ mensaje: 'Rol no encontrado' });
    }
    const token = extraerToken(req);
    const usuarioAutenticado = req.usuario || decodificarToken(token);

    await registrarAuditoria({
      accion: 'UPDATE',
      modulo: 'seguridad',
      tabla: 'roles',
      id_usuario: usuarioAutenticado?.id_usuario || null,
      details: {
        ...result.rows[0],
        token: token || 'Sin token',
        usuario_autenticado: usuarioAutenticado?.usuario || 'Sin usuario autenticado'
      },
      nombre_rol: usuarioAutenticado?.nombre_rol || 'Sistema'
    });

    res.json({ data: result.rows[0], id_usuario_autenticado: usuarioAutenticado?.id_usuario || null });
  } catch (err) {
    console.error('Error en updateRol:', err);
    res.status(500).json({ mensaje: 'Error del servidor', error: err.message });
  }
};

// ========================
// Eliminar rol
// ========================
const deleteRol = async (req, res) => {
  const { id } = req.params;
  try {
    const result = await pool.query(
      'DELETE FROM roles WHERE id_rol = $1 RETURNING *',
      [id]
    );
    if (result.rows.length === 0) {
      return res.status(404).json({ mensaje: 'Rol no encontrado' });
    }
    const token = extraerToken(req);
    const usuarioAutenticado = req.usuario || decodificarToken(token);

    await registrarAuditoria({
      accion: 'DELETE',
      modulo: 'seguridad',
      tabla: 'roles',
      id_usuario: usuarioAutenticado?.id_usuario || null,
      details: {
        ...result.rows[0],
        token: token || 'Sin token',
        usuario_autenticado: usuarioAutenticado?.usuario || 'Sin usuario autenticado'
      },
      nombre_rol: usuarioAutenticado?.nombre_rol || 'Sistema'
    });

    res.json({ mensaje: 'Rol eliminado correctamente', id_usuario_autenticado: usuarioAutenticado?.id_usuario || null });
  } catch (err) {
    console.error('Error en deleteRol:', err);
    res.status(500).json({ mensaje: 'Error del servidor', error: err.message });
  }
};

module.exports = {
  getAllRoles,
  getRolById,
  createRol,
  updateRol,
  deleteRol,
  autenticarToken
};