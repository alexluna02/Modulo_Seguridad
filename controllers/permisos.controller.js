const pool = require('../db');
const { registrarAuditoria } = require('./auditoria.controller');
const bcrypt = require('bcryptjs');
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
// Obtener todos los permisos
// ========================
const getAllPermisos = async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM permisos ORDER BY id_permiso');
    const token = extraerToken(req);
    const usuarioAutenticado = req.usuario || decodificarToken(token);

    await registrarAuditoria({
      accion: 'SELECT',
      modulo: 'seguridad',
      tabla: 'permisos',
      id_usuario: usuarioAutenticado?.id_usuario || null,
      details: {
        consulta: 'SELECT * FROM permisos ORDER BY id_permiso',
        token: token || 'Sin token',
        usuario_autenticado: usuarioAutenticado?.usuario || 'Sin usuario autenticado'
      },
      nombre_rol: usuarioAutenticado?.nombre_rol || 'Sistema'
    });

    res.json({ data: result.rows, id_usuario_autenticado: usuarioAutenticado?.id_usuario || null });
  } catch (err) {
    console.error('Error en getAllPermisos:', err);
    res.status(500).json({ mensaje: 'Error del servidor', error: err.message });
  }
};

// ========================
// Obtener permiso por ID
// ========================
const getPermisoById = async (req, res) => {
  const { id } = req.params;
  try {
    const result = await pool.query('SELECT * FROM permisos WHERE id_permiso = $1', [id]);
    if (result.rows.length === 0) return res.status(404).json({ mensaje: 'Permiso no encontrado' });
    const token = extraerToken(req);
    const usuarioAutenticado = req.usuario || decodificarToken(token);

    await registrarAuditoria({
      accion: 'SELECT',
      modulo: 'seguridad',
      tabla: 'permisos',
      id_usuario: usuarioAutenticado?.id_usuario || null,
      details: {
        consulta: 'SELECT * FROM permisos WHERE id_permiso = $1',
        parametros: [id],
        token: token || 'Sin token',
        usuario_autenticado: usuarioAutenticado?.usuario || 'Sin usuario autenticado'
      },
      nombre_rol: usuarioAutenticado?.nombre_rol || 'Sistema'
    });

    res.json({ data: result.rows[0], id_usuario_autenticado: usuarioAutenticado?.id_usuario || null });
  } catch (err) {
    console.error('Error en getPermisoById:', err);
    res.status(500).json({ mensaje: 'Error del servidor', error: err.message });
  }
};

// ========================
// Crear permiso
// ========================
const createPermiso = async (req, res) => {
  const { nombre_permiso, descripcion, url_permiso, id_modulo } = req.body;
  if (!nombre_permiso || !url_permiso || !id_modulo) {
    return res.status(400).json({ mensaje: 'Faltan campos obligatorios' });
  }
  try {
    const result = await pool.query(
      'INSERT INTO permisos (nombre_permiso, descripcion, url_permiso, id_modulo) VALUES ($1, $2, $3, $4) RETURNING *',
      [nombre_permiso, descripcion, url_permiso, id_modulo]
    );
    const token = extraerToken(req);
    const usuarioAutenticado = req.usuario || decodificarToken(token);

    await registrarAuditoria({
      accion: 'INSERT',
      modulo: 'seguridad',
      tabla: 'permisos',
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
    console.error('Error en createPermiso:', err);
    res.status(500).json({ mensaje: 'Error del servidor', error: err.message });
  }
};

// ========================
// Actualizar permiso
// ========================
const updatePermiso = async (req, res) => {
  const { id } = req.params;
  const { nombre_permiso, descripcion, url_permiso, id_modulo } = req.body;
  try {
    const result = await pool.query(
      'UPDATE permisos SET nombre_permiso = $1, descripcion = $2, url_permiso = $3, id_modulo = $4 WHERE id_permiso = $5 RETURNING *',
      [nombre_permiso, descripcion, url_permiso, id_modulo, id]
    );
    if (result.rows.length === 0) return res.status(404).json({ mensaje: 'Permiso no encontrado' });
    const token = extraerToken(req);
    const usuarioAutenticado = req.usuario || decodificarToken(token);

    await registrarAuditoria({
      accion: 'UPDATE',
      modulo: 'seguridad',
      tabla: 'permisos',
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
    console.error('Error en updatePermiso:', err);
    res.status(500).json({ mensaje: 'Error del servidor', error: err.message });
  }
};

// ========================
// Eliminar permiso
// ========================
const deletePermiso = async (req, res) => {
  const { id } = req.params;
  try {
    const result = await pool.query(
      'DELETE FROM permisos WHERE id_permiso = $1 RETURNING *',
      [id]
    );
    if (result.rows.length === 0) return res.status(404).json({ mensaje: 'Permiso no encontrado' });
    const token = extraerToken(req);
    const usuarioAutenticado = req.usuario || decodificarToken(token);

    await registrarAuditoria({
      accion: 'DELETE',
      modulo: 'seguridad',
      tabla: 'permisos',
      id_usuario: usuarioAutenticado?.id_usuario || null,
      details: {
        ...result.rows[0],
        token: token || 'Sin token',
        usuario_autenticado: usuarioAutenticado?.usuario || 'Sin usuario autenticado'
      },
      nombre_rol: usuarioAutenticado?.nombre_rol || 'Sistema'
    });

    res.json({ mensaje: 'Permiso eliminado correctamente', id_usuario_autenticado: usuarioAutenticado?.id_usuario || null });
  } catch (err) {
    console.error('Error en deletePermiso:', err);
    res.status(500).json({ mensaje: 'Error del servidor', error: err.message });
  }
};

module.exports = {
  getAllPermisos,
  getPermisoById,
  createPermiso,
  updatePermiso,
  deletePermiso,
  autenticarToken
};