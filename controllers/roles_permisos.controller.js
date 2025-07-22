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
// Obtener todos los permisos de un rol
// ========================
const getPermisosByRol = async (req, res) => {
  const { id_rol } = req.params;
  try {
    const result = await pool.query(
      `SELECT p.id_permiso, p.nombre_permiso, p.descripcion, p.url_permiso, p.estado, m.nombre_modulo
       FROM roles_permisos rp
       JOIN permisos p ON rp.id_permiso = p.id_permiso
       JOIN modulos m ON p.id_modulo = m.id_modulo
       WHERE rp.id_rol = $1`,
      [id_rol]
    );
    const token = extraerToken(req);
    const usuarioAutenticado = req.usuario || decodificarToken(token);

    await registrarAuditoria({
      accion: 'SELECT',
      modulo: 'seguridad',
      tabla: 'roles_permisos',
      id_usuario: usuarioAutenticado?.id_usuario || null,
      details: {
        consulta: `SELECT p.id_permiso, p.nombre_permiso, p.descripcion, p.url_permiso, p.estado, m.nombre_modulo FROM roles_permisos rp JOIN permisos p ON rp.id_permiso = p.id_permiso JOIN modulos m ON p.id_modulo = m.id_modulo WHERE rp.id_rol = $1`,
        parametros: [id_rol],
        token: token || 'Sin token',
        usuario_autenticado: usuarioAutenticado?.usuario || 'Sin usuario autenticado'
      },
      nombre_rol: usuarioAutenticado?.nombre_rol || 'Sistema'
    });

    res.json({ data: result.rows, id_usuario_autenticado: usuarioAutenticado?.id_usuario || null });
  } catch (err) {
    console.error('Error en getPermisosByRol:', err);
    res.status(500).json({ mensaje: 'Error del servidor', error: err.message });
  }
};

// ========================
// Asignar un permiso a un rol
// ========================
const addPermisoToRol = async (req, res) => {
  const { id_rol, id_permiso } = req.body;
  try {
    const result = await pool.query(
      'INSERT INTO roles_permisos (id_rol, id_permiso) VALUES ($1, $2) RETURNING *',
      [id_rol, id_permiso]
    );
    const token = extraerToken(req);
    const usuarioAutenticado = req.usuario || decodificarToken(token);

    await registrarAuditoria({
      accion: 'INSERT',
      modulo: 'seguridad',
      tabla: 'roles_permisos',
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
    console.error('Error en addPermisoToRol:', err);
    res.status(500).json({ mensaje: 'Error del servidor', error: err.message });
  }
};

// ========================
// Quitar un permiso de un rol
// ========================
const removePermisoFromRol = async (req, res) => {
  const { id_rol, id_permiso } = req.body;
  try {
    const result = await pool.query(
      'DELETE FROM roles_permisos WHERE id_rol = $1 AND id_permiso = $2 RETURNING *',
      [id_rol, id_permiso]
    );
    if (result.rows.length === 0) {
      return res.status(404).json({ mensaje: 'Relación no encontrada' });
    }
    const token = extraerToken(req);
    const usuarioAutenticado = req.usuario || decodificarToken(token);

    await registrarAuditoria({
      accion: 'DELETE',
      modulo: 'seguridad',
      tabla: 'roles_permisos',
      id_usuario: usuarioAutenticado?.id_usuario || null,
      details: {
        ...result.rows[0],
        token: token || 'Sin token',
        usuario_autenticado: usuarioAutenticado?.usuario || 'Sin usuario autenticado'
      },
      nombre_rol: usuarioAutenticado?.nombre_rol || 'Sistema'
    });

    res.json({ mensaje: 'Permiso quitado del rol', id_usuario_autenticado: usuarioAutenticado?.id_usuario || null });
  } catch (err) {
    console.error('Error en removePermisoFromRol:', err);
    res.status(500).json({ mensaje: 'Error del servidor', error: err.message });
  }
};

// ========================
// Asignar múltiples permisos a un rol
// ========================
const asignarPermisosRol = async (req, res) => {
  const { permisos } = req.body;
  const { id_rol } = req.params;

  if (!Array.isArray(permisos)) {
    return res.status(400).json({ error: 'El campo permisos debe ser un array' });
  }

  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    // Primero eliminamos los permisos actuales del rol
    await client.query('DELETE FROM roles_permisos WHERE id_rol = $1', [id_rol]);

    // Insertamos los nuevos permisos
    for (const id_permiso of permisos) {
      await client.query(
        'INSERT INTO roles_permisos (id_rol, id_permiso) VALUES ($1, $2)',
        [id_rol, id_permiso]
      );
    }

    await client.query('COMMIT');
    const token = extraerToken(req);
    const usuarioAutenticado = req.usuario || decodificarToken(token);

    await registrarAuditoria({
      accion: 'UPDATE',
      modulo: 'seguridad',
      tabla: 'roles_permisos',
      id_usuario: usuarioAutenticado?.id_usuario || null,
      details: {
        id_rol,
        permisos,
        token: token || 'Sin token',
        usuario_autenticado: usuarioAutenticado?.usuario || 'Sin usuario autenticado'
      },
      nombre_rol: usuarioAutenticado?.nombre_rol || 'Sistema'
    });

    res.json({ success: true, message: 'Permisos asignados correctamente', id_usuario_autenticado: usuarioAutenticado?.id_usuario || null });
  } catch (err) {
    await client.query('ROLLBACK');
    console.error('Error al asignar permisos:', err);
    res.status(500).json({ success: false, error: 'Error al asignar permisos', error_details: err.message });
  } finally {
    client.release();
  }
};

module.exports = {
  getPermisosByRol,
  addPermisoToRol,
  removePermisoFromRol,
  asignarPermisosRol,
  autenticarToken
};