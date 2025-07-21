const pool = require('../db');
const { registrarAuditoria } = require('./auditoria.controller');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const SECRET_KEY = process.env.JWT_SECRET || 'mi_clave_ultra_segura';

// Helper para obtener el token del header
function extraerToken(req) {
  return req.headers.authorization?.split(' ')[1] || null;
}

// ========================
// Obtener todos los usuarios
// ========================
const getAllUsuarios = async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM usuarios');
    const token = extraerToken(req);

    await registrarAuditoria({
      accion: 'SELECT',
      modulo: 'seguridad',
      tabla: 'usuarios',
      id_usuario: req.usuario?.id_usuario || null,
      details: {
        consulta: 'SELECT * FROM usuarios',
        token
      },
      nombre_rol: req.usuario?.nombre_rol || 'Sistema'
    });

    res.json(result.rows);
  } catch (err) {
    console.error(err);
    res.status(500).send('Error del servidor');
  }
};

// ========================
// Obtener un usuario por ID
// ========================
const getUsuarioById = async (req, res) => {
  const { id } = req.params;
  try {
    const result = await pool.query('SELECT * FROM usuarios WHERE id_usuario = $1', [id]);
    if (result.rows.length === 0) {
      return res.status(404).send('Usuario no encontrado');
    }

    const token = extraerToken(req);

    await registrarAuditoria({
      accion: 'SELECT',
      modulo: 'seguridad',
      tabla: 'usuarios',
      id_usuario: req.usuario?.id_usuario || null,
      details: {
        consulta: 'SELECT * FROM usuarios WHERE id_usuario = $1',
        parametros: [id],
        token
      },
      nombre_rol: req.usuario?.nombre_rol || 'Sistema'
    });

    res.json(result.rows[0]);
  } catch (err) {
    console.error(err);
    res.status(500).send('Error del servidor');
  }
};

// ========================
// Crear nuevo usuario
// ========================
const createUsuario = async (req, res) => {
  const { usuario, contrasena, nombre, estado } = req.body;
  if (!usuario || !contrasena || !nombre) {
    return res.status(400).send('Faltan campos obligatorios');
  }
  try {
    const hash = await bcrypt.hash(contrasena, 10);
    const result = await pool.query(
      'INSERT INTO usuarios (usuario, contrasena, nombre, estado) VALUES ($1, $2, $3, $4) RETURNING *',
      [usuario, hash, nombre, estado ?? true]
    );

    const token = extraerToken(req);

    await registrarAuditoria({
      accion: 'INSERT',
      modulo: 'seguridad',
      tabla: 'usuarios',
      id_usuario: req.usuario?.id_usuario || null,
      details: {
        ...result.rows[0],
        token
      },
      nombre_rol: req.usuario?.nombre_rol || 'Sistema'
    });

    res.status(201).json(result.rows[0]);
  } catch (err) {
    console.error(err);
    res.status(500).send('Error del servidor');
  }
};

// ========================
// Actualizar usuario
// ========================
const updateUsuario = async (req, res) => {
  const { id } = req.params;
  const { usuario, contrasena, nombre, estado } = req.body;
  try {
    let hash = contrasena;
    if (contrasena) {
      hash = await bcrypt.hash(contrasena, 10);
    }
    const result = await pool.query(
      'UPDATE usuarios SET usuario = $1, contrasena = $2, nombre = $3, estado = $4 WHERE id_usuario = $5 RETURNING *',
      [usuario, hash, nombre, estado, id]
    );
    if (result.rows.length === 0) {
      return res.status(404).send('Usuario no encontrado');
    }

    const token = extraerToken(req);

    await registrarAuditoria({
      accion: 'UPDATE',
      modulo: 'seguridad',
      tabla: 'usuarios',
      id_usuario: req.usuario?.id_usuario || null,
      details: {
        ...result.rows[0],
        token
      },
      nombre_rol: req.usuario?.nombre_rol || 'Sistema'
    });

    res.json(result.rows[0]);
  } catch (err) {
    console.error(err);
    res.status(500).send('Error del servidor');
  }
};

// ========================
// Eliminar usuario
// ========================
const deleteUsuario = async (req, res) => {
  const { id } = req.params;
  try {
    const result = await pool.query(
      'DELETE FROM usuarios WHERE id_usuario = $1 RETURNING *',
      [id]
    );
    if (result.rows.length === 0) {
      return res.status(404).send('Usuario no encontrado');
    }

    const token = extraerToken(req);

    await registrarAuditoria({
      accion: 'DELETE',
      modulo: 'seguridad',
      tabla: 'usuarios',
      id_usuario: req.usuario?.id_usuario || null,
      details: {
        ...result.rows[0],
        token
      },
      nombre_rol: req.usuario?.nombre_rol || 'Sistema'
    });

    res.json({ mensaje: 'Usuario eliminado correctamente' });
  } catch (err) {
    console.error(err);
    res.status(500).send('Error del servidor');
  }
};

// ========================
// Login con JWT
// ========================
const login = async (req, res) => {
  const { usuario, contrasena, id_modulo } = req.body;
  if (!usuario || !contrasena || !id_modulo) {
    return res.status(400).json({ mensaje: 'Faltan datos requeridos' });
  }
  try {
    const result = await pool.query('SELECT * FROM usuarios WHERE usuario = $1', [usuario]);
    if (result.rows.length === 0) return res.status(401).json({ mensaje: 'Usuario o contraseña incorrectos' });

    const user = result.rows[0];
    const valid = await bcrypt.compare(contrasena, user.contrasena);
    if (!valid) return res.status(401).json({ mensaje: 'Usuario o contraseña incorrectos' });

    const rolResult = await pool.query(
      `SELECT r.nombre_rol
       FROM roles r
       JOIN usuarios_roles ur ON r.id_rol = ur.id_rol
       WHERE ur.id_usuario = $1
       LIMIT 1`,
      [user.id_usuario]
    );
    const nombre_rol = rolResult.rows.length > 0 ? rolResult.rows[0].nombre_rol : 'Sin rol';

    const permisosResult = await pool.query(`
      SELECT p.*
      FROM permisos p
      JOIN roles_permisos rp ON p.id_permiso = rp.id_permiso
      JOIN usuarios_roles ur ON rp.id_rol = ur.id_rol
      WHERE ur.id_usuario = $1 AND p.id_modulo = $2
    `, [user.id_usuario, id_modulo]);

    const tokenPayload = {
      id_usuario: user.id_usuario,
      usuario: user.usuario,
      nombre: user.nombre,
      nombre_rol
    };
    const token = jwt.sign(tokenPayload, SECRET_KEY, { expiresIn: '2h' });

    await registrarAuditoria({
      accion: 'LOGIN',
      modulo: id_modulo,
      tabla: '-',
      id_usuario: user.id_usuario,
      details: {
        usuario: user.usuario,
        token
      },
      nombre_rol
    });

    res.json({
      token,
      usuario: {
        id_usuario: user.id_usuario,
        usuario: user.usuario,
        nombre: user.nombre,
        nombre_rol
      },
      permisos: permisosResult.rows
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ mensaje: 'Error del servidor' });
  }
};

// ========================
// Verificar validez de token
// ========================
const tokenValido = async (req, res) => {
  const token = extraerToken(req);
  console.log("Token recibido:", token);
  if (!token) {
    return res.status(401).json({ valido: false, error: 'Token no proporcionado' });
  }

  try {
    const decoded = jwt.verify(token, SECRET_KEY);
    console.log("Token decodificado:", decoded);
    res.json({ valido: true, usuario: decoded });
  } catch (error) {
    console.error("Error al verificar token:", error.message);
    res.status(401).json({ valido: false, error: 'Token inválido o expirado' });
  }
};

// ========================
// Exportar controladores
// ========================
module.exports = {
  getAllUsuarios,
  getUsuarioById,
  createUsuario,
  updateUsuario,
  deleteUsuario,
  login,
  tokenValido
};
