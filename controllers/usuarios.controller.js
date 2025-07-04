const pool = require('../db');
const { registrarAuditoria } = require('./auditoria.controller');
const bcrypt = require('bcryptjs');

const getAllUsuarios = async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM usuarios');

    await registrarAuditoria({
      accion: 'SELECT',
      modulo: 'seguridad',
      tabla: 'usuarios',
      id_usuario: req.usuario?.id_usuario || null,
      details: { consulta: 'SELECT * FROM usuarios' },
      nombre_rol: req.usuario?.nombre_rol || 'Sistema'
    });

    res.json(result.rows);
  } catch (err) {
    console.error(err);
    res.status(500).send('Error del servidor');
  }
};

const getUsuarioById = async (req, res) => {
  const { id } = req.params;
  try {
    const result = await pool.query('SELECT * FROM usuarios WHERE id_usuario = $1', [id]);
    if (result.rows.length === 0) {
      return res.status(404).send('Usuario no encontrado');
    }

    await registrarAuditoria({
      accion: 'SELECT',
      modulo: 'seguridad',
      tabla: 'usuarios',
      id_usuario: req.usuario?.id_usuario || null,
      details: { consulta: 'SELECT * FROM usuarios WHERE id_usuario = $1', parametros: [id] },
      nombre_rol: req.usuario?.nombre_rol || 'Sistema'
    });

    res.json(result.rows[0]);
  } catch (err) {
    console.error(err);
    res.status(500).send('Error del servidor');
  }
};

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

    await registrarAuditoria({
      accion: 'INSERT',
      modulo: 'seguridad',
      tabla: 'usuarios',
      id_usuario: req.usuario?.id_usuario || null,
      details: result.rows[0],
      nombre_rol: req.usuario?.nombre_rol || 'Sistema'
    });

    res.status(201).json(result.rows[0]);
  } catch (err) {
    console.error(err);
    res.status(500).send('Error del servidor');
  }
};

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

    await registrarAuditoria({
      accion: 'UPDATE',
      modulo: 'seguridad',
      tabla: 'usuarios',
      id_usuario: req.usuario?.id_usuario || null,
      details: result.rows[0],
      nombre_rol: req.usuario?.nombre_rol || 'Sistema'
    });

    res.json(result.rows[0]);
  } catch (err) {
    console.error(err);
    res.status(500).send('Error del servidor');
  }
};

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

    try {
      await registrarAuditoria({
        accion: 'DELETE',
        modulo: 'seguridad',
        tabla: 'usuarios',
        id_usuario: req.usuario?.id_usuario || null,
        details: result.rows[0],
        nombre_rol: req.usuario?.nombre_rol || 'Sistema'
      });
    } catch (auditError) {
      console.error('Error al registrar auditoría:', auditError.message);
      // Opcional: Descomenta para fallar si la auditoría falla
      // throw new Error('Fallo al registrar la auditoría');
    }

    res.json({ mensaje: 'Usuario eliminado correctamente' });
  } catch (err) {
    console.error(err);
    res.status(500).send('Error del servidor');
  }
};



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

    // Obtener el rol principal del usuario (puedes ajustar la consulta según tu modelo)
    const rolResult = await pool.query(
      `SELECT r.nombre_rol
       FROM roles r
       JOIN usuarios_roles ur ON r.id_rol = ur.id_rol
       WHERE ur.id_usuario = $1
       LIMIT 1`,
      [user.id_usuario]
    );
    const nombre_rol = rolResult.rows.length > 0 ? rolResult.rows[0].nombre_rol : 'Sin rol';

    // Auditoría del login
    await registrarAuditoria({
      accion: 'LOGIN',
      modulo: id_modulo,
      tabla: '-',
      id_usuario: user.id_usuario,
      details: { usuario: user.usuario },
      nombre_rol
    });

    const permisosQuery = `
      SELECT p.*
      FROM permisos p
      JOIN roles_permisos rp ON p.id_permiso = rp.id_permiso
      JOIN usuarios_roles ur ON rp.id_rol = ur.id_rol
      WHERE ur.id_usuario = $1 AND p.id_modulo = $2
    `;
    const permisosResult = await pool.query(permisosQuery, [user.id_usuario, id_modulo]);
    res.json({ permisos: permisosResult.rows });
  } catch (err) {
    console.error(err);
    res.status(500).json({ mensaje: 'Error del servidor' });
  }
};

module.exports = {
  getAllUsuarios,
  getUsuarioById,
  createUsuario,
  updateUsuario,
  deleteUsuario,
  login,

};