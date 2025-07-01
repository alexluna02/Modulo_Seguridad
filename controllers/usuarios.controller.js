const pool = require('../db');
const { registrarAuditoria } = require('../controllers/auditoria.controller');

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
  const { usuario, contrasena, estado } = req.body;
  try {
    const result = await pool.query(
      'INSERT INTO usuarios (usuario, contrasena, estado) VALUES ($1, $2, $3) RETURNING *',
      [usuario, contrasena, estado ?? true]
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
    if (err.code === '23505') {
      res.status(400).send('El usuario ya existe');
    } else {
      res.status(500).send('Error del servidor');
    }
  }
};

const updateUsuario = async (req, res) => {
  const { id } = req.params;
  const { usuario, contrasena, estado } = req.body;
  try {
    const result = await pool.query(
      'UPDATE usuarios SET usuario = $1, contrasena = $2, estado = $3 WHERE id_usuario = $4 RETURNING *',
      [usuario, contrasena, estado, id]
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
    if (err.code === '23505') {
      res.status(400).send('El usuario ya existe');
    } else {
      res.status(500).send('Error del servidor');
    }
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

const loginUsuario = async (req, res) => {
  const { usuario, contrasena } = req.body;
  try {
    const result = await pool.query(
      'SELECT * FROM usuarios WHERE usuario = $1',
      [usuario]
    );
    if (result.rows.length === 0) {
      return res.status(401).json({ message: 'Usuario o contraseña incorrectos' });
    }
    const user = result.rows[0];
    if (user.contrasena !== contrasena) {
      return res.status(401).json({ message: 'Usuario o contraseña incorrectos' });
    }

    await registrarAuditoria({
      accion: 'LOGIN',
      modulo: 'seguridad',
      tabla: 'usuarios',
      id_usuario: user.id_usuario,
      details: { usuario: user.usuario },
      nombre_rol: req.usuario?.nombre_rol || 'Sistema'
    });

    res.json({ mensaje: 'Login exitoso', usuario: user });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Error del servidor' });
  }
};

module.exports = {
  getAllUsuarios,
  getUsuarioById,
  createUsuario,
  updateUsuario,
  deleteUsuario,
  loginUsuario
};