const pool = require('../db');

// Obtener todos los permisos
const getAllPermisos = async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM permisos ORDER BY id_permiso');
    res.json(result.rows);
  } catch (err) {
    res.status(500).send('Error del servidor');
  }
};

// Obtener permiso por ID
const getPermisoById = async (req, res) => {
  const { id } = req.params;
  try {
    const result = await pool.query('SELECT * FROM permisos WHERE id_permiso = $1', [id]);
    if (result.rows.length === 0) return res.status(404).send('Permiso no encontrado');
    res.json(result.rows[0]);
  } catch (err) {
    res.status(500).send('Error del servidor');
  }
};

// Crear permiso
const createPermiso = async (req, res) => {
  const { nombre_permiso, descripcion, url_permiso, id_modulo } = req.body;
  if (!nombre_permiso || !url_permiso || !id_modulo) {
    return res.status(400).send('Faltan campos obligatorios');
  }
  try {
    const result = await pool.query(
      'INSERT INTO permisos (nombre_permiso, descripcion, url_permiso, id_modulo) VALUES ($1, $2, $3, $4) RETURNING *',
      [nombre_permiso, descripcion, url_permiso, id_modulo]
    );
    res.status(201).json(result.rows[0]);
  } catch (err) {
    res.status(500).send('Error del servidor');
  }
};

// Actualizar permiso
const updatePermiso = async (req, res) => {
  const { id } = req.params;
  const { nombre_permiso, descripcion, url_permiso, id_modulo } = req.body;
  try {
    const result = await pool.query(
      'UPDATE permisos SET nombre_permiso = $1, descripcion = $2, url_permiso = $3, id_modulo = $4 WHERE id_permiso = $5 RETURNING *',
      [nombre_permiso, descripcion, url_permiso, id_modulo, id]
    );
    if (result.rows.length === 0) return res.status(404).send('Permiso no encontrado');
    res.json(result.rows[0]);
  } catch (err) {
    res.status(500).send('Error del servidor');
  }
};

// Eliminar permiso
const deletePermiso = async (req, res) => {
  const { id } = req.params;
  try {
    const result = await pool.query(
      'DELETE FROM permisos WHERE id_permiso = $1 RETURNING *',
      [id]
    );
    if (result.rows.length === 0) return res.status(404).send('Permiso no encontrado');
    res.json({ mensaje: 'Permiso eliminado correctamente' });
  } catch (err) {
    res.status(500).send('Error del servidor');
  }
};

module.exports = {
  getAllPermisos,
  getPermisoById,
  createPermiso,
  updatePermiso,
  deletePermiso
};