const pool = require('../db');

const getAllModulos = async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM modulos');
    res.json(result.rows);
  } catch (err) {
    res.status(500).send('Error del servidor');
  }
};

const getModuloById = async (req, res) => {
  const { id } = req.params;
  try {
    const result = await pool.query('SELECT * FROM modulos WHERE id_modulo = $1', [id]);
    if (result.rows.length === 0) return res.status(404).send('Módulo no encontrado');
    res.json(result.rows[0]);
  } catch (err) {
    res.status(500).send('Error del servidor');
  }
};

const createModulo = async (req, res) => {
  const { id_modulo, nombre_modulo, estado } = req.body;
  try {
    const result = await pool.query(
      'INSERT INTO modulos (id_modulo, nombre_modulo, estado) VALUES ($1, $2, $3) RETURNING *',
      [id_modulo, nombre_modulo, estado ?? true]
    );
    res.status(201).json(result.rows[0]);
  } catch (err) {
    res.status(500).send('Error del servidor');
  }
};

const updateModulo = async (req, res) => {
  const { id } = req.params;
  const { nombre_modulo, estado } = req.body;
  try {
    const result = await pool.query(
      'UPDATE modulos SET nombre_modulo = $1, estado = $2 WHERE id_modulo = $3 RETURNING *',
      [nombre_modulo, estado, id]
    );
    if (result.rows.length === 0) return res.status(404).send('Módulo no encontrado');
    res.json(result.rows[0]);
  } catch (err) {
    res.status(500).send('Error del servidor');
  }
};

const deleteModulo = async (req, res) => {
  const { id } = req.params;
  try {
    const result = await pool.query(
      'DELETE FROM modulos WHERE id_modulo = $1 RETURNING *',
      [id]
    );
    if (result.rows.length === 0) return res.status(404).send('Módulo no encontrado');
    res.json({ mensaje: 'Módulo eliminado correctamente' });
  } catch (err) {
    res.status(500).send('Error del servidor');
  }
};

module.exports = {
  getAllModulos,
  getModuloById,
  createModulo,
  updateModulo,
  deleteModulo
};