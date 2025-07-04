const pool = require('../db');

// Función principal que inserta en la base de datos
async function registrarAuditoria({
  accion,
  modulo,
  tabla,
  id_usuario,
  details,
  nombre_rol = 'Sistema'
}) {
  const query = `
    INSERT INTO auditoria (
      accion, modulo, tabla, id_usuario, details, timestamp, nombre_rol
    ) VALUES ($1, $2, $3, $4, $5, NOW(), $6)
  `;

  const values = [
    accion,
    modulo,
    tabla,
    id_usuario,
    details ? JSON.stringify(details) : null,
    nombre_rol
  ];

  try {
    await pool.query(query, values);
  } catch (error) {
    console.error('Error al registrar auditoría:', error.message);
    throw error;
  }
}

// Endpoint POST para microservicios
const auditoriamodulos = async (req, res) => {
  const { accion, modulo, tabla, id_usuario, details, nombre_rol } = req.body;

  try {
    await registrarAuditoria({ accion, modulo, tabla, id_usuario, details, nombre_rol });
    res.status(201).json({ mensaje: 'Auditoría registrada correctamente' });
  } catch (error) {
    console.error('Error al registrar auditoría vía POST:', error.message);
    res.status(500).json({ mensaje: 'Error al registrar auditoría', error: error.message });
  }
};

// GET /auditoria
const getAllAuditoria = async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM auditoria ORDER BY timestamp DESC');
    res.json(result.rows);
  } catch (error) {
    console.error(error);
    res.status(500).send('Error al obtener auditorías');
  }
};

// GET /auditoria/:id
const getAuditoriaById = async (req, res) => {
  const { id } = req.params;
  try {
    const result = await pool.query('SELECT * FROM auditoria WHERE id = $1', [id]);
    if (result.rows.length === 0) {
      return res.status(404).send('Auditoría no encontrada');
    }
    res.json(result.rows[0]);
  } catch (error) {
    console.error(error);
    res.status(500).send('Error al obtener auditoría');
  }
};

// Exportación
module.exports = {
  registrarAuditoria,             // función reutilizable
  auditoriamodulos,  // controlador POST
  getAllAuditoria,
  getAuditoriaById
};
