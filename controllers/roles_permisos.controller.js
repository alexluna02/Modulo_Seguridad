const pool = require('../db');

// Obtener todos los permisos de un rol
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
    res.json(result.rows);
  } catch (err) {
    console.error(err);
    res.status(500).send('Error del servidor');
  }
};

// Asignar un permiso a un rol
const addPermisoToRol = async (req, res) => {
  const { id_rol, id_permiso } = req.body;
  try {
    await pool.query(
      'INSERT INTO roles_permisos (id_rol, id_permiso) VALUES ($1, $2)',
      [id_rol, id_permiso]
    );
    res.status(201).json({ mensaje: 'Permiso asignado al rol' });
  } catch (err) {
    console.error(err);
    res.status(500).send('Error del servidor');
  }
};

// Quitar un permiso de un rol
const removePermisoFromRol = async (req, res) => {
  const { id_rol, id_permiso } = req.body;
  try {
    const result = await pool.query(
      'DELETE FROM roles_permisos WHERE id_rol = $1 AND id_permiso = $2 RETURNING *',
      [id_rol, id_permiso]
    );
    if (result.rows.length === 0) return res.status(404).send('Relación no encontrada');
    res.json({ mensaje: 'Permiso quitado del rol' });
  } catch (err) {
    console.error(err);
    res.status(500).send('Error del servidor');
  }
};



// Asignar múltiples permisos a un rol
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
    res.json({ success: true, message: 'Permisos asignados correctamente' });
  } catch (err) {
    await client.query('ROLLBACK');
    console.error('Error al asignar permisos:', err);
    res.status(500).json({ success: false, error: 'Error al asignar permisos' });
  } finally {
    client.release();
  }
};


module.exports = {
  getPermisosByRol,
  addPermisoToRol,
  removePermisoFromRol,
  asignarPermisosRol
};