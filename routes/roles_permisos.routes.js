const express = require('express');
const router = express.Router();
const { getPermisosByRol, addPermisoToRol, removePermisoFromRol, asignarPermisosRol } = require('../controllers/roles_permisos.controller');

router.get('/roles/:id_rol/permisos', getPermisosByRol);
router.post('/roles/permisos', addPermisoToRol);
router.delete('/roles/permisos', removePermisoFromRol);
router.post('/roles/:id_rol/permisos', asignarPermisosRol);

module.exports = router;