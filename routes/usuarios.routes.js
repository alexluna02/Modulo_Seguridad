const express = require('express');
const router = express.Router();
const authenticateToken = require('../middleware/auth'); // Importar el middleware
const usuariosController = require('../controllers/usuarios.controller');

// Rutas públicas
router.post('/login', usuariosController.login);

// Rutas protegidas
router.get('/', authenticateToken, usuariosController.getAllUsuarios);
router.get('/:id', authenticateToken, usuariosController.getUsuarioById);
router.post('/', authenticateToken, usuariosController.createUsuario);
router.put('/:id', authenticateToken, usuariosController.updateUsuario);
router.delete('/:id', authenticateToken, usuariosController.deleteUsuario);

module.exports = router;