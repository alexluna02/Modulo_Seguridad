const express = require('express');

const router = express.Router();
const usuariosController = require('../controllers/usuarios.controller');

// Definir endpoints
router.get('/', usuariosController.getAllUsuarios);
router.get('/:id', usuariosController.getUsuarioById);
router.post('/', usuariosController.createUsuario);
router.put('/:id', usuariosController.updateUsuario);
router.delete('/:id', usuariosController.deleteUsuario);
router.post('/login', usuariosController.login);

module.exports = router;