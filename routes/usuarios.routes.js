const express = require('express');

const router = express.Router();
const usuariosController = require('../controllers/usuarios.controller');
router.get('/verificar-token', usuariosController.tokenValido);
router.post('/login', usuariosController.login);
// Definir endpoints
router.get('/', usuariosController.getAllUsuarios);
router.get('/:id', usuariosController.getUsuarioById);
router.post('/', usuariosController.createUsuario);
router.put('/:id', usuariosController.updateUsuario);
router.delete('/:id', usuariosController.deleteUsuario);



module.exports = router;