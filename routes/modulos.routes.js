const express = require('express');
const router = express.Router();
const modulosController = require('../controllers/modulos.controller');

router.get('/', modulosController.getAllModulos);
router.get('/:id', modulosController.getModuloById);
router.post('/', modulosController.createModulo);
router.put('/:id', modulosController.updateModulo);
router.delete('/:id', modulosController.deleteModulo);

module.exports = router;