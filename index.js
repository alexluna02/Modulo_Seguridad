require('dotenv').config(); // Solo una vez
const express = require('express');
const cors = require('cors');
const swaggerUi = require('swagger-ui-express');
const swaggerDocument = require('./swagger.json');
const pool = require('./db');
const authenticateToken = require('./middleware/auth'); // Importar el middleware

const app = express();
const port = process.env.PORT || 3000;

// Middleware
app.use(cors({
  origin: 'http://localhost:3001', // Restringir a tu frontend
  credentials: true,
}));
app.use(express.json());

// Verificar conexión a la base de datos antes de cada solicitud
const checkDbConnection = async (req, res, next) => {
  try {
    await pool.query('SELECT 1');
    next();
  } catch (err) {
    console.error('Error de conexión a la base de datos:', err.message);
    res.status(503).json({ error: 'Servicio no disponible: Problema con la base de datos' });
  }
};
app.use(checkDbConnection);

// Ruta básica
app.get('/', (req, res) => {
  res.send('API de Seguridad');
});

// Rutas
const usuariosRoutes = require('./routes/usuarios.routes');
const rolesRoutes = require('./routes/roles.routes');
const permisosRoutes = require('./routes/permisos.routes');
const auditoriaRoutes = require('./routes/auditoria.routes');
const usuariosRolesRoutes = require('./routes/usuarios_roles.routes');
const rolesPermisosRoutes = require('./routes/roles_permisos.routes');
const modulosRoutes = require('./routes/modulos.routes');

// Aplicar middleware de autenticación a rutas protegidas
app.use('/api/usuarios', usuariosRoutes); // Login es público, otras rutas protegidas
app.use('/api/roles', authenticateToken, rolesRoutes);
app.use('/api/permisos', authenticateToken, permisosRoutes);
app.use('/api/auditoria', authenticateToken, auditoriaRoutes);
app.use('/api/usuarios_roles', authenticateToken, usuariosRolesRoutes);
app.use('/api/roles_permisos', authenticateToken, rolesPermisosRoutes);
app.use('/api/modulos', authenticateToken, modulosRoutes);

// Documentación Swagger
app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(swaggerDocument));

// Middleware de errores
app.use((err, req, res, next) => {
  console.error('Error del servidor:', err.stack);
  res.status(500).json({ error: 'Algo salió mal en el servidor', detalle: err.message });
});

// Iniciar servidor
app.listen(port, () => {
  console.log(`Servidor corriendo en http://localhost:${port}`);
  console.log(`Documentación disponible en http://localhost:${port}/api-docs`);
});

// Verificar conexión inicial
pool.query('SELECT NOW()', (err, res) => {
  if (err) {
    console.error('Error de conexión inicial a la base de datos:', err.message);
  } else {
    console.log('Conexión inicial exitosa a la base de datos:', res.rows[0]);
  }
});