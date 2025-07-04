require('dotenv').config();
const express = require('express');
const cors = require('cors');
const swaggerUi = require('swagger-ui-express');
const swaggerDocument = require('./swagger.json'); // O el path a tu archivo swagger
const pool = require('./db');

const app = express();
const port = process.env.PORT || 3000;

// Middleware
app.use(cors());
app.use(express.json());

// Ruta básica
app.get('/', (req, res) => {
  res.send('API de Seguridad');
});

// Rutas de usuarios
const usuariosRoutes = require('./routes/usuarios.routes');
app.use('/api/usuarios', usuariosRoutes);

// Rutas de roles
const rolesRoutes = require('./routes/roles.routes');
app.use('/api/roles', rolesRoutes);

// Rutas de permisos
const permisosRoutes = require('./routes/permisos.routes');
app.use('/api/permisos', permisosRoutes);

// Rutas de auditoría
const auditoriaRoutes = require('./routes/auditoria.routes');
app.use('/api/auditoria', auditoriaRoutes);

const usuariosRolesRoutes = require('./routes/usuarios_roles.routes');
app.use('/api/usuarios_roles', usuariosRolesRoutes);

const rolesPermisosRoutes = require('./routes/roles_permisos.routes');
app.use('/api/roles_permisos', rolesPermisosRoutes);

const modulosRoutes = require('./routes/modulos.routes');
app.use('/api/modulos', modulosRoutes);

app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(swaggerDocument));

// Iniciar servidor
app.listen(port, () => {
  console.log(`Servidor corriendo en http://localhost:${port}`);
  console.log(`Servidor corriendo en http://localhost:${port}/api-docs`);
});

pool.query('SELECT NOW()', (err, res) => {
  if (err) {
    console.error('Error de conexión a la base de datos:', err);
  } else {
    console.log('Conexión exitosa a la base de datos:', res.rows[0]);
  }
});

