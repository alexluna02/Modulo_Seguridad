require('dotenv').config();
const express = require('express');
const cors = require('cors');
const swaggerUi = require('swagger-ui-express');
const swaggerDocument = require('./swagger.json');
const pool = require('./db');

const app = express();
const port = process.env.PORT || 3000;

// Middleware

app.use(cors({
  origin: ['https://front-modulo-sp.vercel.app', 'http://localhost:3000'],
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  credentials: true // Si usas cookies o credenciales
}));


app.use(express.json());

// Verificar conexión a la base de datos antes de cada solicitud
const checkDbConnection = async (req, res, next) => {
  try {
    await pool.query('SELECT 1');
    next();
  } catch (err) {
    console.error('Error de conexión a la base de datos:', err);
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
app.use('/api/usuarios', usuariosRoutes);

const rolesRoutes = require('./routes/roles.routes');
app.use('/api/roles', rolesRoutes);

const permisosRoutes = require('./routes/permisos.routes');
app.use('/api/permisos', permisosRoutes);

const auditoriaRoutes = require('./routes/auditoria.routes');
app.use('/api/auditoria', auditoriaRoutes);

const usuariosRolesRoutes = require('./routes/usuarios_roles.routes');
app.use('/api/usuarios_roles', usuariosRolesRoutes);

const rolesPermisosRoutes = require('./routes/roles_permisos.routes');
app.use('/api/roles_permisos', rolesPermisosRoutes);

const modulosRoutes = require('./routes/modulos.routes');
app.use('/api/modulos', modulosRoutes);

app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(swaggerDocument));

// Middleware de errores
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ error: 'Algo salió mal en el servidor' });
});

// Iniciar servidor
app.listen(port, () => {
  console.log(`Servidor corriendo en http://localhost:${port}`);
  console.log(`Servidor corriendo en http://localhost:${port}/api-docs`);
});

// Verificar conexión inicial (opcional, para logging)
pool.query('SELECT NOW()', (err, res) => {
  if (err) {
    console.error('Error de conexión inicial a la base de datos:', err);
  } else {
    console.log('Conexión inicial exitosa a la base de datos:', res.rows[0]);
  }
});