const express = require('express');
const { MongoClient } = require('mongodb');

const app = express();
let db;

// Vulnerable a operator injection: req.query viene de la librería
// `qs` (default de Express), que convierte automáticamente
// "password[$ne]=x" en { password: { $ne: 'x' } } sin que el
// desarrollador lo pida — el vector real más común de NoSQLi.
app.get('/login', async (req, res) => {
  const { username, password } = req.query;
  try {
    const user = await db.collection('users').findOne({ username, password });
    if (user) {
      res.status(200).send(`<html><body>Welcome ${user.username}</body></html>`);
    } else {
      res.status(401).send('<html><body>Invalid credentials</body></html>');
    }
  } catch (e) {
    res.status(500).send(`<html><body>Error: ${e.name}: ${e.message}</body></html>`);
  }
});

// Vulnerable a $where injection: concatenación cruda de JS, el
// patrón clásico de los tutoriales de NoSQLi ($where injection).
app.get('/search', async (req, res) => {
  const q = req.query.q || '';
  try {
    const results = await db.collection('products')
      .find({ $where: "this.name == '" + q + "'" })
      .toArray();
    res.status(200).send(`<html><body>Found: ${results.length}</body></html>`);
  } catch (e) {
    res.status(500).send(`<html><body>Error: ${e.name}: ${e.message}</body></html>`);
  }
});

MongoClient.connect('mongodb://test_mongo:27017').then(async (client) => {
  db = client.db('testdb');
  await db.collection('users').deleteMany({});
  await db.collection('users').insertOne({ username: 'admin', password: 'sup3rSecr3t123' });
  await db.collection('products').deleteMany({});
  await db.collection('products').insertOne({ name: 'Widget' });
  app.listen(80, () => console.log('listening on 80'));
}).catch((e) => {
  console.error('Mongo connection failed', e);
  process.exit(1);
});
