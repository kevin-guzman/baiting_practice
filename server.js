const express = require('express');

const app = express();

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.get('/', (req, res) => {
  res.send('Hello World!');
});

app.post('/', (req, res) => {
  console.log("usuario hackeado -> ",req.body);
  
  res.send('Hello World!');
});

app.listen(3000, () => {
  console.log('App corriendo en el puerto 3000!');
});