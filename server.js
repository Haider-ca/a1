require('dotenv').config();
const express       = require('express');
const session       = require('express-session');
const MongoStore    = require('connect-mongo');
const { MongoClient } = require('mongodb');
const bcrypt        = require('bcrypt');
const Joi           = require('joi');
const path          = require('path');

const app = express();
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));
app.set('view engine', 'ejs');

const {
  MONGODB_URI,
  MONGODB_SESSION_SECRET,
  PORT = 3000
} = process.env;

async function main() {
  // 1. Connect to MongoDB
  const client = new MongoClient(MONGODB_URI);
  await client.connect();
  const db = client.db();
  const users = db.collection('users');

  // 2. Session setup (1-hour TTL)
  app.use(session({
    secret: MONGODB_SESSION_SECRET,
    store: MongoStore.create({
      client,
      collectionName: 'sessions',
      ttl: 60 * 60
    }),
    resave: false,
    saveUninitialized: false,
    cookie: { maxAge: 60 * 60 * 1000 }
  }));

  // 3. ROUTES

  // Home
  app.get('/', (req, res) => {
    res.render('home', { user: req.session.user });
  });

  // Sign Up
  app.get('/signup', (req, res) => res.render('signup', { error: null }));
  app.post('/signup', async (req, res) => {
    const schema = Joi.object({
      name:     Joi.string().max(50).required(),
      email:    Joi.string().email().required(),
      password: Joi.string().min(6).required()
    });
    const { error, value } = schema.validate(req.body);
    if (error) return res.render('signup', { error: error.details[0].message });

    const { name, email, password } = value;
    if (await users.findOne({ email })) {
      return res.render('signup', { error: 'Email already registered' });
    }
    const hash = await bcrypt.hash(password, 10);
    await users.insertOne({ name, email, password: hash });

    req.session.user = { name, email };
    res.redirect('/members');
  });

  // Log In
  app.get('/login', (req, res) => res.render('login', { error: null }));
  app.post('/login', async (req, res) => {
    const schema = Joi.object({
      email:    Joi.string().email().required(),
      password: Joi.string().required()
    });
    const { error, value } = schema.validate(req.body);
    if (error) return res.render('login', { error: error.details[0].message });

    const { email, password } = value;
    const user = await users.findOne({ email });
    if (!user) {
      return res.render('login', { error: 'User not found' });
    }
    if (!(await bcrypt.compare(password, user.password))) {
      return res.render('login', { error: 'Invalid password' });
    }
    req.session.user = { name: user.name, email };
    res.redirect('/members');
  });

  // Members-only
  app.get('/members', (req, res) => {
    if (!req.session.user) return res.redirect('/');
    const imgs = ['image1.jpg','image2.jpg','image3.jpg'];
    const randomImage = imgs[Math.floor(Math.random() * imgs.length)];
    res.render('members', { user: req.session.user, randomImage });
  });

  // Log Out
  app.get('/logout', (req, res) => {
    req.session.destroy(() => res.redirect('/'));
  });

  // 404 catcher
  app.use((req, res) => {
    res.status(404).render('404');
  });

  // Start server
  app.listen(PORT, () => console.log(`Server listening on port ${PORT}`));
}

main().catch(console.error);
