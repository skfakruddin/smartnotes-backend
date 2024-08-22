require('dotenv').config();
const exp = require('express');
const cors = require('cors');
const { MongoClient } = require('mongodb');

const app = exp();

app.use(cors({ origin: '*' }));
app.use(exp.json());

const dbURL = 'mongodb://127.0.0.1:27017';
const mc = new MongoClient(dbURL, { useNewUrlParser: true, useUnifiedTopology: true });

mc.connect().then(connectionObject => {
    const companyDatabase = connectionObject.db('Company');
    const usersCollection = companyDatabase.collection('Users');
    
    app.set('usersCollection', usersCollection);

    console.log('Connected to MongoDB');
    
    const port = process.env.PORT || 3000;
    app.listen(port, () => {
        console.log(`Server running on port http://localhost:${port}`);
    });
}).catch(err => {
    console.error('Error in connecting to MongoDB:', err.message);
});

app.get('/', (req, res) => {
    res.send('This is an API Connected to MongoDB');
});

const userAPI = require('./Apis/UserApi.js');

app.use('/user-api', userAPI);

app.use('*', (req, res) => {
    res.status(404).send({ message: `Path ${req.originalUrl} is invalid` });
});

app.use((err, req, res, next) => {
    console.error('Error:', err.message);
    res.status(500).send({ message: 'Error Occurred', error: err.message });
});
