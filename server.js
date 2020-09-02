require('dotenv').config()

const express = require('express')
const app = express()
const jwt = require('jsonwebtoken')
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const bodyParser = require('body-parser')
const cookieParser = require('cookie-parser')
const saltRounds = 10;

const port = process.env.PORT || 3000;

mongoose.connect(process.env.MONGODB_URI || 'mongodb://127.0.0.1/login', { useNewUrlParser: true, useUnifiedTopology: true, useCreateIndex: true })
    .then(() => {
        console.log('Mongoose successfully connected')
    }).catch(() => {
        console.log('Mongoose connection failed')
    });
app.set('views', __dirname + '/views'); 
app.use(express.json())
app.use(cookieParser())
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: false }))
app.engine('html', require('ejs').renderFile);
app.set('view engine', 'ejs');

const contentModel = mongoose.model('users', new mongoose.Schema({
    name: {type: String, required: true, unique: true},
    password: {type: String, required: true},
}))

app.post('/login', async (req, res) => {
    const neededUser = await contentModel.findOne({'name': req.body.loginName}).catch(() => console.log('could not retrieve the user'))
    await bcrypt.compare(req.body.loginPassword, neededUser.password, (err, result) => {
        if (!result) {
            console.log('wrong password')
            res.redirect('/')
        } else {
            const token = jwt.sign({name: neededUser.name, password: neededUser.password}, process.env.ACESS_TOKEN_SECRET)
            res.cookie('token', token, {maxAge:1000000})
            res.redirect('/')
        }
    })

})


app.post('/register', async (req, res) => {
    
    let password;
    await bcrypt.hash(req.body.password, saltRounds, async (err, hash) => {
        if (err) {
            console.log(err) 
            return
        }
        const user = {name: req.body.name, password: hash}
    console.log(user)

    await new contentModel(user).save().then(() => {
        const token = jwt.sign(user, process.env.ACESS_TOKEN_SECRET)
        res.cookie('token', token, {maxAge:1000000})
         res.redirect('/')
    }).then(() => {
        console.log('user saved succesfully')
    }).catch(() => {
        res.send('failed to register, name already in use')
    })
    })

})

app.get('/', authenticateToken, (req, res) => {
    res.render('index');
    
})

app.get('/loggedIn', async (req, res) => {
    const neededUser = await contentModel.findOne({'_id': req.query.id}).catch(() => console.log('could not recieve the user'))
    try {
        res.render('logged', {name: neededUser.name})
    } catch {
        res.sendStatus(404)
    }
    
})

app.get('/logout', (req, res) => {
    res.clearCookie("token")
    res.redirect('/')
})

app.listen(port, () => {
    console.log('listening on ' + port)
}) 

function authenticateToken(req, res, next) {
    
    const token = req.cookies.token
    if (token == null) {
        next()
        return
    }

    jwt.verify(token, process.env.ACESS_TOKEN_SECRET,async (err, user) => {
        if (err) {
            return res.sendStatus(403)
        }
        console.log(user)
        try {
            console.log(user)
            console.log(user.name)
            const id = await contentModel.findOne({'name': user.name})
            res.redirect('/loggedIn?id=' + id._id)
        } catch {
            console.log('error')
        }
        
    })
}