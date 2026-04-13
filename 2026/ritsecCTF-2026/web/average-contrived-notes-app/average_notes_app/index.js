const express = require('express')
const session = require('express-session');
const createDOMPurify = require('dompurify');
const { JSDOM } = require('jsdom');
const path = require('path');
const { visit } = require('./bot')

const app = express()
const PORT = 3031

const SESSION_SECRET = process.env.SESSION_SECRET || 'meowmeowmeow';

const sessionHandler = (req, res, next) => {
    if (!req.session.notes) {
        req.session.notes = [] 
    }
    next()
}

app.use(session({
  secret: SESSION_SECRET,
  resave: false, 
  saveUninitialized: false, 
  cookie: { maxAge: 3600000 }
}))

app.use(sessionHandler)
app.use(express.json())

app.get('/api/notes', function(req, res) {
    let filteredNotes = req.query.search ? req.session.notes.filter((note) => {return note.includes(req.query.search)}).sort() : req.session.notes
    res.send(filteredNotes.join('[SEP]'))
})

app.post('/api/notes', function(req, res) {
    let note = req.body.note
    if (!note) {
        res.status(422).json({error: "empty note"})
        return
    }
    let window = new JSDOM('').window
    let DOMPurify = createDOMPurify(window)
    let clean = DOMPurify.sanitize(note).replaceAll('[SEP]', '')
    req.session.notes.push(clean)
    let filteredNotes = req.query.search ? req.session.notes.filter((note) => {return note.includes(req.query.search)}).sort() : req.session.notes
    res.send(filteredNotes.join('[SEP]'))
})

app.post('/api/bot', function(req, res) {
    let url = req.body.url
    if (!url) {
        res.status(422).json({error: "empty url"})
        return
    }
    try {
        visit(url)
        res.json({ok: true})
    } catch (e){
        res.status(400).json({error: e.message})
    }
})

app.get('/', function(req, res) {
    res.sendFile(path.resolve(__dirname, 'templates/index.html'))
})

app.get('/image', function(req, res) {
    res.header('x-meow-meow', req.session.notes.toString())
    res.sendFile(path.resolve(__dirname, 'templates/image.png'))
})

app.get('/script', function(req, res) {
    res.header('x-meow-meow', req.session.notes.toString())
    res.sendFile(path.resolve(__dirname, 'templates/script.txt'))
})

app.listen(PORT, () => {
  console.log(`meowing on port ${PORT}`)
})