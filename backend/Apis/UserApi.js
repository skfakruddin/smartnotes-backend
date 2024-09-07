const exp = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const tokenVerify = require('../middlewares/tokenVerify');
const saltRounds = 10;

// Initialize the Express Router
const userAPI = exp.Router();

// Secret key for JWT
const secretKey = process.env.SECRET || 'your_secret_key_here';

// Create a new user with note password
userAPI.post('/users', async (req, res) => {
    const { name, username, password, email, notesPassword, confirmNotesPassword } = req.body;
    const usersCollection = req.app.get('usersCollection');

    try {
        // Check if the user already exists
        const existingUser = await usersCollection.findOne({ username });
        if (existingUser) {
            return res.status(400).send({ message: 'Username already exists' });
        }

        // Check if notes passwords match
        if (notesPassword !== confirmNotesPassword) {
            return res.status(400).send({ message: 'Notes password and confirmation do not match' });
        }

        // Hash the passwords
        const hashedPassword = await bcrypt.hash(password, saltRounds);
        const hashedNotesPassword = await bcrypt.hash(notesPassword, saltRounds);

        // Insert the new user into the collection
        const newUser = { name, username, password: hashedPassword, email, notesPassword: hashedNotesPassword, notes: [] };
        await usersCollection.insertOne(newUser);

        res.status(201).send({ message: 'User created successfully' });
    } catch (error) {
        res.status(500).send({ message: 'Error creating user', error: error.message });
    }
});

// Login user and generate a JWT
userAPI.post('/users/login', async (req, res) => {
    const { username, password } = req.body;
    const usersCollection = req.app.get('usersCollection');

    try {
        // Find the user by username
        const user = await usersCollection.findOne({ username });
        if (!user) {
            return res.status(400).send({ message: 'Invalid username or password' });
        }

        // Compare the password
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(400).send({ message: 'Invalid username or password' });
        }

        // Generate a JWT token
        const token = jwt.sign({ username: user.username }, secretKey, { expiresIn: '1d' });

        res.status(200).send({ message: 'Login successful', token });
    } catch (error) {
        res.status(500).send({ message: 'Error during login', error: error.message });
    }
});

// Get all users (Protected route)
userAPI.get('/users', tokenVerify, async (req, res) => {
    const usersCollection = req.app.get('usersCollection');

    try {
        const users = await usersCollection.find().toArray();
        res.status(200).send(users);
    } catch (error) {
        res.status(500).send({ message: 'Error fetching users', error: error.message });
    }
});

// Create a new note for the logged-in user
userAPI.post('/users/notes', tokenVerify, async (req, res) => {
    const { title, noteId, content, tags, password } = req.body;
    console.log('req.body: ', req.body);
    const usersCollection = req.app.get('usersCollection');

    try {
        // Find the logged-in user
        const user = await usersCollection.findOne({ username: req.user.username });
        console.log('user: ', user);

        if (!user) {
            return res.status(404).send({ message: 'User not found' });
        }

        // Check if the password is correct, if provided
        if (password) {
            const isPasswordMatch = await bcrypt.compare(password, user.notesPassword);
            if (!isPasswordMatch) {
                return res.status(403).send({ message: 'Invalid notes password' });
            }
        }

        // Create the note and add it to the user's notes array
        const newNote = {
            noteId: noteId || new Date().toISOString(),
            title: title || '',
            content: content || '',
            tags: tags || [],
            isFavorite: false,
            isDeleted: false,
            deletedAt: null
        };

        const updatedNotes = [...user.notes, newNote];

        // Update the user's notes array in the database
        await usersCollection.updateOne({ username: req.user.username }, { $set: { notes: updatedNotes } });

        res.status(201).send({ message: 'Note created successfully', note: newNote });
    } catch (error) {
        res.status(500).send({ message: 'Error creating note', error: error.message });
    }
});
// Update an existing note for the logged-in user
userAPI.put('/users/notes/:noteId', tokenVerify, async (req, res) => {
    const { noteId } = req.params;
    const { title, content, tags, password } = req.body;
    const usersCollection = req.app.get('usersCollection');

    try {
        // Find the logged-in user
        const user = await usersCollection.findOne({ username: req.user.username });

        if (!user) {
            return res.status(404).send({ message: 'User not found' });
        }

        // Find the note to update
        const noteIndex = user.notes.findIndex(note => note.noteId === noteId && !note.isDeleted);

        if (noteIndex === -1) {
            return res.status(404).send({ message: 'Note not found or is in the recycle bin' });
        }

        // Check if the password is correct, if provided
        if (password) {
            const isPasswordMatch = await bcrypt.compare(password, user.notesPassword);
            if (!isPasswordMatch) {
                return res.status(403).send({ message: 'Invalid notes password' });
            }
        }

        // Update the note
        const updatedNote = {
            ...user.notes[noteIndex],
            title: title || user.notes[noteIndex].title,
            content: content || user.notes[noteIndex].content,
            tags: tags || user.notes[noteIndex].tags
        };

        // Update the notes array
        const updatedNotes = [
            ...user.notes.slice(0, noteIndex),
            updatedNote,
            ...user.notes.slice(noteIndex + 1)
        ];

        // Save the updated notes array back to the database
        await usersCollection.updateOne({ username: req.user.username }, { $set: { notes: updatedNotes } });

        res.status(200).send({ message: 'Note updated successfully', note: updatedNote });
    } catch (error) {
        res.status(500).send({ message: 'Error updating note', error: error.message });
    }
});


// Fetch all notes for the logged-in user
userAPI.get('/users/notes', tokenVerify, async (req, res) => {
    const usersCollection = req.app.get('usersCollection');

    try {
        // Find the logged-in user
        const user = await usersCollection.findOne({ username: req.user.username });

        if (!user) {
            return res.status(404).send({ message: 'User not found' });
        }

        // Filter out notes that are in the recycle bin
        const activeNotes = user.notes.filter(note => !note.isDeleted);

        res.status(200).send(activeNotes);
    } catch (error) {
        res.status(500).send({ message: 'Error fetching notes', error: error.message });
    }
});

// Fetch notes with a specific tag for the logged-in user
userAPI.get('/users/notes/tag/:tag', tokenVerify, async (req, res) => {
    const usersCollection = req.app.get('usersCollection');
    const { tag } = req.params;

    try {
        // Find the logged-in user
        const user = await usersCollection.findOne({ username: req.user.username });

        if (!user) {
            return res.status(404).send({ message: 'User not found' });
        }
        // Filter notes by tag and exclude deleted notes
        const filteredNotes = user.notes.filter(note => note.tags.includes(tag) && !note.isDeleted);
        res.status(200).send(filteredNotes);
    } catch (error) {
        res.status(500).send({ message: 'Error fetching notes', error: error.message });
    }
});

// Mark a note as favorite
userAPI.put('/users/notes/favorite/:noteId', tokenVerify, async (req, res) => {
    const { noteId } = req.params;
    const usersCollection = req.app.get('usersCollection');

    try {
        // Find the logged-in user
        const user = await usersCollection.findOne({ username: req.user.username });

        if (!user) {
            return res.status(404).send({ message: 'User not found' });
        }

        // Update the note to mark as favorite
        const updatedNotes = user.notes.map(note =>
            note.noteId === noteId && !note.isDeleted ? { ...note, isFavorite: true } : note
        );

        await usersCollection.updateOne({ username: req.user.username }, { $set: { notes: updatedNotes } });

        res.status(200).send({ message: 'Note marked as favorite' });
    } catch (error) {
        res.status(500).send({ message: 'Error updating note', error: error.message });
    }
});

// Unmark a note as favorite
userAPI.put('/users/notes/unfavorite/:noteId', tokenVerify, async (req, res) => {
    const { noteId } = req.params;
    const usersCollection = req.app.get('usersCollection');

    try {
        // Find the logged-in user
        const user = await usersCollection.findOne({ username: req.user.username });

        if (!user) {
            return res.status(404).send({ message: 'User not found' });
        }

        // Update the note to unmark as favorite
        const updatedNotes = user.notes.map(note =>
            note.noteId === noteId && !note.isDeleted ? { ...note, isFavorite: false } : note
        );

        await usersCollection.updateOne({ username: req.user.username }, { $set: { notes: updatedNotes } });

        res.status(200).send({ message: 'Note unmarked as favorite' });
    } catch (error) {
        res.status(500).send({ message: 'Error updating note', error: error.message });
    }
});

// Move a note to the recycle bin
userAPI.put('/users/notes/delete/:noteId', tokenVerify, async (req, res) => {
    const { noteId } = req.params;
    const usersCollection = req.app.get('usersCollection');

    try {
        // Find the logged-in user
        const user = await usersCollection.findOne({ username: req.user.username });

        if (!user) {
            return res.status(404).send({ message: 'User not found' });
        }

        // Update the note to mark as deleted
        const updatedNotes = user.notes.map(note =>
            note.noteId === noteId ? { ...note, isDeleted: true, deletedAt: new Date() } : note
        );

        await usersCollection.updateOne({ username: req.user.username }, { $set: { notes: updatedNotes } });

        res.status(200).send({ message: 'Note moved to recycle bin' });
    } catch (error) {
        res.status(500).send({ message: 'Error deleting note', error: error.message });
    }
});

// Get all notes in the recycle bin for the logged-in user
userAPI.get('/users/notes/recycle-bin', tokenVerify, async (req, res) => {
    const usersCollection = req.app.get('usersCollection');

    try {
        // Find the logged-in user
        const user = await usersCollection.findOne({ username: req.user.username });

        if (!user) {
            return res.status(404).send({ message: 'User not found' });
        }

        // Filter notes that are in the recycle bin
        const deletedNotes = user.notes.filter(note => note.isDeleted);

        res.status(200).send(deletedNotes);
    } catch (error) {
        res.status(500).send({ message: 'Error fetching deleted notes', error: error.message });
    }
});

// Undo delete (restore a note from recycle bin)
userAPI.put('/users/notes/undo-delete/:noteId', tokenVerify, async (req, res) => {
    const { noteId } = req.params;
    const usersCollection = req.app.get('usersCollection');

    try {
        // Find the logged-in user
        const user = await usersCollection.findOne({ username: req.user.username });

        if (!user) {
            return res.status(404).send({ message: 'User not found' });
        }

        // Update the note to restore it from the recycle bin
        const updatedNotes = user.notes.map(note =>
            note.noteId === noteId ? { ...note, isDeleted: false, deletedAt: null } : note
        );

        await usersCollection.updateOne({ username: req.user.username }, { $set: { notes: updatedNotes } });

        res.status(200).send({ message: 'Note restored from recycle bin' });
    } catch (error) {
        res.status(500).send({ message: 'Error restoring note', error: error.message });
    }
});

// Fetch all favorite notes for the logged-in user
userAPI.get('/users/notes/favorites', tokenVerify, async (req, res) => {
    const usersCollection = req.app.get('usersCollection');

    try {
        // Find the logged-in user
        const user = await usersCollection.findOne({ username: req.user.username });

        if (!user) {
            return res.status(404).send({ message: 'User not found' });
        }

        // Filter notes that are marked as favorite and not in the recycle bin
        const favoriteNotes = user.notes.filter(note => note.isFavorite && !note.isDeleted);

        res.status(200).send(favoriteNotes);
    } catch (error) {
        res.status(500).send({ message: 'Error fetching favorite notes', error: error.message });
    }
});

// Get the username of the current logged-in user
userAPI.get('/users/me', tokenVerify, async (req, res) => {
    try {
        // The username is available from the tokenVerify middleware
        const username = req.user.username;

        if (!username) {
            return res.status(404).send({ message: 'User not found' });
        }

        res.status(200).send({ username });
    } catch (error) {
        res.status(500).send({ message: 'Error fetching user', error: error.message });
    }
});

// Fetch a note by noteId for the logged-in user
userAPI.get('/users/notes/:noteId', tokenVerify, async (req, res) => {
    const { noteId } = req.params;
    const usersCollection = req.app.get('usersCollection');

    try {
        // Find the logged-in user
        const user = await usersCollection.findOne({ username: req.user.username });

        if (!user) {
            return res.status(404).send({ message: 'User not found' });
        }

        // Find the note with the specified noteId
        const note = user.notes.find(note => note.noteId === noteId);

        if (!note || note.isDeleted) {
            return res.status(404).send({ message: 'Note not found or is in the recycle bin' });
        }

        res.status(200).send(note);
    } catch (error) {
        res.status(500).send({ message: 'Error fetching note', error: error.message });
    }
});

// Permanently delete a note for the logged-in user
userAPI.delete('/users/notes/permanent-delete/:noteId', tokenVerify, async (req, res) => {
    const { noteId } = req.params;
    const usersCollection = req.app.get('usersCollection');

    try {
        // Find the logged-in user
        const user = await usersCollection.findOne({ username: req.user.username });

        if (!user) {
            return res.status(404).send({ message: 'User not found' });
        }

        // Filter out the note to permanently delete it
        const updatedNotes = user.notes.filter(note => note.noteId !== noteId);

        // Update the user's notes array in the database
        await usersCollection.updateOne({ username: req.user.username }, { $set: { notes: updatedNotes } });

        res.status(200).send({ message: 'Note permanently deleted' });
    } catch (error) {
        res.status(500).send({ message: 'Error deleting note permanently', error: error.message });
    }
});


module.exports = userAPI;



