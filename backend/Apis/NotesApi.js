const exp = require('express');
const notesApp = exp.Router();
const expressAsyncHandler = require('express-async-handler');
const bcrypt = require('bcrypt');
const { ObjectId } = require('mongodb');
const saltRounds = 10;
const tokenVerify = require('../middlewares/tokenVerify'); // Import tokenVerify middleware

notesApp.use(exp.json());

// Create a new note
notesApp.post('/create-note', tokenVerify, expressAsyncHandler(async (req, res) => {
    const notesCollection = req.app.get('notesCollection');
    const { title, content, tags } = req.body;
    const username = req.user.username;

    if (!title || !content) {
        return res.status(400).send({ message: "Title and content are required" });
    }

    // Hash the note content
    const hashedContent = await bcrypt.hash(content, saltRounds);

    let newNote = {
        username,
        title,
        content: hashedContent, // Store hashed content
        tags: tags || [], // Default to an empty array if no tags are provided
        favorites: false, // Default to not being a favorite
        createdAt: new Date(),
        deletedAt: null // Track deleted time for recycle bin functionality
    };

    await notesCollection.insertOne(newNote);
    res.send({ message: "Note Created", payload: newNote });
}));

// Get all notes for the logged-in user
notesApp.get('/notes', tokenVerify, expressAsyncHandler(async (req, res) => {
    const notesCollection = req.app.get('notesCollection');
    const username = req.user.username;

    const userNotes = await notesCollection.find({ username }).toArray();
    
    // Unhash content for displaying to the user
    for (const note of userNotes) {
        note.content = await bcrypt.compare(note.content, note.content) ? note.content : "Error retrieving content";
    }

    res.send({ message: "User Notes", payload: userNotes });
}));

// Get notes by tag
notesApp.get('/notes/tag/:tag', tokenVerify, expressAsyncHandler(async (req, res) => {
    const notesCollection = req.app.get('notesCollection');
    const username = req.user.username;
    const tag = req.params.tag;

    const notesByTag = await notesCollection.find({ username, tags: tag }).toArray();
    
    // Unhash content for displaying to the user
    for (const note of notesByTag) {
        note.content = await bcrypt.compare(note.content, note.content) ? note.content : "Error retrieving content";
    }

    res.send({ message: `Notes with tag '${tag}'`, payload: notesByTag });
}));

// Get all favorite notes
notesApp.get('/notes/favorites', tokenVerify, expressAsyncHandler(async (req, res) => {
    const notesCollection = req.app.get('notesCollection');
    const username = req.user.username;

    const favoriteNotes = await notesCollection.find({ username, favorites: true }).toArray();
    
    // Unhash content for displaying to the user
    for (const note of favoriteNotes) {
        note.content = await bcrypt.compare(note.content, note.content) ? note.content : "Error retrieving content";
    }

    res.send({ message: "Favorite Notes", payload: favoriteNotes });
}));

// Add tag to a note
notesApp.put('/notes/add-tag/:noteId', tokenVerify, expressAsyncHandler(async (req, res) => {
    const notesCollection = req.app.get('notesCollection');
    const noteId = req.params.noteId;
    const { tag } = req.body;

    if (!tag) {
        return res.status(400).send({ message: "Tag is required" });
    }

    const result = await notesCollection.updateOne(
        { _id: new ObjectId(noteId), username: req.user.username },
        { $addToSet: { tags: tag } } // Use $addToSet to avoid duplicate tags
    );

    if (result.modifiedCount === 0) {
        return res.status(404).send({ message: "Note not found or not owned by user" });
    }

    res.send({ message: "Tag added to note" });
}));

// Remove tag from a note
notesApp.put('/notes/remove-tag/:noteId', tokenVerify, expressAsyncHandler(async (req, res) => {
    const notesCollection = req.app.get('notesCollection');
    const noteId = req.params.noteId;
    const { tag } = req.body;

    if (!tag) {
        return res.status(400).send({ message: "Tag is required" });
    }

    const result = await notesCollection.updateOne(
        { _id: new ObjectId(noteId), username: req.user.username },
        { $pull: { tags: tag } } // Use $pull to remove the tag
    );

    if (result.modifiedCount === 0) {
        return res.status(404).send({ message: "Note not found or not owned by user" });
    }

    res.send({ message: "Tag removed from note" });
}));

// Mark a note as favorite
notesApp.put('/notes/favorite/:noteId', tokenVerify, expressAsyncHandler(async (req, res) => {
    const notesCollection = req.app.get('notesCollection');
    const noteId = req.params.noteId;

    const result = await notesCollection.updateOne(
        { _id: new ObjectId(noteId), username: req.user.username },
        { $set: { favorites: true } }
    );

    if (result.modifiedCount === 0) {
        return res.status(404).send({ message: "Note not found or not owned by user" });
    }

    res.send({ message: "Note marked as favorite" });
}));

// Unmark a note as favorite
notesApp.put('/notes/unfavorite/:noteId', tokenVerify, expressAsyncHandler(async (req, res) => {
    const notesCollection = req.app.get('notesCollection');
    const noteId = req.params.noteId;

    const result = await notesCollection.updateOne(
        { _id: new ObjectId(noteId), username: req.user.username },
        { $set: { favorites: false } }
    );

    if (result.modifiedCount === 0) {
        return res.status(404).send({ message: "Note not found or not owned by user" });
    }

    res.send({ message: "Note unmarked as favorite" });
}));

// Delete a note (move to recycle bin)
notesApp.put('/notes/delete/:noteId', tokenVerify, expressAsyncHandler(async (req, res) => {
    const notesCollection = req.app.get('notesCollection');
    const noteId = req.params.noteId;

    const result = await notesCollection.updateOne(
        { _id: new ObjectId(noteId), username: req.user.username },
        { $set: { deletedAt: new Date() } } // Move note to recycle bin by setting deletedAt
    );

    if (result.modifiedCount === 0) {
        return res.status(404).send({ message: "Note not found or not owned by user" });
    }

    res.send({ message: "Note moved to recycle bin" });
}));

// Restore a note from recycle bin
notesApp.put('/notes/restore/:noteId', tokenVerify, expressAsyncHandler(async (req, res) => {
    const notesCollection = req.app.get('notesCollection');
    const noteId = req.params.noteId;

    const result = await notesCollection.updateOne(
        { _id: new ObjectId(noteId), username: req.user.username },
        { $set: { deletedAt: null } } // Restore note by setting deletedAt to null
    );

    if (result.modifiedCount === 0) {
        return res.status(404).send({ message: "Note not found or not owned by user" });
    }

    res.send({ message: "Note restored from recycle bin" });
}));

// Permanently delete a note
notesApp.delete('/notes/permanent-delete/:noteId', tokenVerify, expressAsyncHandler(async (req, res) => {
    const notesCollection = req.app.get('notesCollection');
    const noteId = req.params.noteId;

    const result = await notesCollection.deleteOne(
        { _id: new ObjectId(noteId), username: req.user.username }
    );

    if (result.deletedCount === 0) {
        return res.status(404).send({ message: "Note not found or not owned by user" });
    }

    res.send({ message: "Note permanently deleted" });
}));

// Get notes in the recycle bin
notesApp.get('/notes/recycle-bin', tokenVerify, expressAsyncHandler(async (req, res) => {
    const notesCollection = req.app.get('notesCollection');
    const username = req.user.username;

    const recycleBinNotes = await notesCollection.find({ username, deletedAt: { $ne: null } }).toArray();
    
    // Unhash content for displaying to the user
    for (const note of recycleBinNotes) {
        note.content = await bcrypt.compare(note.content, note.content) ? note.content : "Error retrieving content";
    }

    res.send({ message: "Notes in Recycle Bin", payload: recycleBinNotes });
}));

module.exports = notesApp;
