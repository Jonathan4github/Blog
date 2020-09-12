const express = require('express');
const router = express.Router();
const blogController = require('../controllers/blog');

router.get('/', blogController.time);

module.exports = router;
