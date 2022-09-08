const multer = require('multer')


/**
 * File Path to store the CollectionImage
 */
const storage = multer.diskStorage({
    destination: function (req, file, cb) {
        cb(null, './upload/')
    },
    filename: function (req, file, cb) {
        cb(null, new Date().toISOString().replace(/:/g, '-') + "_" + file.originalname)
    }
})

const upload = multer({
    storage: storage
})
module.exports = {
    upload: upload
}