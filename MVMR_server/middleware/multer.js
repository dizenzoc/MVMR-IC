/* middleware multer per l'upload dei file XML */
var multer  = require('multer');

const storage = multer.diskStorage({ //setting multer
    destination : (req, file, callback) => { 
        callback(null, 'public/xmls') //destinazione in cui salvare i file xmls
    },
    filename : (req, file, callback) => {
        callback(null, file.originalname) //definisce il nome da dare al file che viene caricato
    }
})

var upload = multer({storage : storage/*, fileFilter, fileFilter*/}) //storage dei file XMLs


module.exports = upload;

