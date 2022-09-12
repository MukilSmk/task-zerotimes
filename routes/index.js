const express = require('express');
const router = express.Router();
const AdmZip = require("adm-zip");
const fs = require("fs");
const path = require('path')
const {
  upload
} = require("../helpers/multer");
const {
  constants
} = require('fs/promises');



/*Upload and Extract Multiple zip files */

router.post('/upload-files', upload.array('zipfile'),
  function (req, res, next) {
    try {
      if (req.files.length != 0) {
        // Passes the path of the multiple uploaded files
        req.files.forEach((item, index) => {
          const extract_directory = path.join(__dirname, "..", 'extracted_files')
          const zip = new AdmZip(path.join(__dirname, "..", item.path));
          zip.extractAllTo(extract_directory);

          if (req.files.length - 1 === index) {
            return res.json({
              success: true,
              message: "All files have been extracted successfully"
            })
          }

        })

      }

    } catch (err) {
      console.log(err)
      res.send(err)
    }
  });


/* GET home page. */
router.post('/search-cve-records', async function (req, res, next) {
  try {
    const search = req.body.search
    let matched_cpe23Uri = []
    const directoryPath = "./extracted_files/"
    fs.readdir(directoryPath, (err, files_in_path) => {
      if (err) {
        return res.send(err)
      }
      files_in_path.forEach((files_in_path_item, files_in_path_index) => {

        //Reading the first json file in extracted folder
        fs.readFile(`./extracted_files/${files_in_path_item}`, 'utf8', async (err, data) => {
          if (err) {
            console.log(err)
            res.send(err)
          }
          const result = JSON.parse(data)

          result.CVE_Items.forEach((item, index) => {
            if (item.configurations.nodes.length > 0) {
              let nodes = item.configurations.nodes

              nodes.forEach((nodes_item, nodes_index) => {
                let cpe_match = nodes_item.cpe_match
                cpe_match.forEach((cpe_match_item, cpe_match_index) => {
                  // Matching the search elements with the cpe23 uri in the JSON File
                  search.forEach((search_item, search_index) => {
                    let cpe23_uri_elements = search_item.split(":")
                    let split_cpe23Uri = cpe_match_item.cpe23Uri.split(":")
                    if (cpe_match_item.cpe23Uri === search_item) {
                      matched_cpe23Uri.push(item.cve.CVE_data_meta.ID)
                      return;
                    }
                    if (cpe23_uri_elements[2] === split_cpe23Uri[2] && cpe23_uri_elements[3] === split_cpe23Uri[3] && cpe23_uri_elements[4] === split_cpe23Uri[4] && cpe23_uri_elements[5] === split_cpe23Uri[5]) {
                      matched_cpe23Uri.push(item.cve.CVE_data_meta.ID)
                      return;
                    }

                    if (cpe23_uri_elements[2] === split_cpe23Uri[2] && cpe23_uri_elements[4] === split_cpe23Uri[4] && cpe23_uri_elements[5] === split_cpe23Uri[5]) {
                      matched_cpe23Uri.push(item.cve.CVE_data_meta.ID)
                      return;
                    }
                    if (cpe23_uri_elements[2] === split_cpe23Uri[2] && cpe23_uri_elements[4] === split_cpe23Uri[4] && cpe23_uri_elements[3] === split_cpe23Uri[3]) {
                      matched_cpe23Uri.push(item.cve.CVE_data_meta.ID)
                      return;
                    }

                    if (files_in_path.length - 1 === files_in_path_index && search.length - 1 === search_index && cpe_match.length - 1 === cpe_match_index && result.CVE_Items.length - 1 === index) {
                      return res.json({
                        message: "Success",
                        data: matched_cpe23Uri,
                      })
                    }
                  })
                })
              })
            }
          });
        })
      })
    })
  } catch (err) {
    console.log(err)
    res.send(err)


  }

});

// Function to extract the archived zip files
async function extractArchive(file_path, output_dir) {
  try {
    const zip = new AdmZip(file_path);
    zip.extractAllTo(output_dir);
    let extracted_file_path = file_path.split('/').slice(-1)[0].split("_").slice(-1)[0]
    extracted_file_path = "./extracted_files/" + extracted_file_path.slice(0, extracted_file_path.length - 4)
    return extracted_file_path.toString();

  } catch (e) {
    console.log(`Something went wrong. ${e}`);
  }
}




module.exports = router;
