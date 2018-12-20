var express = require('express');
var router = express.Router();
var shell = require('shelljs');
var vuln_scanner = require('../public/javascripts/scanner_util');
var report = require('../public/javascripts/report_generator');
var mongoose = require('mongoose');
var multer = require('multer');
var fs = require('fs');

var storage = multer.diskStorage(
  {
      destination: 'repositories/uploads/',
      filename: function ( req, file, cb ) {
          file_name = file.originalname;
          cb( null, file.originalname);
      }
  }
);

var upload = multer( { storage: storage } );

// Bring in models
let vulnStat = require('../models/vulnStats');
var connection = false;
// Connect to mongoDB database
// mongoose.connect('mongodb://localhost/vulnDB');

const options = {
  reconnectTries: 30, // Retry up to 30 times
  reconnectInterval: 500, // Reconnect every 500ms
  poolSize: 10, // Maintain up to 10 socket connections
  // If not connected, return errors immediately rather than waiting for reconnect
  bufferMaxEntries: 0
}

const connectWithRetry = () => {
console.log('MongoDB connection with retry')
mongoose.connect("mongodb://mongo:27017/vulnDB", options).then(()=>{
  console.log('MongoDB is connected');
  connection = true
  // setTimeout(git_sync, 10000)

}).catch(err=>{
  console.log('MongoDB connection unsuccessful, retry after 5 seconds.')
  setTimeout(connectWithRetry, 5000)
})
}

connectWithRetry()
console.log('Filling DB please wait...')

/* GET home page. */
router.get('/', function(req, res, next) {
  res.render('index', { title: 'Wookie Scanner' });
});

router.get('/scanner', function(req, res, next) {
  res.render('scanner', { title: 'Wookie Scanner' });
});

router.get('/about', function(req, res, next) {
  res.render('about', { title: 'Wookie Scanner' });
});

router.get('/bus', function(req, res, next) {
  res.render('Bus', { title: 'Wookie Scanner' });
});

router.get('/train', function(req, res, next) {
  res.render('Train', { title: 'Wookie Scanner' });
});

router.get('/hotels', function(req, res, next) {
  res.render('Hotels', { title: 'Wookie Scanner' });
});

router.get('/payments', function(req, res, next) {
  res.render('Payments', { title: 'Wookie Scanner' });
});

router.get('/git_scanner', function(req, res, next) {
  res.render('git_scanner', { title: 'Wookie Scanner' });
});

router.get('/git_scan_project_vuln_details', function(req, res, next) {
  res.render('git_scan_report', { title: 'Wookie Scanner' });
});

router.get('/scanner_results', function(req, res, next) {
  res.render('scanner_results', { title: 'Wookie Scanner' });
});

router.get('/force_sync', function(req, res, next) {
  git_sync();
  res.send("sync done");
});


router.post('/scanner', function(req, res, next) {
  var path = req.body.path;
  a = shell.exec('retire --outputformat=json --path=' + path);
  data = a['stderr'];
  results = vuln_scanner.get_vuln_stats(JSON.parse(data));
  res.send(results);
});

router.post('/test', function(req, res, next) {
  var repo_path = req.body.path;
  console.log(repo_path)
  // a = shell.exec('git status contentfe');
  res.send({"OK" : repo_path});
});

router.post('/sync', function(req, res, next) {
  // Check git status, update table, return changes.
  let project = req.body.projectName;
  shell.cd('repositories');
  shell.cd(project);
  shell.exec('git fetch');
  let status_message = shell.exec('git status');
  let need_update = !(status_message.includes('Your branch is up-to-date'));
  console.log('response for git pull: ')
  console.log(need_update)
  console.log('\n')
  if(need_update) {
    shell.exec('git pull');
    console.log('\n\nPulled\n\n');

    a = shell.exec('retire --outputformat=json');
    data = a['stderr'];
    results = vuln_scanner.get_vuln_stats(JSON.parse(data));
    console.log(results)
    var last_scan = new Date.now();

    vulnStat.find({projectName: project}, function(err, res) {
      if(err) {
        console.log(err)
      }
      else {
        if(res.length == 0) {
          p = new vulnStat({projectName : project})
          p.save();
        }
      }
    });

    vulnStat.updateOne({
      projectName: project
    }, {$set: { affectedFiles: results[0], totalVuln: results[1], low: results[2], med: results[3], high: results[4], critical: results[5], lastScan: last_scan }})
      .exec(function(err, stats){
        if(err) {
          console.log(err);
        }
        else {
          console.log('Updated');
        }
      });
  }
  shell.cd('..');
  shell.cd('..');

  res.send(need_update);
});

router.post('/get_stats', function(req, res, next) {
  // Check git status, update table, return changes.
  let projectName = req.body.projectName;
  console.log(projectName)
  vulnStat.find({
    projectName: projectName
  })
    .exec(function(err, stats){
      if(err) {
        console.log(err);
      }
      else {
        res.send(stats);
      }
    });
});

router.post('/scan_project_vuln_details', function(req, res, next) {
  let projectName = req.body.projectName;
  shell.cd('repositories');
  shell.cd(projectName);
  var error_msg = shell.error();
  if(error_msg != undefined && error_msg.includes('no')) {
    res.send(false);
    shell.cd('..');
  }
  else {
    shell.exec('npm install');
    a = shell.exec('retire --outputformat=json');
    data = a['stderr'];
    shell.cd('..')
    shell.cd('..')
    console.log('OUTPUT')
    console.log(a)
    if(data.length == 0) {
      data = a;
    }
    res.send(JSON.parse(data));
  }
})

router.post('/local_scan_project_vuln_details', function(req, res, next) {

  let fileName = req.body.fileName;
  shell.cd('repositories');
  shell.cd('uploads');
  console.log('PATH:')
  shell.exec('ls');
  shell.exec('unzip ' + fileName);
  // Remove .zip extension
  fileName = fileName.split('.');
  fileName = fileName[0];
  shell.cd(fileName);
  var error_msg = shell.error();
  if(error_msg != undefined && error_msg.includes('no')) {
    res.send(false);
    shell.cd('..');
  }
  else {
    shell.exec('npm install');
    a = shell.exec('retire --outputformat=json');
    data = a['stderr'];
    shell.cd('..')
    shell.cd('..')
    shell.rm('-r', 'uploads');
    shell.cd('..')
    res.send(JSON.parse(data));
  }
})

router.post('/project_vuln_details', function(req, res, next) {

  let projectName = req.body.projectName;
  var error_msg = shell.error();

  if(error_msg != undefined && error_msg.includes('no')) {
    res.send(false);
    shell.cd('..');
  }
  else {
    shell.cd('vuln_files');
    var contents = fs.readFileSync(projectName+'.txt', 'utf8');
    shell.cd('..');
    res.send(JSON.parse(contents));
  }
});

router.post('/sum', function(req, res, next) {
  var totalLow = 0;
  var totalMed = 0;
  var totalHigh = 0;
  var totalCritical = 0;
  vulnStat.aggregate([
    {
        $group: {
            _id: '$_id',  //$region is the column name in collection
            totalLow: {$sum: '$low'},
            totalMed: {$sum: '$med'},
            totalHigh: {$sum: '$high'},
            totalCritical: {$sum: '$critical'}
        }
    }
  ], function (err, result) {
    if (err) {
        next(err);
    } else {
        result.forEach(item => {
          totalLow += item['totalLow'];
          totalMed += item['totalMed'];
          totalHigh += item['totalHigh'];
          totalCritical += item['totalCritical'];
        });
        res.json([totalLow, totalMed, totalHigh, totalCritical]);
    }
  });
});

function git_sync() {
  if(connection) {
    var projects = ["Bus", "Train", "Payment", "Hotels"];
    projects.forEach(project => {
      shell.cd('repositories');
      shell.cd(project);
      a = shell.exec('retire --outputformat=json');
      data = a['stderr'];
      results = vuln_scanner.get_vuln_stats(JSON.parse(data));
      console.log(results);
      var last_scan = new Date(Date.now()).toLocaleString();

      vulnStat.find({projectName: project}, function(err, res) {
        if(err) {
          console.log(err)
        }
        else {
          if(res.length == 0) {
            p = new vulnStat({projectName : project})
            p.save();
          }
        }
        
      });

      vulnStat.updateOne({
        projectName: project
        }, {$set: { affectedFiles: results[0], totalVuln: results[1], low: results[2], med: results[3], high: results[4], critical: results[5], lastScan: last_scan }})
        .exec(function(err, stats){
          if(err) {
            console.log(err);
          }
          else {
            console.log('Updated');
          }
        });

      shell.cd('..');
      shell.cd('..');

      shell.cd('vuln_files');
      fs.writeFile(project + '.txt', data, function (err) {
        if (err) throw err;
        console.log(project + '.txt');
        console.log('Saved!');
      }); 

      shell.cd('..');
    });
  }
  else {
    setTimeout(git_sync, 5000)
  }
}

router.post('/git_scan_clone', function(req, res, next) {
  shell.cd('repositories');
  var url = req.body.url;
  url_array = url.split('/');
  projectName = url_array[url_array.length - 1];
  // if URL is https://name/project/
  if(projectName.length == 0) {
    projectName = url_array[url_array.length - 2];
  }
  projectName = projectName.slice(0, projectName.length - 4);
  shell.cd(projectName);
  var exists = shell.error()
  var message;
  console.log(url)
  console.log(exists)
  if(exists != undefined && exists.includes('no')) {
    // Repository does not exist
    // Clone, scan and report
    shell.exec('git clone ' + url);
    error_msg = shell.error();
    
    if(error_msg != undefined && error_msg.includes('fatal')) {
      message = 'Invalid';
    }
    else {
      message = 'Cloned';
    }
    shell.cd('..');
    
  }
  else {
    // Repository exists

    // git pull
    shell.exec('git fetch');
    command = 'git status';
    let status_message = shell.exec(command);
    let need_update = !(status_message.includes('Your branch is up-to-date'));
    if(need_update) {
      shell.exec('git pull');
      console.log('\n\nPulled\n\n');
    }
    shell.cd('..');
    shell.cd('..');
    message = 'Exists';
  }
  res.send(message);

});

// setInterval(git_sync, 10000);
// git_sync()

module.exports = router;

// Upload hack
router.post('/file', upload.single('file-to-upload'), (req, res) => {
  res.redirect('/scanner_results');
});


router.post('/scanner', function(req, res, next) {
  var path = req.body.path;
  a = shell.exec('retire --outputformat=json --path=' + path);
  data = a['stderr'];
  res.send(data);
});

router.post('/report', function(req, res, next) {
  let projectName = req.body.projectName;
  shell.cd('repositories');
  shell.cd(projectName);
  var error_msg = shell.error();
  if(error_msg != undefined && error_msg.includes('no')) {
    res.send(false);
    shell.cd('..');
  }
  else {
    shell.exec('npm install');
    a = shell.exec('retire --outputformat=json');
    data = a['stderr'];
    shell.cd('..')
    shell.cd('..')
    console.log('OUTPUT')
    console.log(a)
    if(data.length == 0) {
      data = a;
    }
    html_report = report.generate_report(JSON.parse(data));
    fs.writeFile('report000000.html', html_report, function (err) {
      if (err) throw err;
      console.log('REPORT GENERATED!');
    }); 
    res.send(html_report);
  }  
});

module.exports = router;