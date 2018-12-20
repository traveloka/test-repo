var repos = ['Bus', 'Train', 'Payment', 'Hotels'];
var options = {
	classname: 'p-bar',
    id: 'p-bar',
    target: document.getElementById('myDivId'),
    bg: '#42f4b3'
};

var nanobar = new Nanobar( options );

function update_cells(projectName, total_vuln, low, med, high, critical, r_time) {
    $('.tot' + projectName).text(total_vuln);
    $('.low' + projectName).text(low);
    $('.med' + projectName).text(med);
    $('.high' + projectName).text(high);
    $('.critical' + projectName).text(critical);
    var raw_time = r_time;
    var raw_time = raw_time.split('T');
    var date = raw_time[0];
    var time = raw_time[1].slice(0,8);
    $('.time' + projectName).text('Last scan: ' + date + ' ' + time);
}

$.post( "/sum", { }, function( data ) {
    donut_chart(data[0], data[1], data[2], data[3])
    var tot = data[0] + data[1] + data[2] + data[3];
    fill_header(tot, data[0], data[1], data[2], data[3])
});

// Get stats for each project
repos.forEach(repo => {
    $.post( "/get_stats", { projectName : repo }, function( data ) {
        // console.log(data[0]);
        update_cells(data[0]['projectName'], data[0]['totalVuln'], data[0]['low'], data[0]['med'], data[0]['high'], data[0]['critical'], data[0]['lastScan']);
    });
});

// Git Sync
$('.syncBus').click(function() {
    $.LoadingOverlay("show");
    $.post( "/sync", { projectName : 'Bus' }, function( data ) {
        if(data) {
            alertify.message('Detected changes in master Branch');
            alertify.message('Pulling changes...');
            $.post( hostname + "/get_stats", { projectName : 'Bus' }, function( data ) {
                update_cells(data[0]['projectName'], data[0]['totalVuln'], data[0]['low'], data[0]['med'], data[0]['high'], data[0]['critical'], data[0]['lastScan']);
            });
            $.LoadingOverlay("hide");
            alertify.success('Repository is now up to date!');
        }
        else {
            alertify.success('Repository is up to date!');
            $.LoadingOverlay("hide");
        }
    });
});

$('.syncTrain').click(function() {
    $.LoadingOverlay("show");
    $.post( "/sync", { projectName : 'Train' }, function( data ) {
        if(data) {
            alertify.message('Detected changes in master Branch');
            alertify.message('Pulling changes...');
            $.post( hostname + "/get_stats", { projectName : 'Train' }, function( data ) {
                update_cells(data[0]['projectName'], data[0]['totalVuln'], data[0]['low'], data[0]['med'], data[0]['high'], data[0]['critical'], data[0]['lastScan']);
            });
            $.LoadingOverlay("hide");
            alertify.success('Repository is now up to date!');
        }
        else {
            alertify.success('Repository is up to date!'); 
            $.LoadingOverlay("hide");
        }
    });
});

$('.syncPayments').click(function() {
    $.LoadingOverlay("show");
    $.post( "/sync", { projectName : 'Payment' }, function( data ) {
        if(data) {
            alertify.message('Detected changes in master Branch');             
            alertify.message('Pulling changes...'); 
            $.post( hostname + "/get_stats", { projectName : 'Payment' }, function( data ) {
                update_cells(data[0]['projectName'], data[0]['totalVuln'], data[0]['low'], data[0]['med'], data[0]['high'], data[0]['critical'], data[0]['lastScan']);
            });
            $.LoadingOverlay("hide");
            alertify.success('Repository is now up to date!');
        }
        else {
            alertify.success('Repository is up to date!');
            $.LoadingOverlay("hide");
        }
    });
});

$('.syncHotels').click(function() {
    $.LoadingOverlay("show");
    $.post( "/sync", { projectName : 'Hotels' }, function( data ) {
        if(data) {
            alertify.message('Detected changes in master Branch');             
            alertify.message('Pulling changes...'); 
            $.post( hostname + "/get_stats", { projectName : 'Hotels' }, function( data ) {
                update_cells(data[0]['projectName'], data[0]['totalVuln'], data[0]['low'], data[0]['med'], data[0]['high'], data[0]['critical'], data[0]['lastScan']);
            });
            $.LoadingOverlay("hide");
            alertify.success('Repository is now up to date!');
        }
        else {
            alertify.success('Repository is up to date!');
            $.LoadingOverlay("hide");
        }
    });
});

function donut_chart(low, med, high, critical) {
    var ctx_donut = document.getElementById("doughnut-chart").getContext('2d');
    new Chart(ctx_donut, {
        type: 'doughnut',
        data: {
        labels: ["Low", "Medium", "High", "Critical"],
        datasets: [
            {
                backgroundColor: ["#1D748A","#00B285", "#FF5019","#B22A00"],
                data: [low ,med ,high, critical]
            }
        ]
        },
        options: {
            title: {
                display: true,
                text: 'Severity distribution'
            }
        }
    });
}

function fill_header(total_vuln, low, med, high, critical) {
    var total_ = new CountUp("total-vuln", 0, total_vuln);
    if (!total_.error) {
        total_.start();
    } else {
        console.error(total_.error);
    }
    var low_ = new CountUp("low", 0, low);
    if (!low_.error) {
        low_.start();
    } else {
        console.error(low_.error);
    }
    var med_ = new CountUp("med", 0, med);
    if (!med_.error) {
        med_.start();
    } else {
        console.error(med_.error);
    }
    var high_ = new CountUp("high", 0, high);
    if (!high_.error) {
        high_.start();
    } else {
        console.error(high_.error);
    }

    var critical_ = new CountUp("critical", 0, critical);
    if (!critical_.error) {
        critical_.start();
    } else {
        console.error(critical_.error);
    }
}