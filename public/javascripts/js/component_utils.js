function fill_stat_table(affected_files, total_vuln, low, med, high, critical) {
    var affected_ = new CountUp("affected", 0, affected_files);
    if (!affected_.error) {
        affected_.start();
    } else {
        console.error(affected_.error);
    }
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

    if(critical > 0 || high > 1) {
        $('.threat-level-number').text('III')
    }
    else if(high == 1 || med > 2) {
        $('.threat-level-number').text('II')
    }
    else if(total_vuln > 0){
        $('.threat-level-number').text('I')
    }
    else {
        $('.threat-level-number').text('0')
    }
}

function addRow(s_no, name, severity, current_version, affected_versions_below, affected_versions_above, cve_id, summary) {
    var sv_class = '';

    var low_flag = false;
    var med_flag = false;
    var high_flag = false;
    var critical_flag = false;

    if(severity == 'low') {
        sv_class = '"badge badge-low"';
        low_flag = true;
    }
    else if(severity == 'medium') {
        sv_class = '"badge badge-med"';
        med_flag = true;
    }
    else if(severity == 'high') {
        sv_class = '"badge badge-high"';
        high_flag = true;
    }
    else {
        sv_class = '"badge badge-critical"';
        critical_flag = true;        
    }
    if(affected_versions_above != '-') {
        affected_versions_above = '>=' + affected_versions_above;
    }
    if(cve_id.length < 2) {
        row = '<tr> <td class="serial">'+ s_no +'</td>   <td>' + name + '</td>  <td><span class=' + sv_class + '>' + severity + '</span></td>  <td>' + current_version + '</td>  <td>\<' + affected_versions_below + '</td>  <td>' + affected_versions_above + '</td>  <td>' +  cve_id + '</td>  <td>' + summary + '</td></tr>';
    }
    else {
        row = '<tr> <td class="serial">'+ s_no +'</td>   <td>' + name + '</td>  <td><span class=' + sv_class + '>' + severity + '</span></td>  <td>' + current_version + '</td>  <td>\<' + affected_versions_below + '</td>  <td>' + affected_versions_above + '</td>  <td><a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=' +  cve_id + '">' + cve_id + '</a> </td>  <td>' + summary + '</td></tr>';
    }
    
    if(low_flag) {
        low_rows.push(row);
    }
    else if(med_flag) {
        med_rows.push(row);
    }
    else if(high_flag) {
        high_rows.push(row);
    }
    else if(critical_flag) {
        crirtical_rows.push(row);
    }
    // $('.vuln-body').append(row);
}

function writeRow(low_rows, med_rows, high_rows, crirtical_rows) {
    crirtical_rows.forEach(element => {
        $('.vuln-body').append(element);
    });
    high_rows.forEach(element => {
        $('.vuln-body').append(element);
    });
    med_rows.forEach(element => {
        $('.vuln-body').append(element);
    });
    low_rows.forEach(element => {
        $('.vuln-body').append(element);
    });
}

function parse_data(data, callback) {
    // Overall vuln stats
    var affected_files = data['data'].length;
    var total_vuln = 0;
    var low = 0;
    var med = 0;
    var high = 0;
    var critical = 0;
    data['data'].forEach(file => {
        file['results'].forEach(vulns => {
            try {
                total_vuln += vulns['vulnerabilities'].length;
                for(var i = 0; i < vulns['vulnerabilities'].length; i++) {
                    if(vulns['vulnerabilities'][i]['severity'] == 'low') {
                        low += 1;
                    }
                    else if(vulns['vulnerabilities'][i]['severity'] == 'medium') {
                        med += 1;
                    }
                    else if(vulns['vulnerabilities'][i]['severity'] == 'high') {
                        high += 1;
                    }
                    else if(vulns['vulnerabilities'][i]['severity'] == 'critical') {
                        critical += 1;
                    }
                }                
            } catch (error) {
                console.log("NO VULNS");
            }
        });
    });

    // Details for each vuln
    s_no = 1
    data['data'].forEach(file => {
        file['results'].forEach(vulns => {
            try {
                name = vulns['component'];
                current_version = vulns['version'];
                for(var i = 0; i < vulns['vulnerabilities'].length; i++) {
                        severity = vulns['vulnerabilities'][i]['severity'];
                        // Affected versions below
                        try {
                            affected_versions_below = vulns['vulnerabilities'][i]['below'];
                        }
                        catch (error) {
                            affected_versions_below = '-'
                        }
                        // Affected version above
                        try {
                            affected_versions_above = vulns['vulnerabilities'][i]['atOrAbove'];
                            if(typeof affected_versions_above == 'undefined') {
                                affected_versions_above = '-';
                            }
                        }
                        catch (error) {
                            affected_versions_above = '-';
                        }
                        // CVE_ID and summary
                        try {
                            // CVE_ID
                            try {
                                cve_id = vulns['vulnerabilities'][i]['identifiers']['CVE'][0];
                            }
                            catch (error) {
                                cve_id = '-'
                            }
                            // Summary 
                            try {
                                summary = vulns['vulnerabilities'][i]['identifiers']['summary'];
                            }
                            catch (error) {
                                summary = '-';
                            }
                        }

                        catch (error) {
                            cve_id = '-';
                            summary = '-';
                        }
                        addRow(s_no++, name, severity, current_version, affected_versions_below, affected_versions_above, cve_id, summary)
                    }               
                }                
            catch (error) {
                console.log("NO VULNS");
            }
        });
    });    
    fill_stat_table(affected_files, total_vuln, low, med, high, critical);
    donut_chart(low, med, high, critical);
    writeRow(low_rows, med_rows, high_rows, crirtical_rows);
    line_chart();
    callback();
}

// Donut chart
function donut_chart(low, med, high, critical) {
    var ctx_donut = document.getElementById("doughnut-chart").getContext('2d');
    new Chart(ctx_donut, {
        type: 'doughnut',
        data: {
        labels: ["Low", "Medium", "High", "Critical"],
        datasets: [
            {
                label: "Population (millions)",
                backgroundColor: ["#1D748A","#00B285", "#FF5019","#B22A00"],
                data: [low, med, high, critical]
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

// Line history chart
function line_chart() {
    var ctx = document.getElementById("myChart").getContext('2d');
    var myChart = new Chart(ctx, {
        type: 'line',
        data: {
            labels: [new Date("2018-3-1").toDateString(), new Date("2018-4-1").toDateString(), new Date("2018-5-1").toDateString(), new Date("2018-6-1").toDateString(), new Date("2018-7-1").toDateString(), new Date("2018-8-1").toDateString(), new Date("2018-9-1").toDateString()],
            datasets: [{
            data: [{t: new Date("2018-3-1"), y: 2},{t: new Date("2018-4-1"), y: 5},{t: new Date("2018-5-1"), y: 6},{t: new Date("2018-6-1"), y: 3},{t: new Date("2018-7-1"), y: 7},{t: new Date("2018-8-1"), y: 1},{t: new Date("2018-5-1"), y: 4}],
            label: "Number of vulnerabilities",
            borderColor: "#3e95cd",
            fill: false
            }
            ]
        },
        options: {
            title: {
                display: false,
                text: 'Count history'
            },
            scales: {
                yAxes: [{
                    ticks: {
                        padding: 0,
                    }
                }],
                xAxes: [{
                    ticks: {
                        padding: 0,
                        display: false
                    },
                }],
            },
        }
    });
}