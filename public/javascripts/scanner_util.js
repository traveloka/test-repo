function _get_vuln_stats(data) {
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
    return [affected_files, total_vuln, low, med, high, critical];
}

function _get_vuln_details(data) {
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
}

module.exports = {
    get_vuln_stats: _get_vuln_stats,
    get_vuln_details: _get_vuln_details
};