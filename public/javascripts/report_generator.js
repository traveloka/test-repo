function _generate_report(data) {
    var json_data = JSON.stringify(data);
    var layout = ' \
                <!DOCTYPE html> \
                <meta charset="utf-8"/> \
                <html> \
                    <head> \
                        <link rel="stylesheet" type="text/css" href="https://stackpath.bootstrapcdn.com/bootstrap/4.1.3/css/bootstrap.min.css" /> \
                        <script src="https://cdn.jsdelivr.net/npm/countup@1.8.2/dist/countUp.min.js" integrity="sha256-9vWhvsKDjFldeHpXPfbzJxt2cotNqMonlIVp9cQc690=" crossorigin="anonymous"></script> \
                        <script type="text/javascript" src="http://yourjavascript.com/011112557218/component-utils.js"></script> \
                        <script src="https://code.jquery.com/jquery-3.3.1.slim.min.js" integrity="sha256-3edrmyuQ0w65f8gfBsqowzjJe2iM6n0nKciPUp8y+7E=" crossorigin="anonymous"></script> \
                    </head> \
                    <body> \
                        <div class="jumbotron"> \
                            <h1 class="display-4">TOSS</h1> \
                            <p class="lead">Traveloka Open Secuirty Scanner</p> \
                            <hr class="my-4"> \
                            <p>Reports CVEs in third party libraries.</p> \
                            <p class="lead"> \
                                <a class="btn btn-primary btn-lg" href="#" role="button">Learn more</a> \
                            </p> \
                        </div> \
    ';

    var stat_table = ' \
                    <div class="container">\
                        <table class="table"> \
                            <thead class="thead-dark"> \
                                <tr> \
                                <th scope="col">Affected files</th> \
                                <th scope="col">Total Vulnerabilities</th> \
                                <th scope="col">Low</th> \
                                <th scope="col">Medium</th> \
                                <th scope="col">High</th> \
                                <th scope="col">Critical</th> \
                                </tr> \
                            </thead> \
                            <tbody> \
                                <tr scope="row"> \
                                    <td><span id="affected">0</span></td> \
                                    <td><span id="total-vuln">0</span></td> \
                                    <td><span id="low">0</span></td> \
                                    <td><span id="med">0</span></td> \
                                    <td><span id="high">0</span></td> \
                                    <td><span id="critical">0</span></td> \
                                </tr> \
                            </tbody> \
                        </table> \
                    </div> \
    '; 
    var cve_table = '\
                        <table class="table"> \
                            <thead> \
                                <tr> \
                                    <th class="serial">#</th> \
                                    <th>Name</th> \
                                    <th>Severity</th> \
                                    <th>Current Version</th> \
                                    <th>Below Affected Versions</th> \
                                    <th>At or Above Affected Versions</th> \
                                    <th>CVE ID</th> \
                                    <th>Summary</th> \
                                </tr> \
                            </thead> \
                            <tbody class="vuln-body"></tbody> \
                        </table> \
    ';
    var cve_data = '<script>' + 'json_data = ' + json_data + ';' + '</script>';
    var parse_script = ' \
                        <script>  \
                           parse_data(json_data);\
                        </script>\
    ';
    var footer = '</body></html>';
    var html = layout + stat_table + cve_table + cve_data + parse_script + footer;
    return html;
}

module.exports = {
    generate_report: _generate_report,
};