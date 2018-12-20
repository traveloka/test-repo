var options = {
	classname: 'p-bar',
    id: 'p-bar',
    target: document.getElementById('myDivId'),
    bg: '#42f4b3'
};

var nanobar = new Nanobar( options );

$('.clonebtn').click(function() {
    var url_input = $('.searchtext').val();
    nanobar.go( 20 );
    var result;
    if(url_input.length != 0) {
        $.post('/git_scan_clone', { url : url_input }, function( data ) {
            result = data;
            console.log(result)
            if(result == 'Cloned') {     
                alertify.success('Cloned repository. Scan now!');      
            }
            else if(result == 'Exists'){ 
                alertify.message('Repository already exists, please scan!');
            }
            else if(result == 'Invalid') {
                alertify.error('Invalid github URL'); 
            }
            else {
                alertify.error('Whoa!');
            }
            nanobar.go( 100 );
        });

    }
    else {
        alertify.error('Please enter URL');
        nanobar.go( 100 );
    }

});

$('.scanbtn').click(function() {
    nanobar.go( 10 );
    var url_input = $('.searchtext').val();
    url_array = url_input.split('/');
    projectName = url_array[url_array.length - 1];
    if(projectName.length == 0) {
        projectName = url_array[url_array.length - 2];
    }
    if(projectName.includes('.git')) {
        projectName = projectName.slice(0, projectName.length - 4);
    }
    if(url_input.length != 0) {
        // Create form
        Cookies.set('projectName', projectName);
        Cookies.set('projectLink', url_input);
        window.open('/git_scan_project_vuln_details'); 
        nanobar.go( 100 );
    }
    else {
        alertify.error('URL field empty!');
        nanobar.go( 100 );
    }
});