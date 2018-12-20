$('.btn-plus').click(function() {
    alertify.prompt( 'Add new porject to Dashboard', 'Enter github URL', ''
    , function(evt, value) { 
        // Verify git link
        // Check is already exists
        // Clone, add entry to table, make vuln file, make jade file,
        alertify.success('You entered: ' + value) 
    }
    , function() { 
        alertify.error('Cancel') 
    });

});