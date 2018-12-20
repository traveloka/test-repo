var options = {
	classname: 'p-bar',
    id: 'p-bar',
    target: document.getElementById('myDivId'),
    bg: '#42f4b3'
};

var nanobar = new Nanobar( options );

var low_rows = [];
var med_rows = [];
var high_rows = [];
var crirtical_rows = [];

function callback() {
    nanobar.go( 100 );
}

nanobar.go( 20 );