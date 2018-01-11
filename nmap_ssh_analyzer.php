<link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.7/css/bootstrap.min.css">
<script src="https://ajax.googleapis.com/ajax/libs/jquery/3.2.1/jquery.min.js"></script>
<script src="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.7/js/bootstrap.min.js"></script>

<div class="container">
<h1>ssh2-enum-algos Analyzer <small>v1.0</small></h1>
Verify Nessus SSH findings with Nmap generated XML report. 
<br/><br/>
<b>Command: </b><kbd>nmap --script ssh2-enum-algos <i>target</i> -oX ssh_report</kbd>
<hr/>
<?php
echo '
	<table class="table table-hover">
    <thead>
      <tr>
        <th>Target</th>
        <th>TCP Port</th>
        <th>SSH Related Vulnerability</th>
      </tr>
    </thead>
    <tbody>
    ';

$file = "ssh_report.xml";
$report = simplexml_load_file("$file");

function displayMediumVuln($vuln){
	echo '<button type="button" class="btn btn-warning btn-xs">Medium</button> '.$vuln;
}

function displayLowVuln($vuln){
	echo '<button type="button" class="btn btn-success btn-xs">Low</button> '.$vuln;
}

function getElementInArray($getArrayTest, $getArrayDB){
	$elementInArray = array();

	foreach ($getArrayTest as $target){
		if(in_array($target, $getArrayDB)){
			$elementInArray[] = $target;
		}
	}

	return $elementInArray;
}

function arrayToText($getArrayTest){
	return implode("  |  ", $getArrayTest);
}

function displayInstances($instance){
	echo '<h6>'.$instance.'</h6>';
}

$weakCiphers = array ("arcfour", "arcfour128", "arcfour256");

$cbcCiphers = array ("3des-cbc", "aes128-cbc", "aes192-cbc", "aes256-cbc", "blowfish-cbc", "cast128-cbc", "rijndael-cbc@lysator.liu.se");

$macAlgos = array ("hmac-md5", "hmac-md5-96", "hmac-md5-96-etm@openssh.com", "hmac-md5-etm@openssh.com", "hmac-sha1-96", "hmac-sha1-96-etm@openssh.com");


foreach ($report->host as $targets ) {
	$currentTarget = $targets->address[0]["addr"];
	$currentPort = $targets->ports->port["portid"];
	
	echo '
		<tr>
        <td>'.$currentTarget.'</td>
        <td>'.$currentPort.'</td>
        <td>
	';

	$xmlCiphers = $targets->ports->port->script->table[2]; 
	$xmlMACs = $targets->ports->port->script->table[3];
	$currentCiphers = array();
	$currentMACs = array();

	foreach($xmlCiphers->elem as $curr){
		$currentCiphers[] = $curr;
	}

	foreach($xmlMACs->elem as $curr){
		$currentMACs[] = $curr;
	}


	$vuln = "SSH Weak Algorithms Supported"; //Cipher
	$affectedWeakAlgos = arrayToText(getElementInArray($currentCiphers, $weakCiphers));
	if(!empty($affectedWeakAlgos)){
		displayMediumVuln($vuln);
		displayInstances($affectedWeakAlgos);
	}

	$vuln = "SSH Weak MAC Algorithms Enabled";
	$affectedMacAlgos = arrayToText(getElementInArray($currentMACs, $macAlgos));


	if(!empty($affectedMacAlgos)){
		displayLowVuln($vuln);
		displayInstances($affectedMacAlgos);
	}

	$vuln = "SSH Server CBC Mode Ciphers Enabled";
	$affectedWeakCiphers = arrayToText(getElementInArray($currentCiphers, $cbcCiphers));
	if(!empty($affectedWeakCiphers)){
		displayLowVuln($vuln);
		displayInstances($affectedWeakCiphers);
	}

	echo "</td>";
}
echo '</tr></tbody></table>';
?>