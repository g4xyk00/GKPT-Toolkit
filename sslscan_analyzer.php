<link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.7/css/bootstrap.min.css">
<script src="https://ajax.googleapis.com/ajax/libs/jquery/3.2.1/jquery.min.js"></script>
<script src="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.7/js/bootstrap.min.js"></script>

<div class="container">
<h1>SSLScan Analyzer <small>v1.0</small></h1>
Verify Nessus SSL findings with sslscan generated XML report. 
<br/><br/>
<b>Command: </b><kbd>sslscan --xml=ssl_report <i>target</i></kbd>

<hr/>
<?php

/** SSLScan Analyzer v1.0

Author: g4xyk00
Date: 2018-01-10



SSL/TLS Diffie-Hellman Modulus <= 1024 Bits (Logjam)

**/

$file = "sslscan_report.xml";
$report = simplexml_load_file("$file");

function br(){ echo "<br />"; }

function isKeywordExisted($text, $match){
	if(strpos($text, $match) === false){
		return false;
	}
	return true;
}


function displayMediumVuln($vuln){
	echo '<button type="button" class="btn btn-warning btn-xs">Medium</button> '.$vuln;
}

function displayLowVuln($vuln){
	echo '<button type="button" class="btn btn-success btn-xs">Low</button> '.$vuln;
}

function displayInstances($instance){
	echo '<h6>'.$instance.'</h6>';
}

function getVulnerableCiphers($getCipherArray, $getBlacklistedCiphers){
	$getAffectedCiphers = array();

	foreach ($getCipherArray as $cipher){
		if(isKeywordExisted($cipher, $getBlacklistedCiphers)){
			$getAffectedCiphers[] = $cipher;
		}
	}

	return $getAffectedCiphers;
}


function displayVulnerableCiphers($getAffectedCiphers, $severity, $vuln){
	if(!empty($getAffectedCiphers)){
		$getAffectedCiphers = implode(", ", $getAffectedCiphers);

		switch($severity){
			case "2": //Medium
				displayMediumVuln($vuln);
				break;
			case "1": //Low
				displayLowVuln($vuln);
				break;
			default:
				break;
		}
		displayInstances($getAffectedCiphers);
	}
}

function isVulnerableAlgos($getAlogs, $getBlacklistedAlgos){
	if(in_array($getAlogs, $getBlacklistedAlgos)){
		return true;
	}
	return false;
}

echo '
	<table class="table table-hover">
    <thead>
      <tr>
        <th>Target</th>
        <th>TCP Port</th>
        <th>SSL Related Vulnerability</th>
      </tr>
    </thead>
    <tbody>
    ';

foreach ($report->ssltest as $targets ) {
	$currentTarget = $targets["host"];
	$currentPort = $targets["port"];

	echo '
		<tr>
        <td>'.$currentTarget.'</td>
        <td>'.$currentPort.'</td>
        <td>
	';

    //Collect Cipher Information
	$cipherArray = array();
	$protocolArray = array();

	foreach ( $targets->cipher as $ciphers ){ 
		$currentCipher = (string)$ciphers["cipher"];
		$currentProtocol = (string)$ciphers["sslversion"];

		if(!in_array($currentCipher, $cipherArray)){
			$cipherArray[] = $currentCipher;
		}

		if(!in_array($currentProtocol, $protocolArray)){
			$protocolArray[] = $currentProtocol;
		}
	}


	//Check for Weak Protocol
	$vuln = "SSL Version 2 and 3 Protocol Detection";
	$blacklistedProtocol = array("SSLv2", "SSLv3");
	$sslV2Existed = in_array($blacklistedProtocol[0], $protocolArray);
	$sslV3Existed = in_array($blacklistedProtocol[1], $protocolArray);

	if($sslV2Existed || $sslV3Existed){
		displayMediumVuln($vuln);

		if($sslV3Existed){
			$vuln = "SSLv3 Padding Oracle On Downgraded Legacy Encryption Vulnerability (POODLE)";
			br();
			displayMediumVuln($vuln);
		}

		if($sslV2Existed){ displayInstances("SSLv2"); }
		if($sslV3Existed){ displayInstances("SSLv3"); }
	}

	$vuln = "SSL 64-bit Block Size Cipher Suites Supported (SWEET32)";
	$blacklistedCiphers = "DES-CBC3-SHA";
	$affectedCiphers = getVulnerableCiphers($cipherArray, $blacklistedCiphers);
	displayVulnerableCiphers($affectedCiphers, 2, $vuln);

	$subject = $targets->certificate->subject;
	$issuer  = $targets->certificate->issuer;

	$vuln = "SSL Self-Signed Certificate";
	if(strcmp($subject, $issuer) == 0){
		displayMediumVuln($vuln);
		displayInstances("Subject: ".$subject."<br/>Issuer: ".$issuer);
	}

	$vuln = "SSL/TLS EXPORT_RSA <= 512-bit Cipher Suites Supported (FREAK)";
	$blacklistedCiphers = array("EXP-RC4-MD5", "EXP-DES-CBC-SHA");

	$vuln = "SSL Weak Cipher Suites Supported";
	$blacklistedCiphers = array("RC2-CBC-MD5", "DES-CBC-SHA", "EDH-RSA-DES-CBC-SHA", "EXP-EDH-RSA-DES-CBC-SHA");



	$vuln = "SSL Certificate Expiry";
	$expiredDate =  $targets->certificate->{'not-valid-after'};
	$expiredDate = explode(" ", $expiredDate);
	$expiredDate = $expiredDate[1].' '.$expiredDate[0].' '.$expiredDate[3];

	if (strtotime('now') > strtotime($expiredDate)){
		displayMediumVuln($vuln);
		displayInstances("Expired on: ".$expiredDate);
	}

	$vuln = "SSL Certificate Signed Using Weak Hashing Algorithm";
	$signatureAlgorithm =  $targets->certificate->{'signature-algorithm'};
	$blacklistedAlgos = array("sha1WithRSAEncryption", "md5WithRSAEncryption");

	if(isVulnerableAlgos($signatureAlgorithm, $blacklistedAlgos)){
		displayMediumVuln($vuln);
		displayInstances($signatureAlgorithm);
	}


	$vuln = "SSL Certificate Chain Contains RSA Keys Less Than 2048 bits";
	$rsaKey  = $targets->certificate->pk["bits"];

	if($rsaKey < 2048){
		displayMediumVuln($vuln);
		displayInstances($rsaKey);
	}

	$vuln = "SSL RC4 Cipher Suites Supported (Bar Mitzvah)";
	$blacklistedCiphers = "RC4";
	$affectedCiphers = getVulnerableCiphers($cipherArray, $blacklistedCiphers);
	displayVulnerableCiphers($affectedCiphers, 1, $vuln);







    echo "</td>";
}

echo '</tr></tbody></table>';
?>
</div>