<?php
$file = "nmap_report.xml";
$report = simplexml_load_file("$file");

foreach ($report->host as $targets ) {
	$currentAddress = $targets->address["addr"];
	echo "IP Address: ".$currentAddress."<br/>";
	echo "Port Open: <br/>";

	foreach ($targets->ports->port as $ports){

	$portStatus = $ports->state["state"];
	
	if($portStatus == "open"){
		$protocol =  $ports["protocol"];
		$portNo =  $ports["portid"];
		$service = $ports->service["name"];
		$serviceProduct = $ports->service["product"];
		$serviceVersion = $ports->service["version"];
	
		if(strlen($serviceProduct)>0){
			echo $protocol."/".$portNo." ".$serviceProduct." ".$serviceVersion."<br/>";
		}else{
			echo $protocol."/".$portNo." ".$service."<br/>";
		}
	}
	}

	echo "<hr/>";
}
?>