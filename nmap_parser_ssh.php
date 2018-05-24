<link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.7/css/bootstrap.min.css">
<script src="https://ajax.googleapis.com/ajax/libs/jquery/3.2.1/jquery.min.js"></script>
<script src="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.7/js/bootstrap.min.js"></script>
<div class="container">
<?php
$file = "nmap_report.xml";
$report = simplexml_load_file("$file");

$uniqueIP = [];
$uniquePort = [];

foreach ($report->host as $targets ) {
	$currentAddress = $targets->address["addr"];

	foreach ($targets->ports->port as $ports){
		$portStatus = $ports->state["state"];
		if($portStatus == "open"){
			$portNo =  trim($ports["portid"]);
			$service = trim($ports->service["name"]);
		
			if($service == "ssh"){
				$instance = $currentAddress.":".$portNo;
				$instances[] = $instance;

				if(in_array($currentAddress, $uniqueIP) == false){
					 $uniqueIP[] = $currentAddress;
				}

				if(in_array($portNo, $uniquePort) === false){
					$uniquePort[] = $portNo;
				}
			}
		}
	}
}

echo "<h3>SSH Instances</h3>";
echo "<hr/>";
foreach ($instances as $i){
	echo $i."<br/>";
};
echo "<hr/>";
echo "<h3>ssh2-enum-algos Analyzer Command Generator</h3>";
echo "<b>Command:</b> <code>nmap --script ssh2-enum-algos -iL target.txt -p ".implode(",", $uniquePort)." -oX nmap_ssh </code><br/><br/>";

echo "<i>target.txt:</i><br/>";
foreach ($uniqueIP as $ip){
	echo $ip."<br/>";
}
?>	
</div>