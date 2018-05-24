<?php
$file = "nmap_report.xml";
$report = simplexml_load_file("$file");

foreach ($report->host as $targets ) {
	$currentAddress = $targets->address["addr"];

	foreach ($targets->ports->port as $ports){
		$portStatus = $ports->state["state"];
		if($portStatus == "open"){
			$portNo =  $ports["portid"];
			$ssl_enabled = $ports->service["tunnel"];
		
			if($ssl_enabled == "ssl"){
				$instance = $currentAddress.":".$portNo;
				$instances[] = $instance;
			}
		}
	}
}

echo "<h3>SSLScan Instances</h3>";
echo "<b>Command:</b> <code>sslscan --targets=&lt;filename&gt;</code><br/><br/>";
echo "<hr/>";
foreach ($instances as $i){
	echo $i."<br/>";
};
echo "<hr/>";
?>	