package main

import (
	"fmt"

	"github.com/binaryfigments/nessusparse"
)

// This is for testing and playing only!!!

func main() {
	nessus, err := nessusparse.Run("../test001.nessus")
	if err != nil {
		fmt.Println(err)
	}

	for _, host := range nessus.Report.ReportHosts {
		println(host.Name)

		var hostIP string

		for _, tag := range host.HostProperties.Tags {
			// println(tag.Name)
			// println(tag.Data)
			if tag.Name == "host-ip" {
				hostIP = tag.Data
			}
		}
		println("host-ip: " + hostIP)

		for index, finding := range host.ReportItems {
			if finding.RiskFactor == "None" {
				continue
			}
			println(index)
			println(finding.PluginID)
			println(finding.PluginName)
			println(finding.Severity)
			println(finding.RiskFactor)
			println(finding.PluginOutput)
		}
	}
	/*
		json, err := json.MarshalIndent(nessus, "", "  ")
		if err != nil {
			fmt.Println(err)
		}
		fmt.Printf("%s\n", json)
	*/
}
