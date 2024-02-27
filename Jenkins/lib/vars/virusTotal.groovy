def call(String binaryLocation) {
    // VTCLI_APIKEY is a special variable used by the VT-CLI to manage the API key
    withCredentials(bindings: [string(credentialsId: 'VirusTotal', variable: 'VTCLI_APIKEY')]) {
        withEnv(["binaryLocation=${binaryLocation}"]) {
            powershell script: '''
                $hash = $(vt scan file $env:binaryLocation --silent).Split()[1]
                $report = vt analysis $hash
                Write-Host '[+] Report: \n' + $report
            '''
        }
        echo '[+] VirusTotal report complete'
        findText(textFinder: [textFinder(buildResult: 'UNSTABLE', alsoCheckConsoleOutput: true, regexp: 'malicious')])
    }
}