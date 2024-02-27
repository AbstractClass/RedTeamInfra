def call(String binaryLocation) {
    // VTCLI_APIKEY is a special variable used by the VT-CLI to manage the API key
    withCredentials(bindings: [string(credentialsId: 'VirusTotal', variable: 'VTCLI_APIKEY')]) {
        withEnv(["binaryLocation=${binaryLocation}"]) {
            powershell script: '''
                $result = vt scan file $env:binaryLocation --silent
                echo $result
                $hash = $result.Split()[1]
                $report = vt analysis $hash
                echo $report | Format-Table
                if (echo $report | Select-String -Pattern '"malicious"') {
                    echo '[!] Some AVs marked this as "malicious" !'
                } else {
                    ehco '[+] You're clean, no AVs detected this as malicious. Good job!
                }
            '''
        }
        echo '[+] VirusTotal report complete'
        findText(textFinders: [textFinder(buildResult: 'UNSTABLE', alsoCheckConsoleOutput: true, regexp: '\"malicious\"')])
    }
}