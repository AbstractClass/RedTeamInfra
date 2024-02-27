def call(String dotNetVersion = '') {
    withEnv(["dotNetVersion=${dotNetVersion}", "JOB_NAME=${JOB_NAME}"]) {
        powershell script: '''
            Write-Host "[*] Value of dotNetVersion is '$env:dotNetVersion'"
            if ($env:dotNetVersion -eq '') {
                Write-Host "[*] No version selected, using default";
                $arg = '';
            } else {
                $arg = '/p:TargetFrameworkVersion=v' + $env:dotNetVersion;
            };
            $target = $env:JOB_NAME + '.sln';
            msbuild $target /t:build -restore /p:RestorePackagesConfig=true /p:Configuration=Release $arg;
        '''
    }

    echo '[+] Build complete'

    echo fileOperations([
        fileRenameOperation(
            source: "${JOB_NAME}/bin/Release/${JOB_NAME}.exe",
            destination: "${JOB_NAME}/bin/Release/${JOB_NAME}_${dotNetVersion}.exe"
        )
    ])
    echo "[*] Binary renamed to ${JOB_NAME}/bin/Release/${JOB_NAME}_${dotNetVersion}.exe"
}