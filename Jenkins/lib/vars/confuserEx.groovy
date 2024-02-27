def call(String binaryLocation) {
    powershell script: """
        \$fqfile = Resolve-Path ${binaryLocation};
        confuser.exe -o . -n \$fqfile;
    """
}