def buildStatus = currentBuild.result;
def call() {
    withEnv(["buildStatus=${buildStatus}", "JOB_NAME=${JOB_NAME}"]) {
        def result = powershell returnStatus: true, script: '''
            echo "[*] Checking latest commit for changes";
            $currentHash = git rev-parse HEAD;
            $latestHash = $(git ls-remote --symref origin HEAD -q | Select -Index 1).Split()[0];
            $diff = git --no-pager diff HEAD $latestHash --stat;
            echo '[*] Diff: ' + $diff;
            if ($diff) {
                # Do a webhook!
                echo "[!] Pretend I am a webhook, there are updates available!";
                exit 1;
            } else {
                echo "[+] All good, no updates";
                return 'SUCCESS';
            }
        '''
        if (result == 1) {
            currentBuild.result = 'ABORTED'
            error('Newer commit detected, aborting build') // halt with error so you can tell at a glance that the build needs review
        } else {
            script {
                currentBuild.getRawBuild().getExecutor().interrupt(Result.SUCCESS) // Force early stop with a success status
                sleep(1) // Interrupts aren't blocking so we want to wait for it to take effect
            }
        }
    }
}