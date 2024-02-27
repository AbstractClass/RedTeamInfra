def call(String projectLocation, String method) {
    powershell script: """
        InvisibilityCloak.py -m $method -d ${projectLocation} -n ${JOB_NAME}
    """
}