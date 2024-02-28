@Library('csharp')
def gitURL = "https://github.com/GhostPack/Seatbelt"
def branch = "953f764a57388868bd70ee0d0bca3a2d82081c22"

pipeline {
    agent {
        docker {
            image 'csharp:latest'
            label 'docker'
        }
    }
    parameters {
        booleanParam(
            name: 'InvisibilityCloak', 
            defaultValue: true, 
            description: 'Obfuscate the project with InvisibilityCloak')
        choice(
            name: 'CloakMethod', 
            choices: ['base64', 'rot13', 'reverse'], 
            description: 'InvisibilityCloak method')
        booleanParam(
            name: 'ConfuserEx', 
            defaultValue: true, 
            description: 'Obfuscate the binary with ConfuserEx')
        booleanParam(
            name: 'VirusTotal', 
            defaultValue: false, 
            description: 'Submit the payload to VT. If there are detections, build will be set to unstable')
    }
    stages {
        stage('Checkout') {
            steps {
                echo "[*] Cloning ${gitURL}"
                checkout([
                    $class: 'GitSCM', 
                    branches: [[name: branch]], 
                    doGenerateSubmoduleConfigurations: false, 
                    extensions: [[$class: 'CleanBeforeCheckout']], 
                    submoduleCfg: [], 
                    userRemoteConfigs: [[url: gitURL]]
                ])
                gitCommitCheck()
            }
        }
        stage('Cloak') {
            when { expression { return params.InvisibilityCloak }}
            steps {
                echo "[*] Obfuscating Seatbelt with InvisibilityCloak"
                cloak(".", CloakMethod)
            }
        }
        stage('Build') {
            steps {
                msbuilder("3.5")
                msbuilder()
            }
        }
        stage('ConfuserEx') {
            when { expression { return params.ConfuserEx }}
            steps {
                echo "[*] Obfuscating binary with ConfuserEx"
                confuserEx("./Seatbelt/bin/release/Seatbelt_3.5.exe")
                confuserEx("./Seatbelt/bin/release/Seatbelt.exe")
            }
        }
        stage('VirusTotal') {
            when { expression {return params.VirusTotal }}
            steps {
                echo '[*] Submitting payload to VirusTotal'
                virusTotal('./Seatbelt/bin/release/Seatbelt.exe')
            }
        }
    }
    post {
        success {
            archiveArtifacts artifacts: "**/bin/Release/*.exe", fingerprint: true
            // <user's> build finished with status <buildstatus>
        }
        unstable {
            archiveArtifacts artifacts: "**/bin/Release/*.exe", fingerprint: true
        }
    }
}
