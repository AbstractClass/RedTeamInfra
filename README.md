## Author's Note
This is the script outline for my presentation of this project 2024-02-27 in Mr.Un1k0d3r's Discord. It is meant to describe how to go from a blank Windows 11 install to the final product outlined in the GitHub.

## Installation
The official Jenkins image is for a Linux container, so if you are on Windows be sure to switch to Linux virtualization. If you are in a Windows VM it will be a huge headache or just not possible to do this, instead install Jenkins via the WAR file.

For MalDev we will be building things using a Windows docker image, as our payloads will be meant for Windows machine primarily. To make this demo as easy as possible we will use a Windows host so we can easily run Windows Docker containers.

Our Jenkins Docker image will be hosted in a Linux VM, because we can't have simultaneous Windows and Linux containers on Docker.
### Linux
1. Install via the package manager is easiest. I use Ubuntu for my dev work so:
```bash
sudo wget -O /usr/share/keyrings/jenkins-keyring.asc \
  https://pkg.jenkins.io/debian-stable/jenkins.io-2023.key
echo deb [signed-by=/usr/share/keyrings/jenkins-keyring.asc] \
  https://pkg.jenkins.io/debian-stable binary/ | sudo tee \
  /etc/apt/sources.list.d/jenkins.list > /dev/null
sudo apt update
sudo apt install openjdk-17
sudo apt install jenkins
```
1. Start the Jenkins service
```bash
sudo systemctl start jenkins
```
2. Get the password for the Jenkins instance from `/var/lib/jenkins/secrets/initialAdminPassword`
4. By default it will be running on `localhost:8080` but you can check with `netstat -ant`
5. Navigate to the landing page (`http://localhost:8080`) and enter the password
6. Install the following plugins when prompted (Don't worry, you can install more later):
	- Dashboard View
	- Folders
	- Configuration as Code Plugin
	- Docker Pipeline
	- File Operations Plugin
	- OWASP Markup Formatter
	- Build Name and Description Setter
	- Build Timeout
	- Config File Provider
	- Conditional BuildStep
	- Credentials Binding
	- Embeddable Build Status
	- SSH Agent
	- Timestamper
	- Workspace Cleanup
	- MSBuild
	- Warnings
	- Pipeline
	- GithHub Branch Source
	- Pipeline: GitHub Groovy Libraries
	- Pipeline: Stage View
	- Conditional Build Step
	- Parameterized Trigger
	- Copy Artifact
	- Text Finder
	- Git
	- GitHub
	- SSH Build Agents
	- Matrix Authorization Strategy
	- Dark Theme
7. Create your admin user by filling out the form

8. You are ready to go!

## Setting up a Node
Jenkins can build things on the main node, but we'd like to avoid that not only for security reasons, but also because we are going to be compiling on Windows.

So we will need to setup a safe Windows environment where we can compile malware. I found the easiest way to do this is to use a Windows Docker container.

### Docker
Let's examine what we want to do with this container:
- Compile .NET 3.5 and 4.X executables
- Some kind of obfuscation
	- Lets use ConfuserEx and Invisibility Cloak
	- That means we need Python

So based on that the hardest thing to get configured is going to be .NET 3.5, so let's use the official MS .NET container.
```dockerfile
FROM mcr.microsoft.com/dotnet/framework/sdk:3.5-windowsservercore-ltsc2019
LABEL maintainer="0xC130D"
```

Save this as "Dockerfile" and build it with the following:
```cmd
docker build . -t csharp
```

We can then interact with the following command:
```cmd
docker exec -it csharp powershell
```

Referring back to that the above list we need to get .NET configured properly. We are going to need:
- git
- Visual Studio tools (2019 and 2022)
- 7zip (to install ConfuserEx)
- Python (for InvisibilityCloak)

The easiest way to get all of these is to use the [chocolatey](https://chocolatey.org/) package manager. We need to experiment a bit to make sure we can install it without any user prompts and that it works correctly. So let's try it in the interactive shell first:
```powershell
Set-ExecutionPolicy Bypass -Scope Process -Force; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'));

choco install git 7zip python3 -y
```

Once we have figured out how to install everything without any user prompts we can toss it all in a PowerShell script, we'll call it `install-requirements.ps1`. We can keep this in the same folder as the Dockerfile. We will also want to make PowerShell the default when launching the container, which we can do with the `ENTRYPOINT` command.

We can use this script during our Docker build process using the `COPY` command. So now our script looks like this:

```Dockerfile
FROM mcr.microsoft.com/dotnet/framework/sdk:3.5-windowsservercore-ltsc2019
LABEL maintainer="0xC130D"

SHELL = [ "powershell", "-Command", "$ErrorActionPreference = 'stop'; $ProgressPreference = 'SilentlyContinue';" ]
RUN New-Item C:/temp -ItemType Directory
WORKDIR C:/temp

COPY install-requirements.ps1 .
RUN .\install-requirements.ps1
```

### Adding an Agent
In Jenkins, head to your Nodes (`/computer`) and click the `New Node` button. Remember that we are adding the Windows **host** as an agent, and will be calling Docker from that host. The idea is in the future we can create more Docker containers and launch them from this host. So let's name the host 'Windows'.


Then we will set some basic information about the Node. Nothing here is actually important and is just human readable information. We will make use of the labels later, but the information can also be edited at any time.

> Everything else on this page can be left default

That's it, our Node has been created. But we still have to add the Jenkins agent to the node so it can communicate with the server. We can see how to do this by clicking on the node name from the menu and going to the node status page.


Since we are using a Windows host we can just copy the Windows code.
```ad-warning
WAIT! We know that Jenkins needs java to function, the same is true for the agents. We need to install openjdk17. The easiest way to do this is the same package manager we have been using the whole time, Chocolatey. `choco install openjdk17`.
```

If you notice connection error when the agent is trying to connect then you might need to switch the Jenkins URL from `localhost` to the IP of your server. This can be done from the "System" page of the management dashboard.


If you are getting an HTTP 404 error when the agent tries to connect then you need to alter the agent inbound port settings. Go to the "Security" page of the management dashboard and select "Random" for the "TCP Port for Inbound Agents" setting:


You know you are done when the agent status shows connected and you can see the node machine information:


## Our First Pipeline
### Creating the Pipeline
From the homepage, select "+ New Item" and select "Pipeline". We also have to give it a name. Let's pick "Seatbelt" since that will be the first project for us.

In the future we will want to use a "Jenkinsfile", but for now let's keep it simple and write directly into the Pipeline form.

### Pipeline Script
We are first presented with a choice, do we want to use *Declarative* syntax or *Scripted* syntax? Well ultimately it's a choice you should make on your own based on your needs, but I personally advocate for declarative syntax for the following reasons:
- Access to scripted syntax using the `script` tags
- Implicit steps like post-actions and SCM checkout
- The ability to replay a job from any given stage

Now that we have decided on declarative syntax, what does that even mean, what does it look like? Well the Jenkins docs have you covered there:
- [Pipeline Syntax (jenkins.io)](https://www.jenkins.io/doc/book/pipeline/syntax/)

There is a lot to read, and you really should read all of it, but to keep things moving I will summarize the important bits here:
1. All pipelines need to start with `pipeline {...}`, all script tags will reside within this pipeline tag. However, things like global variables will sit outside of this tag.
2. Declare which agent(s) should run this job using the `agent {...}` tag. Since we want to use docker we take this a step further, using `agent { docker <label-name> }`
3. After the agent we declare any `parameters` or `options` which can be used to define user supplied variables (think function args) or build options like timestamps on the output
4. Now we can declare build stages, each stage is a logical grouping of steps. This is useful for tracking where a build fails and letting us replay a build from a particular stage. Stages  are contained within a `stages {...}` tag and each stage is defined using `stage('<stage-name>') {...}`
5. Each stage must contain at least one step, defined using `step {...}`. The only tags that can reside within a `stage` tag is `steps` or `parallel` (for the parallel execution of steps)
6. Steps are where we actually do the building, this is typically the execution of scripts or shell commands and the manipulation of files or folders.
7. Finally, once all steps are complete we can declare post actions. Post actions let us declare more steps that should be executed once the job is complete depending on if the job was successful, you can think of this as the `finally` and `catch` steps of a `try, catch, finally` block. We will mostly use this to get our final build binaries and push status notifications via webhook

### Understanding Pipeline Script and Troubleshooting
When looking at the `Script` section of our new pipeline we can try out some samples with the drop-down menu located in the top right. Let's start with `Hello World`:
```Groovy
pipeline {
	agent any
	stages {
		stage('Hello') {
			steps {
				echo 'Hello World'
			}
		}
	}
}
```

```ad-info
If the job is completing but warns that there are "no steps" then make sure you have the `Pipeline` plugin installed!
```



Ok that works, let's use the right agent now, we want to use the "Windows" node and use the "csharp:latest" docker image. Change the `agent` tag to the following:
```Groovy
agent {
	docker {
		image 'csharp:latest'
		label 'docker'
	}
}
```



Running the job again shows a success and if we click into the job and view the console output we can see it is launching the docker container. Now that we have that down let's start mapping out the process of doing the build.

Let's start with the git clone, we will first create two global variables: `branch` and `gitURL`.
```Groovy
def gitURL = 'https://github.com/GhostPack/Seatbelt'
def branch = 'master'
```

Then we can use the `checkout` command in Jenkins to declaratively checkout the repo.
```Groovy
stage('Checkout') {
	steps {
		checkout([
			$class: 'GitSCM',
			branches: [[name: branch]],
			doGenerateSubmoduleConfiguration: false,
			extensions: [[$class: 'CleanBeforeCheckout']],
			submodulecfg: [],
			userRemoteConfigs: [[url: gitURL]]
		])
	}
}
```

Then we can add another stage just to see what the downloaded file look like
```Groovy
stage('validate') {
	steps {
		powershell 'ls'
	}
}
```



That looks good, we didn't even have to change directories into the repo, that's going to be important information. Let's move on to building! We will need to create a new stage where we can compile the project.
```Groovy
stage('Build') {
	steps {
		powershell script: """
			msbuild Seatbelt /t:build -restore /p:RestorePackagesConfig=true /p:Configuration=Release
		"""
		echo '[+] Build complete'
	}
}
```

We will also need to grab the final binary, and can do this with a `post` action with the `archiveArtifacts` tag!
```Groovy
post {
	success {
		archiveArtifacts artifacts: "Seatbelt/bin/Release/Seatbelt.exe"
	}
}
```

Now when we run it again we can see we have `Seatbelt.exe` waiting for download!
```ad-warning
Windows Defender may delete your binary if you haven't made an exclusion for `C:\jenkins` (or whatever folder you set)
```

### Adding Obfuscation and Parameters
Ok that's great, but it's the same as just getting a release binary from Github, what if sometimes we want to obfuscate using InvisibilityCload, ConfuserEx, or both!

Let's start by adding parameters so the user can decide which obfuscators they want to use:
```Groovy
parameters {
    booleanParam(name: 'InvisibilityCloak', defaultValue: true, description: 'Obfuscate the project with InvisibilityCloak')
    choice(name: 'CloakMethod', choices: ['base64', 'rot13', 'reverse'], description: 'InvisibilityCloak method')
    booleanParam(name: 'ConfuserEx', defaultValue: true, description: 'Obfuscate the binary with ConfuserEx')
}
```
Note that you can't see these parameters on the GUI. Make sure `This project is paramterized` is selected and that you have run the script with the parameters. Jenkins isn't aware of the script contents (i.e. the parameters) until you run it.

Now we will want to add optional stages based on the values of these options, which can be done with *conditional stages*:
```Groovy
stage('Cloak') {
	when { expression { return params.InvisibilityCloak }}
	steps {
		echo "[*] Obfuscating Seatbelt with InvisibilityCloak"
		powershell script: """
			InvisibilityCloak.py -m ${params.CloakMethod} -d '.' -n ${JOB_NAME}
		"""
	}
}
stage('Build') { ... }
stage('ConfuserEx') {
	when { expression { return params.ConfuserEx }}
	steps {
		echo "[*] Obfuscating binary with ConfuserEx"
		powershell script: """
			\$fqfile = Resolve-Path .\Seatbelt\bin\Release\Seatbelt.exe;
			confuser.exe -o . -n \$fqfile
		"""
	}
}
```

Great! We now have a stealthy Seatbelt! Here is the final script:
```Groovy
def gitURL = "https://github.com/GhostPack/Seatbelt"
def branch = "master"

pipeline {
    agent {
        docker {
            image 'csharp:latest'
            label 'docker'
        }
    }
    parameters {
        booleanParam(name: 'InvisibilityCloak', defaultValue: true, description: 'Obfuscate the project with InvisibilityCloak')
        choice(name: 'CloakMethod', choices: ['base64', 'rot13', 'reverse'], description: 'InvisibilityCloak method')
        booleanParam(name: 'ConfuserEx', defaultValue: true, description: 'Obfuscate the binary with ConfuserEx')
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
            }
        }
        stage('Cloak') {
            when { expression { return params.InvisibilityCloak }}
            steps {
                echo "[*] Obfuscating Seatbelt with InvisibilityCloak"
                powershell script: """
                    InvisibilityCloak.py -m ${params.CloakMethod} -d '.' -n ${JOB_NAME}
                """
            }
        }
        stage('Build') {
            steps {
                powershell script: """
                    msbuild Seatbelt /t:build -restore /p:RestorePackagesConfig=true /p:Configuration=Release
                """
                echo "[+] Build complete"
            }
        }
        stage('ConfuserEx') {
            when { expression { return params.ConfuserEx }}
            steps {
                echo "[*] Obfuscating binary with ConfuserEx"
                powershell script: """
                    \$fqfile = Resolve-Path .\\Seatbelt\\bin\\Release\\Seatbelt.exe;
                    confuser.exe -o . -n \$fqfile
                """
            }
        }
    }
    post {
        success {
            archiveArtifacts artifacts: "Seatbelt/bin/Release/Seatbelt.exe", fingerprint: true
        }
    }
}
```

### Scaling Up
We can see from this that every C# tool will more or less look the same as this, which means a ton of duplicated code. We want to avoid duplicated code so let's make a library of common functions! The library will include the following:
- msbuild
	- build the binary
	- retarget .NET version
- InvisibilityCloak
	- obfuscate with the given method
- ConfuserEx
	- obfuscate the binary

Jenkins has documentation on creating a shared library here: [Extending with Shared Libraries (jenkins.io)](https://www.jenkins.io/doc/book/pipeline/shared-libraries/)

We need to create a new GitHub repo with the following structure:
```
resources\
	org\
src\
	org\
vars\
	cloak.groovy
	confuserEx.groovy
	msbuilder.groovy
```

Each of these groovy files will contain a singular function called `call` which will make the file callable as a function.

**cloak.groovy**
```Groovy
def call(String projectLocation, String method) {
    powershell script: """
        InvisibilityCloak.py -m $method -d ${projectLocation} -n ${JOB_NAME}
    """
}
```

**confuserEx.groovy**
```Groovy
def call(String binaryLocation) {
    powershell script: """
        \$fqfile = Resolve-Path ${binaryLocation};
        confuser.exe -o . -n \$fqfile;
    """
}
```

**msbuilder.groovy**
```Groovy
def call(String dotNetVersion = '') {
    withEnv(["dotNetVersion=${dotNetVersion}", "JOB_NAME=${JOB_NAME}"]) {
        powershell script: '''
            Write-Host "[*] dotNetVersion is: $env:dotNetVersion"
            if ($env:dotNetVersion) {
                $arg = '/p:TargetFrameworkVersion=v' + $env:dotNetVersion;
            } else {
                Write-Host "[*] No version selected, using default";
                $arg = '';
            };
            $target = $env:JOB_NAME + '.sln';
            msbuild $target /t:build -restore /p:RestorePackagesConfig=true /p:Configuration=Release $arg;
        '''
    }

    echo '[+] Build complete'

    if (dotNetVersion != '') {
        fileOperations([
            fileRenameOperation(
                source: "${JOB_NAME}/bin/Release/${JOB_NAME}.exe",
                destination: "${JOB_NAME}/bin/Release/${JOB_NAME}_${dotNetVersion}.exe"
            )
        ])
        echo "[*] Binary renamed to ${JOB_NAME}/bin/Release/${JOB_NAME}_${dotNetVersion}.exe"
    }
}
```

Now we can go back through our main script, import the library, and add the function calls.
```Groovy
@Library('csharp')
def gitURL = "https://github.com/GhostPack/Seatbelt"
def branch = "master"

pipeline {
    agent {
        docker {
            image 'csharp:latest'
            label 'docker'
        }
    }
    parameters {
        booleanParam(name: 'InvisibilityCloak', defaultValue: true, description: 'Obfuscate the project with InvisibilityCloak')
        choice(name: 'CloakMethod', choices: ['base64', 'rot13', 'reverse'], description: 'InvisibilityCloak method')
        booleanParam(name: 'ConfuserEx', defaultValue: true, description: 'Obfuscate the binary with ConfuserEx')
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
    }
    post {
        success {
            archiveArtifacts artifacts: "**/bin/Release/*.exe", fingerprint: true
        }
    }
}
```

### The Git Commit Check
It's generally not the smartest idea to build the latest commit on a random open-source repo. Instead we should specify a commit hash, and then run a regular check to see if there are new updates and send that data to a user for manual review.

Let's start with a new groovy script that will check the commit
```Groovy
def call() {
    def isUserRun = currentBuild.rawBuild.getCause(hudson.model.Cause$UserIdCause) != null
    if (isUserRun) {
        echo "[*] User run, skipping check"
        return
    }
    def buildStatus = currentBuild.result;
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
```

There are several interesting things to note about this script:
- We abandon if it's user run, this way we only do the check when the build runs as a part of a scheduled task
- We mess with build status to make it easier to visually separate if the build was run as a part of a scheduled build and what the outcome was

Now what are these scheduled build, how do we do that? Well if we go back to our pipeline and select "Configure" we can select "Build Periodically" with the following schedule `H 6 * * 1` to run weekly on Monday at 6am.

## Automating Detection
Wouldn't it be great if we ran some kind of detection when we compile these payloads to make sure they won't get caught when we try to use them? Wouldn't it also be great if the job status reflected whether or not the payload was detected? Well we can do that.

For the sake of this demonstration we will use the VirusTotal free API. Go ahead and create a VirusTotal account and get your API key. Once you have it we can add it to Jenkins securely. Go to "Manage Jenkins" and select "Credentials". Select the "global" domain and select "+ Add Credentials". 



```ad-note
Observe that credentials can be scoped to a specific domain. If you are going to be managing a lot of credentials or need only certain users to have access to credentials then you can utilize this feature, but for the sake of the demonstration we will just use the global domain.
```

Select "secret text" for our API key, paste in the key and chose a short but descriptive name for our key (i.e. "VirusTotal" or "VirusTotalKey").


Now let's create a new function to call the API and submit our payload, then get the result. We could write API calls with PowerShell or Python directly, but there is already a VirusTotal CLI tools and it's available on Chocolatey, so let's update our Docker script `install-requirements.ps1` to install it.



Now we can create `virusTotal.groovy`:
```Groovy
def call(String binaryLocation) {
    // VTCLI_APIKEY is a special variable used by the VT-CLI to manage the API key
    withCredentials(bindings: [string(credentialsId: 'VirusTotal', variable: 'VTCLI_APIKEY')]) {
        withEnv(["binaryLocation=${binaryLocation}"]) {
            powershell script: '''
                $result = vt scan file $env:binaryLocation --silent
                echo $result
                $hash = $result.Split()[1]
                $report = vt analysis $hash
                while (echo $report | Select-String -Pattern 'status: "queued"') {
                    echo "Report analyzing, waiting 5s ..."
                    Start-Sleep -Seconds 5
                    $report = vt analysis $hash
                }
                echo $report
                if (echo $report | Select-String -Pattern '"malicious"') {
                    echo '[!] Some AVs marked this as "malicious" !'
                } else {
                    echo '[+] You're clean, no AVs detected this as malicious. Good job!
                }
            '''
        }
        echo '[+] VirusTotal report complete'
        findText(textFinders: [textFinder(buildResult: 'UNSTABLE', alsoCheckConsoleOutput: true, regexp: '\"malicious\"')])
    }
}
```

```ad-note
We make use of the `findText` tag here, which is from the `Text Finder` plugin.
```

Now we don't necessarily want to run this *every* time we run our build, so let's leave it up to the user and add a parameter to our parameters list:
```Groovy
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
```

Then we can create the `VirusTotal` stage:
```Groovy
stage('VirusTotal') {
    when { expression {return params.VirusTotal }}
    steps {
        echo '[*] Submitting payload to VirusTotal'
        virusTotal('./Seatbelt/bin/release/Seatbelt.exe')
    }
}
```

And finally, now that we may set our build to `UNSTABLE` we need to still archive the artifacts. We will update the `post` tag to handle this:
```Groovy
post {
    success {
        archiveArtifacts artifacts: "**/bin/Release/*.exe", fingerprint: true
    }
    unstable {
        archiveArtifacts artifacts: "**/bin/Release/*.exe", fingerprint: true
    }
}
```

There, now we can run it again and see if VT catches us (spoiler: it definitely will).



## Next Steps
There are several things I just simply won't have time to cover but have explored and/or already implemented privately. Some things to consider:

- Add webhooks to your favorite monitoring tool (Slack maybe?)
- Integration with your favourite C2 and environmental keying
- Making containers for Golang, C++, etc.
- Creating pipelines for Terraform script deployments
- Unit Testing exploitation methods with an EDR lab
