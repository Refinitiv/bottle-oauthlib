pipeline {
    agent {
        docker {
            image 'docker.int.thomsonreuters.com:5001/eds-auth/jenkins-slave:python3.6.2-jessie-v4'
            label 'master'
        }
    }
	options {
		disableConcurrentBuilds()
		timeout(time: 10, unit: 'MINUTES')
		timestamps()
	}
	environment {
	    bamsRepositoryPath = "default.pypi.local/eds-publish"
	}
    stages {
        stage('Checkout') {
            steps {
                checkout([$class: 'GitSCM', branches: [[name: 'master']], doGenerateSubmoduleConfigurations: false, extensions: [[$class: 'CleanBeforeCheckout']], submoduleCfg: [], userRemoteConfigs: [[credentialsId: 'SSH-Key-s.TR.eikon.RCSData', url: 'git@git.sami.int.thomsonreuters.com:eds-auth/bottle-oauthlib.git']]])
            }
        }
		stage('Running tests') {
			steps {
			    sh 'tox'
			}
		}
		stage('Packaging and publishing .WHL') {
			steps {
			    sh 'ls -la'
			    echo 'Packaging .whl package'
			    withEnv(["PATCH_VERSION=$BUILD_NUMBER"]) {
                    echo "$PATCH_VERSION"
                    sh 'python setup.py bdist_wheel'
                    configFileProvider([configFile(fileId: '1f64d757-27c4-4afb-8a02-72a989e01ea0', targetLocation: 'schema.sh', variable: 'UPLOAD')]) {
                        sh "chmod +x ${env.UPLOAD} && ${env.UPLOAD}"
                        sh 'cat uploadSchema.json'
                    }
                    echo 'Publishing package'

    			    script {
        			    def server = Artifactory.server 'bams'
        			    def uploadSpec = readFile 'uploadSchema.json'
                        server.upload(uploadSpec)
                    }
			    }
			}
		}
	}
	post {
	    always {
	        echo 'always'
          gitlabCommitStatus(name: 'bottle-oauthlib publish') {}

	    }
      failure {
        //emailext body: '$DEFAULT_CONTENT', subject: '$DEFAULT_SUBJECT', to: 'EikonEdge.Infra-Dev@thomsonreuters.com'
        echo 'Build failed'
      }
	}
}
