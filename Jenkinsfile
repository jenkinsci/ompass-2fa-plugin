pipeline {
    agent any

    tools {
        maven 'maven-3'
        jdk 'jdk11'
    }

    options {
        buildDiscarder(logRotator(numToKeepStr: '10'))
        timestamps()
        timeout(time: 30, unit: 'MINUTES')
    }

    stages {
        stage('Build') {
            steps {
                sh 'mvn clean package -DskipTests'
            }
        }

        stage('Test') {
            steps {
                sh 'mvn test'
            }
            post {
                always {
                    junit allowEmptyResults: true, testResults: 'target/surefire-reports/*.xml'
                }
            }
        }

        stage('Archive') {
            steps {
                archiveArtifacts artifacts: 'target/*.hpi', fingerprint: true
            }
        }
    }

    post {
        failure {
            echo 'Build failed. Check the logs for details.'
        }
        success {
            echo 'Build succeeded. HPI artifact is available in the archived artifacts.'
        }
    }
}
