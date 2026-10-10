# Exec Environment Detector

Usage:

```golang
env := ci.Detect()
env.IsAutomatedEnv()
env.Name
```

## CI environments

* AWS Code Build [Spec](https://docs.aws.amazon.com/codebuild/latest/userguide/build-env-ref-env-vars.html)
* Azure Build Pipeline [Spec](https://learn.microsoft.com/en-us/azure/devops/pipelines/build/variables?view=azure-devops)
* GitLab [Spec](https://docs.gitlab.com/ci/variables/)
* Google Cloud Build [Spec](https://docs.cloud.google.com/build/docs/configuring-builds/substitute-variable-values#using_default_substitutions)
* CircleCI [Spec](https://circleci.com/docs/guides/security/env-vars/)
* Jenkins [Spec](https://www.jenkins.io/doc/book/pipeline/jenkinsfile/#using-environment-variables)
* Travis [Spec](https://docs.travis-ci.com/user/environment-variables/#default-environment-variables)
* GoCD [Spec](https://docs.gocd.org/current/faq/environment_variables.html)
* TeamCity [Spec](https://www.jetbrains.com/help/teamcity/predefined-build-parameters.html)

## Low-level structure

**list of env vars**

jenkins:

    Name: "BUILD_ID",
    Name: "BUILD_NUMBER",
    Name: "BUILD_NUMBER",
    Name: "BUILD_URL",
    Name: "GIT_COMMIT",
    Name: "JENKINS_URL",
    Name: "JENKINS_URL",
    Name: "JOB_NAME",

circleci:

    Name: "CIRCLE_BUILD_URL",
    Name: "CIRCLE_JOB",
    Name: "CIRCLE_PULL_REQUEST",
    Name: "CIRCLE_REPOSITORY_URL",
    Name: "CIRCLE_SHA1",
    Name: "CIRCLE_TAG",
    Name: "CIRCLE_USERNAME",

travis:

    Name: "TRAVIS_BUILD_ID",
    Name: "TRAVIS_BUILD_NUMBER",
    Name: "TRAVIS_BUILD_WEB_URL",
    Name: "TRAVIS_COMMIT",
    Name: "TRAVIS_COMMIT_MESSAGE",
    Name: "TRAVIS_JOB_ID",
    Name: "TRAVIS_JOB_NAME",
    Name: "TRAVIS_JOB_WEB_URL",

gitlab:

    Name: "CI_COMMIT_DESCRIPTION",
    Name: "CI_COMMIT_REF_NAME",
    Name: "CI_COMMIT_SHA",
    Name: "CI_JOB_ID",
    Name: "CI_JOB_NAME",
    Name: "CI_JOB_URL",
    Name: "CI_MERGE_REQUEST_ID",
    Name: "CI_MERGE_REQUEST_PROJECT_URL",
    Name: "CI_PIPELINE_URL",
    Name: "CI_PROJECT_ID",
    Name: "CI_PROJECT_NAME",
    Name: "CI_PROJECT_URL",
    Name: "GITLAB_CI",
    Name: "GITLAB_USER_EMAIL",
    Name: "GITLAB_USER_ID",
    Name: "GITLAB_USER_NAME",

teamcity

    Name: "TEAMCITY_PROJECT_NAME",
    Name: "BUILD_NUMBER",

**shared names**

We cannot change the env vars the system is providing, so we have to support the system-specific ones that are listed above. But we should support these in case a user is in another build system and wants to provide build info:

    MONDOO_CI            // true if the CI/CD is used and the value is set to the CI/CD system of this run
                         // (eg travis-ci.com, gitlab.com)

    CI_COMMIT_SHA        // i know, it should be checksum... sha is shorter, but not as precise and robust
    CI_COMMIT_MESSAGE    // this is just the message, whatever we will use
    CI_COMMIT_REF_NAME   // optional, used if specified
    CI_COMMIT_URL        // url to the project's PR or the project itself

    CI_PROJECT_NAME      // name of the project in the CI/CD system
    CI_PROJECT_ID        // id of this project in the CI/CD system
    CI_PROJECT_URL       // url to view this project in the CI/CD system

    CI_BUILD_ID          // internal ID of the target system
    CI_BUILD_NAME        // optional, used if specified
    CI_BUILD_NUMBER      // 1, 2, ...
    CI_BUILD_URL         // url to view the build in the CI/CD system
    CI_BUILD_USER_NAME   // user name
    CI_BUILD_USER_ID     // user identifier
    CI_BUILD_USER_EMAIL  // user email

## References

* https://github.com/watson/ci-info
