# CloudFormation Provider

Static analysis provider for AWS CloudFormation and SAM templates. Parses YAML/JSON templates locally without requiring AWS credentials or API access.

## Usage

```shell
mql shell cloudformation <path-to-template>
```

Supports both YAML and JSON template formats.

```shell
# Single template file
mql shell cloudformation template.yaml

# JSON format
mql shell cloudformation stack.json
```

## Examples

**List all resources in a template**

```shell
mql> cloudformation.template.resources { name type }
cloudformation.template.resources: [
  0: {
    name: "MyVPC"
    type: "AWS::EC2::VPC"
  }
  1: {
    name: "MySubnet"
    type: "AWS::EC2::Subnet"
  }
]
```

**Check that no resources use a specific type**

```shell
mql> cloudformation.template.resources.none(type == "AWS::IAM::User")
```

**Ensure all S3 buckets have versioning enabled**

```shell
mql> cloudformation.template.resources.where(type == "AWS::S3::Bucket") {
       properties["VersioningConfiguration"]["Status"] == "Enabled"
     }
```

**Check that all Lambda functions use a supported runtime**

```shell
mql> cloudformation.template.resources.where(type == "AWS::Lambda::Function") {
       properties["Runtime"] == /^python3\.(11|12|13)$/
     }
```

**One-shot query from the command line**

```shell
mql run cloudformation template.yaml -c "cloudformation.template.resources.where(type == /SecurityGroup/) { name properties }"
```

## References

- [AWS CloudFormation Template Reference](https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/introduction.html)
- [AWS SAM Template Specification](https://docs.aws.amazon.com/serverless-application-model/latest/developerguide/sam-specification.html)
