import io.kloudformation.DeletionPolicy
import io.kloudformation.KloudFormation
import io.kloudformation.ResourceProperties
import io.kloudformation.StackBuilder
import io.kloudformation.function.plus
import io.kloudformation.model.Output
import io.kloudformation.model.iam.IamPolicyEffect
import io.kloudformation.model.iam.IamPolicyVersion
import io.kloudformation.model.iam.action
import io.kloudformation.model.iam.policyDocument
import io.kloudformation.model.iam.resource
import io.kloudformation.property.Tag
import io.kloudformation.property.aws.s3.bucket.ServerSideEncryptionByDefault
import io.kloudformation.property.aws.s3.bucket.ServerSideEncryptionRule
import io.kloudformation.resource.aws.s3.bucket
import io.kloudformation.resource.aws.s3.bucketPolicy
import io.kloudformation.unaryPlus

class Stack: StackBuilder {
    override fun KloudFormation.create(args: List<String>) {
        val bucket = bucket(resourceProperties = ResourceProperties(deletionPolicy = DeletionPolicy.RETAIN.policy)) {
            bucketName("hexlabs-inventory")
            bucketEncryption(listOf(ServerSideEncryptionRule(
                    ServerSideEncryptionByDefault(sSEAlgorithm = +"AES256")
            )))
            versioningConfiguration(+"Enabled")
            tags(listOf(
                    Tag(+"HexLabsProject", +"Inventory")
            ))
        }
        bucketPolicy(bucket.ref(), policyDocument("PutObjectPolicy", IamPolicyVersion.V2.version){
            statement(action("s3:PutObject"), IamPolicyEffect.Deny, resource(bucket.Arn() + "/*")) {
                condition("StringNotEquals", mapOf("s3:x-amz-server-side-encryption" to listOf(+"AES256")))
            }
            statement(action("s3:PutObject"), IamPolicyEffect.Deny, resource(bucket.Arn() + "/*")) {
                condition("Null", mapOf("s3:x-amz-server-side-encryption" to listOf(+"true")))
            }
        })
        outputs("Bucket" to Output(bucket.Arn()))
    }
}