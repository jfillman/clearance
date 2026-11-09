package scope

import (
	"strings"
	"testing"
)

func TestFirstReleaseAreasAreEvaluated(t *testing.T) {
	f := &Filter{DataBuckets: []string{"tf-state"}}
	for _, c := range []struct {
		svc, name string
		data      bool
		bucket    string
		want      string
	}{
		{"iam", "AttachRolePolicy", false, "", "IAM"},
		{"cloudtrail", "StopLogging", false, "", "CloudTrail configuration"},
		{"config", "StopConfigurationRecorder", false, "", "AWS Config configuration"},
		{"ec2", "AuthorizeSecurityGroupIngress", false, "", "security groups"},
		{"s3", "PutBucketPolicy", false, "", "S3 policies and public access"},
		{"s3", "DeletePublicAccessBlock", false, "", "S3 policies and public access"},
		{"s3-control", "PutPublicAccessBlock", false, "", "S3 policies and public access"},
		{"kms", "ScheduleKeyDeletion", false, "", "KMS"},
		{"s3", "PutObject", true, "tf-state", "S3 data events (state and artifact buckets)"},
		{"events", "DisableRule", false, "", "EventBridge rules (monitoring feed)"},
	} {
		d := f.Decide(c.svc, c.name, c.data, c.bucket)
		if !d.Evaluated || d.Wave != 1 || d.Area != c.want {
			t.Errorf("%s:%s: %+v, want evaluated %q", c.svc, c.name, d, c.want)
		}
	}
	if len(f.Counts()) != 0 {
		t.Fatalf("nothing should be counted as not evaluated: %v", f.Counts())
	}
}

func TestSecondWaveAndTheRestAreNamedNotEvaluated(t *testing.T) {
	f := &Filter{DataBuckets: []string{"tf-state"}}
	for _, c := range []struct {
		svc, name string
		data      bool
		bucket    string
		area      string
		wave      int
	}{
		{"ec2", "CreateRoute", false, "", "VPC routing", 2},
		{"secretsmanager", "PutSecretValue", false, "", "Secrets Manager", 2},
		{"lambda", "UpdateFunctionConfiguration", false, "", "Lambda configuration", 2},
		{"eks", "CreateAccessEntry", false, "", "EKS access", 2},
		{"rds", "ModifyDBInstance", false, "", "RDS", 2},
		{"ssm", "StartSession", false, "", "ssm (not classified)", 0},
		{"dynamodb", "PutItem", false, "", "dynamodb (not classified)", 0},
		{"s3", "PutObject", true, "someone-elses-bucket", "S3 data events of other buckets", 0},
		{"lambda", "InvokeFunction", false, "", "lambda (not classified)", 0},
	} {
		d := f.Decide(c.svc, c.name, c.data, c.bucket)
		if d.Evaluated || d.Area != c.area || d.Wave != c.wave {
			t.Errorf("%s:%s: %+v", c.svc, c.name, d)
		}
	}
	st := f.Statement()
	for _, want := range []string{"VPC routing", "SSM session contents", "database content", "events seen and not evaluated", "Secrets Manager 1", "ssm (not classified) 1"} {
		if !strings.Contains(st, want) {
			t.Errorf("statement lacks %q:\n%s", want, st)
		}
	}
}

func TestSecondWaveCanBeTurnedOn(t *testing.T) {
	f := &Filter{MaxWave: 2}
	if d := f.Decide("rds", "ModifyDBInstance", false, ""); !d.Evaluated || d.Wave != 2 {
		t.Fatalf("%+v", d)
	}
	if strings.Contains(f.Statement(), "second release") {
		t.Fatal("with the second wave on, it is not listed as pending")
	}
	if d := f.Decide("ssm", "StartSession", false, ""); d.Evaluated {
		t.Fatal("an unclassified service is never evaluated")
	}
}

func TestConfigItemsFollowTheSameScope(t *testing.T) {
	f := &Filter{}
	if d := f.DecideConfig("AWS::EC2::SecurityGroup"); !d.Evaluated || d.Area != "security groups" {
		t.Fatalf("%+v", d)
	}
	if d := f.DecideConfig("AWS::RDS::DBInstance"); d.Evaluated || d.Wave != 2 {
		t.Fatalf("%+v", d)
	}
	if d := f.DecideConfig("AWS::SSM::ManagedInstanceInventory"); d.Evaluated || d.Wave != 0 {
		t.Fatalf("%+v", d)
	}
}
