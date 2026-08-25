from detection.rules import (
    detect_public_s3_bucket,
    detect_public_s3_objects,
    detect_s3_encryption_disabled
)


def test_public_s3_bucket():
    bucket = {
        "public_access": True
    }

    finding = detect_public_s3_bucket(bucket)

    assert finding is not None
    assert finding["rule_id"] == "S3-01"
    assert finding["severity"] == 5


def test_public_s3_objects():
    bucket = {
        "public_object_access": True
    }

    finding = detect_public_s3_objects(bucket)

    assert finding is not None
    assert finding["rule_id"] == "S3-02"
    assert finding["severity"] == 4


def test_s3_encryption_disabled():
    bucket = {
        "encryption_enabled": False
    }

    finding = detect_s3_encryption_disabled(bucket)

    assert finding is not None
    assert finding["rule_id"] == "S3-03"
    assert finding["severity"] == 3
    
