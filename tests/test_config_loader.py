import pytest
import yaml

from scanner.config_loader import load_config, ConfigLoadError


def test_load_json():
    config = load_config("mock_data/aws_config.json")

    assert isinstance(config, dict)
    assert len(config) > 0


def test_load_yaml(tmp_path):
    yaml_file = tmp_path / "test_config.yaml"

    yaml_file.write_text(
        """
AWSTemplateFormatVersion: '2010-09-09'
Resources:
  MyBucket:
    Type: AWS::S3::Bucket
    Properties:
      BucketName: test-bucket
        """,
        encoding="utf-8"
    )

    config = load_config(yaml_file)

    assert isinstance(config, dict)
    assert "Resources" in config
    assert "MyBucket" in config["Resources"]


def test_unsupported_format():
    with pytest.raises(ConfigLoadError):
        load_config("mock_data/test.txt")


def test_missing_file():
    with pytest.raises(ConfigLoadError):
        load_config("mock_data/nonexistent.json")


def test_empty_yaml(tmp_path):
    yaml_file = tmp_path / "empty.yaml"
    yaml_file.write_text("", encoding="utf-8")

    with pytest.raises(ConfigLoadError):
        load_config(yaml_file)