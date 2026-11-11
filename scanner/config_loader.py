import json
from pathlib import Path

import yaml


class ConfigLoadError(Exception):
    """Raised when a configuration file cannot be loaded."""


def load_config(file_path):
    """
    Load a JSON or YAML configuration file.

    Returns:
        dict: Parsed configuration.
    """

    path = Path(file_path)

    # Check whether the file exists
    if not path.is_file():
        raise ConfigLoadError(
            f"Configuration file not found: {path}"
        )

    # Check supported file formats
    extension = path.suffix.lower()

    if extension not in {".json", ".yaml", ".yml"}:
        raise ConfigLoadError(
            f"Unsupported file format: {extension}. "
            "Supported formats are JSON and YAML."
        )

    try:
        with path.open("r", encoding="utf-8") as file:

            if extension == ".json":
                config = json.load(file)

            else:
                config = yaml.safe_load(file)

    except json.JSONDecodeError as error:
        raise ConfigLoadError(
            f"Invalid JSON configuration: {error}"
        ) from error

    except yaml.YAMLError as error:
        raise ConfigLoadError(
            f"Invalid YAML configuration: {error}"
        ) from error

    except UnicodeDecodeError as error:
        raise ConfigLoadError(
            "Configuration file must use UTF-8 encoding."
        ) from error

    # Reject empty files and non-object configurations
    if not isinstance(config, dict):
        raise ConfigLoadError(
            "Configuration must contain a top-level object or mapping."
        )

    return config