#!/usr/bin/env python3
"""Verify a local OCI export and write its checksum and image identity sidecars."""

import hashlib
import json
from pathlib import Path
import sys
import tarfile


def main():
    archive = Path(sys.argv[1]).resolve()
    expected_source = sys.argv[2]
    digest = hashlib.sha256()
    with archive.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1 << 20), b""):
            digest.update(chunk)
    archive_sha = digest.hexdigest()
    with tarfile.open(archive) as image:
        def read_blob(descriptor):
            algorithm, blob_sha = descriptor["digest"].split(":", 1)
            if algorithm != "sha256":
                raise ValueError("unexpected OCI digest algorithm")
            content = image.extractfile("blobs/sha256/" + blob_sha).read()
            if hashlib.sha256(content).hexdigest() != blob_sha:
                raise ValueError("OCI blob checksum mismatch")
            return json.loads(content)

        index = json.load(image.extractfile("index.json"))
        if len(index["manifests"]) != 1:
            raise ValueError("expected one candidate image index")
        candidate = index["manifests"][0]
        platforms, attestations = [], []
        labels = None
        for descriptor in read_blob(candidate)["manifests"]:
            platform = descriptor.get("platform", {})
            manifest = read_blob(descriptor)
            if platform.get("os") == "unknown":
                attestations.append(descriptor["digest"])
                continue
            configuration = read_blob(manifest["config"])
            current_labels = configuration.get("config", {}).get("Labels", {})
            if current_labels.get("io.registry.source.sha256") != expected_source:
                raise ValueError("exported image source label does not match the build inputs")
            if labels is not None and current_labels != labels:
                raise ValueError("platform images have different source labels")
            labels = current_labels
            platforms.append({"platform": platform, "digest": descriptor["digest"]})
        if {(p["platform"]["os"], p["platform"]["architecture"]) for p in platforms} != {("linux", "amd64"), ("linux", "arm64")}:
            raise ValueError("candidate must contain Linux amd64 and arm64")
    record = {
        "archive": archive.name,
        "archive_sha256": archive_sha,
        "image_index_digest": candidate["digest"],
        "platform_manifests": platforms,
        "attestation_manifests": attestations,
        "labels": labels,
    }
    archive.with_suffix(archive.suffix + ".sha256").write_text(archive_sha + "  " + archive.name + "\n")
    archive.with_suffix(archive.suffix + ".metadata.json").write_text(json.dumps(record, indent=2, sort_keys=True) + "\n")
    print("Verified OCI candidate: " + candidate["digest"])


if __name__ == "__main__":
    main()
